import { useSyncExternalStore } from 'react'
import type { ChatBackupView } from '@kutup/chat-core/backup'
import { fetchChatCapabilities, isSupportedChat } from '@kutup/chat-core/capabilities'
import { accountKey, conversationKey, directKey, type AccountRef } from '@kutup/chat-core/identity'
import { ChatService, ChatServiceError, type ChatConnectionStatus, type ChatInstall } from '@kutup/chat-core/service'
import type {
  ChatCapabilities,
  ConversationId,
  ChatProfile,
  ChatTypingEvent,
  InboundAttention,
} from '@kutup/chat-core/types'
import { privateCiphertextCacheForAccountV1, type PrivateCiphertextCacheV1 } from '@kutup/files/mediaCache'
import type { Session } from '@kutup/session/store'
import type { ChatData } from '../state/views'
import { setSealedStorage } from '../state/sealedState'
import { currentReadMarks } from '../state/readState'
import { foldAccountState, mergeReadMarks } from '../state/accountState'
import { startAccountNames, stopAccountNames } from '../state/accountNames'
import { checkRenames, resetRenameWatch } from '../state/renameWatch'
import { setReadReceipts, setTypingIndicators } from '../state/prefs'
import { isServerUnreachable, REOPEN_DELAYS_MS } from './openFailure'

/**
 * One chat connection per signed-in tab, outside React: `ChatService.open`
 * registers a device and takes cross-tab locks, so it must not run twice
 * (StrictMode, remounts). Components read the state through `useChat`.
 * Every update the service announces (socket, other tabs, backup) reloads
 * the whole picture in one go; a slower, older load never overwrites a
 * newer one.
 */

/**
 * `unreachable`: the server could not be reached; Chat opens again by itself.
 * `unavailable`: this browser's own Chat state would not open.
 */
/** The service's codes an open can fail with; any other is "unavailable". */
const OPEN_FAILURES: ReadonlySet<string> = new Set(['serverUnsupported', 'browserUnsupported', 'contactListUnconfirmed', 'contactListIntegrity', 'linkRequired'])

export type ChatFailure =
  | 'capabilities'
  | 'serverUnsupported'
  | 'browserUnsupported'
  | 'unreachable'
  | 'unavailable'
  | 'contactListUnconfirmed'
  | 'contactListIntegrity'
  /** Another device of the account holds its Chat identity: link this one. */
  | 'linkRequired'

export interface ChatSelf {
  /** This account: its server and permanent id. */
  account: AccountRef
  /** Its key, `aci:<uuid>@<server>`: how Chat names it (senders, Note to Self). Never shown. */
  key: string
  /** Its address now (`username@server`): shown only, never a key. */
  address: string
  /** The account's id: what this browser keys the account's local state by, never a name. */
  userId: string
}

export interface ChatSnapshot extends ChatData {
  attention: InboundAttention[]
  profile: ChatProfile | null
  backup: ChatBackupView | null
  /** The account's contact list is full: changes (a block too) wait to be written. */
  contactListFull: boolean
}

export interface ChatState {
  status: 'idle' | 'opening' | 'ready' | 'failed'
  failure: ChatFailure | null
  service: ChatService | null
  capabilities: ChatCapabilities | null
  self: ChatSelf | null
  mediaCache: PrivateCiphertextCacheV1 | null
  snapshot: ChatSnapshot
  /** The first load after opening has finished. */
  loaded: boolean
  /** The last reload failed (the snapshot is the one before). */
  stale: boolean
  /** Who is typing where: conversation key → sender → until (ms). */
  typing: ReadonlyMap<string, ReadonlyMap<string, number>>
  /** This tab's link to the server. */
  connection: ChatConnectionStatus
  /** Raised when an account's shown name arrives (`state/accountNames`). */
  namesRevision: number
}

const TYPING_TTL_MS = 6_000

const emptySnapshot: ChatSnapshot = {
  history: [],
  contacts: [],
  profiles: [],
  chatGroups: [],
  attention: [],
  profile: null,
  backup: null,
  contactListFull: false,
}

const initial: ChatState = {
  status: 'idle',
  failure: null,
  service: null,
  capabilities: null,
  self: null,
  mediaCache: null,
  snapshot: emptySnapshot,
  loaded: false,
  stale: false,
  typing: new Map(),
  connection: 'connecting',
  namesRevision: 0,
}

let state: ChatState = initial
const listeners = new Set<() => void>()
let openedFor: string | null = null
let generation = 0
let teardown: (() => void) | null = null
let reopenTimer: number | null = null
let reopenAttempt = 0

function set(patch: Partial<ChatState>): void {
  state = { ...state, ...patch }
  for (const listener of listeners) listener()
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

export function getChatState(): ChatState {
  return state
}

export function useChat(): ChatState {
  return useSyncExternalStore(subscribe, getChatState)
}

/**
 * Whether group links can be followed here (the server hosts groups): one
 * boolean, so a message re-renders only when it changes.
 */
export function useGroupLinksEnabled(): boolean {
  return useSyncExternalStore(subscribe, () => state.capabilities?.pairwiseGroups === true)
}

/** The open service; only for components rendered once the chat is ready. */
export function useChatService(): ChatService {
  const { service } = useChat()
  if (!service) throw new Error('chat is not open')
  return service
}

async function reload(service: ChatService): Promise<void> {
  const mine = ++generation
  try {
    // What needs the server keeps its last value while offline, so the local
    // history (a message queued offline, say) still shows.
    const previous = state.snapshot
    const orPrevious = <T,>(work: Promise<T>, fallback: T): Promise<T> =>
      work.catch((error: unknown) => {
        console.warn('chat: part of the reload kept its last value', error)
        return fallback
      })
    const pairwise = state.capabilities?.pairwiseGroups === true
    const [history, attention, contacts, profile, profiles, chatGroups] =
      await Promise.all([
        // The live window, not the whole history (Phase 2b): read again only
        // for the conversations that changed.
        service.liveWindow((controls) => {
          const self = state.self?.key ?? ''
          return mergeReadMarks(currentReadMarks(), foldAccountState(controls, self).readThrough)
        }).then((window) => window.history),
        orPrevious(service.inboundAttention(), previous.attention),
        service.contacts(),
        orPrevious(service.profile(), previous.profile),
        orPrevious(service.profiles(), previous.profiles),
        pairwise ? orPrevious(service.chatGroups(), previous.chatGroups) : Promise.resolve([]),
      ])
    const contactListFull = await service.contactListFull().catch(() => previous.contactListFull)
    if (mine !== generation || state.service !== service) return
    set({
      snapshot: {
        history,
        attention,
        contacts,
        profile,
        profiles,
        chatGroups,
        backup: service.backupStatus(),
        contactListFull,
      },
      loaded: true,
      stale: false,
    })
    // Renames of the people here, newest conversations first (a few a pass).
    void checkRenames(service, directPeersByRecency(history, contacts, state.self?.key ?? ''), () => void reload(service))
  } catch (error) {
    console.warn('chat: reload failed', error)
    if (mine === generation && state.service === service) set({ stale: true, loaded: true })
  }
}

/** Reload now (after an action whose result should show at once). */
export function refreshChat(): Promise<void> {
  const { service } = state
  return service ? reload(service) : Promise.resolve()
}

function onTyping(event: ChatTypingEvent): void {
  const key = conversationKey(event.conversation)
  const typing = new Map(state.typing)
  const senders = new Map(typing.get(key) ?? [])
  if (event.active) senders.set(event.sender, Date.now() + TYPING_TTL_MS)
  else senders.delete(event.sender)
  if (senders.size > 0) typing.set(key, senders)
  else typing.delete(key)
  set({ typing })
}

function expireTyping(): void {
  const now = Date.now()
  let changed = false
  const typing = new Map<string, ReadonlyMap<string, number>>()
  for (const [key, senders] of state.typing) {
    const live = new Map([...senders].filter(([, until]) => until > now))
    if (live.size !== senders.size) changed = true
    if (live.size > 0) typing.set(key, live)
  }
  if (changed) set({ typing })
}

/**
 * Open the chat for `session` (once; later calls for the same session do
 * nothing). A failure is kept in the state for the page to explain.
 */
export function openChat(session: Session, install?: ChatInstall): void {
  if (openedFor === session.sessionId) return
  closeChat()
  openedFor = session.sessionId
  const sessionId = session.sessionId
  set({ ...initial, status: 'opening' })
  void (async () => {
    let capabilities: ChatCapabilities | null
    try {
      capabilities = await fetchChatCapabilities()
    } catch (error) {
      if (openedFor !== sessionId) return
      if (isServerUnreachable(error)) reopenLater(session, null)
      else set({ status: 'failed', failure: 'capabilities' })
      return
    }
    if (openedFor !== sessionId) return
    if (!capabilities || !isSupportedChat(capabilities)) {
      set({ status: 'failed', failure: 'serverUnsupported', capabilities })
      return
    }
    if (!session.username || !capabilities.serverName) {
      set({ status: 'failed', failure: 'unavailable', capabilities })
      return
    }
    const account: AccountRef = { server: capabilities.serverName, accountId: session.userId }
    const mediaCache = privateCiphertextCacheForAccountV1(session.userId)
    void mediaCache.initialize().catch((error: unknown) => console.warn('chat: media cache unavailable', error))
    let service: ChatService
    try {
      service = await ChatService.open({
        userId: session.userId,
        envelopeBinding: session.envelopeBinding,
        account,
        displayName: session.username,
        masterKey: session.masterKey,
        capabilities,
        install,
      })
    } catch (error) {
      if (openedFor !== sessionId) return
      console.error('chat: could not open', error)
      if (!(error instanceof ChatServiceError) && isServerUnreachable(error)) {
        reopenLater(session, capabilities)
        return
      }
      set({
        status: 'failed',
        failure: error instanceof ChatServiceError && OPEN_FAILURES.has(error.code) ? (error.code as ChatFailure) : 'unavailable',
        capabilities,
      })
      return
    }
    if (openedFor !== sessionId) {
      service.dispose()
      return
    }
    // Linked: the account's settings, as the linking device sent them.
    if (install?.kind === 'link') {
      if (install.linking.readReceipts !== undefined) setReadReceipts(install.linking.readReceipts)
      if (install.linking.typingIndicators !== undefined) setTypingIndicators(install.linking.typingIndicators)
      install.linking.free()
    }
    const unsubscribers = [
      service.subscribe(() => void reload(service)),
      service.subscribeTyping(onTyping),
      service.subscribeConnection((connection) => set({ connection })),
      service.subscribeAttachmentExpiry(async (ids) => {
        await Promise.all(ids.map((id) => mediaCache.removeObject('chat', id)))
      }),
    ]
    const ticker = window.setInterval(expireTyping, 1_000)
    teardown = () => {
      window.clearInterval(ticker)
      for (const unsubscribe of unsubscribers) unsubscribe()
      setSealedStorage(null)
      stopAccountNames()
      resetRenameWatch()
      service.dispose()
    }
    forgetPlaintextChatState(`${session.username}@${capabilities.serverName}`, session.userId)
    startAccountNames(session, () => set({ namesRevision: state.namesRevision + 1 }))
    const sealed = service.sealedStorage
    setSealedStorage(sealed)
    reopenAttempt = 0
    set({
      status: 'ready',
      service,
      capabilities,
      self: {
        account,
        key: accountKey(account),
        address: `${session.username}@${capabilities.serverName}`,
        userId: session.userId,
      },
      mediaCache,
      connection: service.connectionStatus(),
    })
    await reload(service)
  })()
}

/**
 * Removes what older versions kept in this browser in plaintext, keyed by the
 * address or the account id: drafts, read positions and owed timers. None of
 * it is read any more (an account that later takes the same username must
 * not inherit it); it is only cleared away.
 */
function forgetPlaintextChatState(address: string, userId: string): void {
  for (const key of [
    `kutup.chat.drafts.v1:${address}`,
    `kutup:chat:read:${userId}`,
    `kutup.chat.pending-default-timers.v1:${address}`,
  ]) {
    try {
      window.localStorage.removeItem(key)
    } catch {
      // Storage blocked: nothing reads these keys anyway.
    }
  }
}

/**
 * The server cannot be reached: say so, and open again by itself, sooner at
 * first and then every half minute, and at once when the browser comes back
 * online. Nothing about this browser's state is in doubt, so no repair is
 * offered (openFailure.ts).
 */
function reopenLater(session: Session, capabilities: ChatCapabilities | null): void {
  set({ status: 'failed', failure: 'unreachable', capabilities })
  const delay = REOPEN_DELAYS_MS[Math.min(reopenAttempt, REOPEN_DELAYS_MS.length - 1)]
  reopenAttempt += 1
  const reopen = () => {
    if (openedFor !== session.sessionId || state.failure !== 'unreachable') return
    reopenChat(session)
  }
  reopenTimer = window.setTimeout(reopen, delay)
  window.addEventListener('online', reopen, { once: true })
}

/**
 * Open Chat again with this browser's device made as `install` says: linked
 * with the envelope another device sent, or re-registered after the person
 * confirmed they have none of the account's other devices.
 */
export function openChatWith(session: Session, install: ChatInstall): void {
  closeChat()
  openChat(session, install)
}

/** Try to open Chat again now (the "Try now" button, the retry timer). */
export function reopenChat(session: Session): void {
  const attempt = reopenAttempt
  closeChat()
  reopenAttempt = attempt
  openChat(session)
}

/** Close the chat (sign-out, another account). */
export function closeChat(): void {
  if (reopenTimer !== null) window.clearTimeout(reopenTimer)
  reopenTimer = null
  reopenAttempt = 0
  teardown?.()
  teardown = null
  openedFor = null
  generation += 1
  set(initial)
}

/** The other accounts of direct chats (and requests), newest conversation first, Note to Self left out. */
export function directPeersByRecency(
  history: readonly { conversation: ConversationId; timestampMs: number }[],
  contacts: readonly { peer: string; updatedAtMs: number }[],
  self: string,
): string[] {
  const latest = new Map<string, number>()
  for (const entry of history) {
    const peer = directKey(entry.conversation)
    if (peer && peer !== self) latest.set(peer, Math.max(latest.get(peer) ?? 0, entry.timestampMs))
  }
  for (const contact of contacts) {
    if (contact.peer !== self && !latest.has(contact.peer)) latest.set(contact.peer, contact.updatedAtMs)
  }
  return [...latest].sort((a, b) => b[1] - a[1]).map(([peer]) => peer)
}
