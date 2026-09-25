import { useSyncExternalStore } from 'react'
import type { ChatBackupView } from '@kutup/chat-core/backup'
import { fetchChatCapabilities, isSupportedChat } from '@kutup/chat-core/capabilities'
import { canonicalAccountAddress, conversationKey, withHomeServer } from '@kutup/chat-core/identity'
import { ChatService, ChatServiceError, type ChatConnectionStatus } from '@kutup/chat-core/service'
import type {
  AccountAddress,
  ChatCapabilities,
  ChatProfile,
  ChatTypingEvent,
  GroupJoinRequest,
  InboundAttention,
  MlsInvitationFeedback,
  OwnJoinRequest,
  PendingMlsInvitation,
  PendingMlsOwnerApprovalRequest,
} from '@kutup/chat-core/types'
import { privateCiphertextCacheForAccountV1, type PrivateCiphertextCacheV1 } from '@kutup/files/mediaCache'
import type { Session } from '@kutup/session/store'
import type { ChatData } from '../state/views'

/**
 * One chat connection per signed-in tab, outside React: `ChatService.open`
 * registers a device and takes cross-tab locks, so it must not run twice
 * (StrictMode, remounts). Components read the state through `useChat`.
 * Every update the service announces (socket, other tabs, backup) reloads
 * the whole picture in one go; a slower, older load never overwrites a
 * newer one.
 */

export type ChatFailure = 'capabilities' | 'serverUnsupported' | 'browserUnsupported' | 'unavailable'

export interface ChatSelf {
  account: AccountAddress
  /** Canonical `username@server`. */
  address: string
}

export interface ChatSnapshot extends ChatData {
  attention: InboundAttention[]
  profile: ChatProfile | null
  invitations: PendingMlsInvitation[]
  invitationFeedback: MlsInvitationFeedback[]
  ownerApprovals: PendingMlsOwnerApprovalRequest[]
  /** People asking to join groups this account administers. */
  joinRequests: GroupJoinRequest[]
  /** This account's own requests through group links. */
  ownJoinRequests: OwnJoinRequest[]
  backup: ChatBackupView | null
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
}

const TYPING_TTL_MS = 6_000

const emptySnapshot: ChatSnapshot = {
  history: [],
  contacts: [],
  profiles: [],
  groups: [],
  attention: [],
  profile: null,
  invitations: [],
  invitationFeedback: [],
  ownerApprovals: [],
  joinRequests: [],
  ownJoinRequests: [],
  backup: null,
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
}

let state: ChatState = initial
const listeners = new Set<() => void>()
let openedFor: string | null = null
let generation = 0
let teardown: (() => void) | null = null

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

/** The open service; only for components rendered once the chat is ready. */
export function useChatService(): ChatService {
  const { service } = useChat()
  if (!service) throw new Error('chat is not open')
  return service
}

async function reload(service: ChatService, mlsGroups: boolean): Promise<void> {
  const mine = ++generation
  try {
    const [history, attention, contacts, profile, profiles, groups, invitations, invitationFeedback, ownerApprovals] =
      await Promise.all([
        service.history(),
        service.inboundAttention(),
        service.contacts(),
        service.profile(),
        service.profiles(),
        mlsGroups ? service.groups() : Promise.resolve([]),
        mlsGroups ? service.groupInvitations() : Promise.resolve([]),
        mlsGroups ? service.groupInvitationFeedback() : Promise.resolve([]),
        mlsGroups ? service.pendingGroupOwnerApprovals() : Promise.resolve([]),
      ])
    if (mine !== generation || state.service !== service) return
    set({
      snapshot: {
        history,
        attention,
        contacts,
        profile,
        profiles,
        groups,
        invitations,
        invitationFeedback,
        ownerApprovals,
        joinRequests: service.groupJoinRequests(),
        ownJoinRequests: service.ownJoinRequests(),
        backup: service.backupStatus(),
      },
      loaded: true,
      stale: false,
    })
  } catch (error) {
    console.warn('chat: reload failed', error)
    if (mine === generation && state.service === service) set({ stale: true, loaded: true })
  }
}

/** Reload now (after an action whose result should show at once). */
export function refreshChat(): Promise<void> {
  const { service, capabilities } = state
  return service ? reload(service, capabilities?.mlsGroups === true) : Promise.resolve()
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
export function openChat(session: Session): void {
  if (openedFor === session.sessionId) return
  closeChat()
  openedFor = session.sessionId
  const sessionId = session.sessionId
  set({ ...initial, status: 'opening' })
  void (async () => {
    let capabilities: ChatCapabilities | null
    try {
      capabilities = await fetchChatCapabilities()
    } catch {
      if (openedFor === sessionId) set({ status: 'failed', failure: 'capabilities' })
      return
    }
    if (openedFor !== sessionId) return
    if (!capabilities || !isSupportedChat(capabilities)) {
      set({ status: 'failed', failure: 'serverUnsupported', capabilities })
      return
    }
    if (!session.username) {
      set({ status: 'failed', failure: 'unavailable', capabilities })
      return
    }
    const account = withHomeServer({ username: session.username }, capabilities.serverName)
    const mediaCache = privateCiphertextCacheForAccountV1(session.userId)
    void mediaCache.initialize().catch((error: unknown) => console.warn('chat: media cache unavailable', error))
    let service: ChatService
    try {
      service = await ChatService.open({
        userId: session.userId,
        email: session.email,
        username: session.username,
        masterKey: session.masterKey,
        capabilities,
      })
    } catch (error) {
      if (openedFor !== sessionId) return
      console.error('chat: could not open', error)
      set({
        status: 'failed',
        failure: error instanceof ChatServiceError ? error.code : 'unavailable',
        capabilities,
      })
      return
    }
    if (openedFor !== sessionId) {
      service.dispose()
      return
    }
    const mlsGroups = capabilities.mlsGroups === true
    const unsubscribers = [
      service.subscribe(() => void reload(service, mlsGroups)),
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
      service.dispose()
    }
    set({
      status: 'ready',
      service,
      capabilities,
      self: { account, address: canonicalAccountAddress(account) },
      mediaCache,
      connection: service.connectionStatus(),
    })
    await reload(service, mlsGroups)
  })()
}

/** Close the chat (sign-out, another account). */
export function closeChat(): void {
  teardown?.()
  teardown = null
  openedFor = null
  generation += 1
  set(initial)
}
