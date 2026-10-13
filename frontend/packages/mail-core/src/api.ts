import { useInfiniteQuery, useMutation, useQuery, useQueryClient, type InfiniteData } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import { useMemo } from 'react'
import {
  encryptMailMessage,
  encryptMailMessageAsGroup,
  encryptMailPgp,
  encryptMailPgpAsGroup,
  encryptMailMessageUnsigned,
  encryptMailPgpUnsigned,
  signMailCleartext,
  signMailCleartextAsGroup,
  signMailDetached,
  signMailDetachedAsGroup,
  inspectExternalMailKey,
  openMailGroupMessage,
  openMailMessage,
  toBase64,
  verifyMailCleartext,
  verifyMailDetachedSignature,
  type GroupMailKey,
  type SealedMailKey,
} from '@kutup/crypto'
import { useAccountAddress, useContacts } from '@kutup/contacts-core/api'
import { keysFor, type ContactEmailPgp, type ContactKey } from '@kutup/contacts-core/model'
import api from '@kutup/session/client'
import { useRequiredSession } from '@kutup/session/store'
import { addFirstAddressKey } from './addressKey'
import { addressKeys, forgetKeys, GroupAddress, groupMembers, NoKutupAddress } from './keys'
import { sanitizeSignature } from './sanitize'
import { searchText } from './searchText'
import { attachmentPart, buildBody, buildInlineMessage, buildMessage, buildPgpMessage, buildSignedMessage, describePart, inlineContentId, newMessageId, parseMessage, partContent, type Mailbox, type ParsedMessage, type Receipt } from './mime'
import { autocryptKey, openPgp } from './pgp'
import { PinnedKeyUnusable, pgpKey, protectionFor } from './protection'

// Mail (docs/plans/mail.md): the folders' readable fields from the server,
// each message opened here with the address key, and messages written here,
// encrypted once for every Kutup recipient and the sender's own copy.

export type FolderId = 'inbox' | 'drafts' | 'scheduled' | 'snoozed' | 'sent' | 'archive' | 'spam' | 'trash' | 'starred' | 'all'
export const FOLDERS: FolderId[] = ['inbox', 'drafts', 'scheduled', 'snoozed', 'sent', 'starred', 'archive', 'spam', 'trash']
/**
 * What a list shows: a fixed folder, one of the account's own folders
 * (`folder:<id>`) or a label (`label:<id>`), docs/plans/mail-filters.md.
 */
export type PlaceKey = FolderId | `folder:${string}` | `label:${string}`

export interface MailMessage {
  id: string
  threadId: string
  direction: 'inbound' | 'outbound'
  /** A fixed folder, or `custom` with `customFolder`. */
  folder: Exclude<FolderId, 'starred' | 'all'> | 'custom'
  customFolder: string | null
  labels: string[]
  seen: boolean
  starred: boolean
  protection: 'zero_access' | 'end_to_end'
  size: number
  receivedAt: string
  sentAt: string | null
  subject: string
  from: Mailbox | null
  to: Mailbox[]
  cc: Mailbox[]
  replyTo: Mailbox[]
  bcc: Mailbox[]
  messageId: string | null
  inReplyTo: string | null
  references: string[]
  attachmentCount: number
  /** From a mailing list the reader unsubscribed from. */
  unsubscribed?: boolean
  /** From a list that offers a way out (noted on arrival): moving it to Spam may unsubscribe (Proton's SpamAction). */
  unsubscribable?: boolean
  /** The reader sent the read receipt the sender asked for. */
  receiptSent?: boolean
  /** Its attached files, for the list. */
  attachments?: AttachmentMeta[]
  /** A scheduled message: when it goes, and its held send (to take it back). */
  scheduledAt?: string | null
  outboxId?: string | null
  /** Snoozed: when it comes back to the Inbox. */
  snoozedUntil?: string | null
  /** An expiring message: when every Kutup copy is deleted. */
  expiresAt?: string | null
  /** The distribution list or shared mailbox it came through. */
  groupAddress: string | null
  /** A shared mailbox's sent mail: the member who sent it. */
  sentBy: string | null
  /** Listed by conversation: the thread this row stands for, in the place listed (Proton's conversation grouping). */
  conversation?: MailConversation
}

/** What moving or marking one message of a conversation needs. */
export interface ConversationMember {
  id: string
  folder: MailMessage['folder']
  direction: MailMessage['direction']
  customFolder: string | null
  unsubscribable?: boolean
}

/** An attached file as the list knows it (Proton's AttachmentsMetadata): readable, as the subject is. */
export interface AttachmentMeta {
  name: string
  type: string
  size: number
  /** In a conversation row: the message it is attached to. */
  message?: string
}

/** A conversation in one place, as Proton's ContextNumMessages and ContextNumUnread. */
export interface MailConversation {
  /** Its messages here, oldest first. */
  members: ConversationMember[]
  unread: number
  starred: boolean
  /** Who wrote them, each once, in the order they first wrote. */
  senders: Mailbox[]
  attachmentCount: number
  /** Their attached files, oldest message first. */
  attachments?: AttachmentMeta[]
}

/** The messages a row stands for: a conversation's members here, else the message itself. */
export function membersOf<T extends Pick<MailMessage, 'id' | 'folder' | 'direction' | 'customFolder'> & { conversation?: MailConversation }>(rows: T[]): ConversationMember[] {
  return rows.flatMap((row) => row.conversation?.members ?? [{ id: row.id, folder: row.folder, direction: row.direction, customFolder: row.customFolder }])
}

/** A row read as a whole: a conversation is unread while any of its messages is, starred when any is. */
export const rowSeen = (row: MailMessage) => (row.conversation ? row.conversation.unread === 0 : row.seen)
export const rowStarred = (row: MailMessage) => row.conversation?.starred ?? row.starred

export interface Page {
  messages: MailMessage[]
  next?: string | null
  /** With a numbered page: how many the place holds with these filters. */
  total?: number | null
}

export interface FolderCount {
  folder: PlaceKey
  unread: number
  total: number
}

/** The account's own address and its key, as the browser uses them. */
export interface MailAccount {
  address: string
  domain: string
  /** The display name outgoing mail carries (Mail → Settings → Identity). */
  name: string
  /** The signature new messages start with (HTML, sanitised); empty for none. */
  signature: string
  publicKey: string
  /** The primary key: it signs, and new mail is encrypted to it. */
  key: SealedMailKey
  /** The address's other keys, which still open mail encrypted to them before a new key took over. */
  olderKeys: SealedMailKey[]
}

/** Opens a shared mailbox's message with the newest group key that opens it. */
async function openWithGroupKeys(keys: GroupMailKey[], message: Uint8Array, signerKey?: string) {
  let last: unknown = new Error('no key of this shared mailbox opens the message')
  for (const key of keys) {
    try {
      return await openMailGroupMessage(key, message, signerKey)
    } catch (error) {
      last = error
    }
  }
  throw last
}

/** Opens a message with the primary key, else with an older key (mail from before a new key). */
async function openWithKeys(account: MailAccount, message: Uint8Array, signerKey?: string) {
  try {
    return await openMailMessage(account.key, message, signerKey)
  } catch (error) {
    for (const key of account.olderKeys) {
      try {
        return await openMailMessage(key, message, signerKey)
      } catch {
        // Not this key either.
      }
    }
    throw error
  }
}

export const mailKey = ['mail'] as const
// `group` is a shared mailbox's id; absent, the account's own mailbox.
const folderKey = (folder: PlaceKey, view: ListView) => ['mail', 'folder', folder, view.q ?? '', view.group ?? null, !!view.conversations, view.filter ?? null, view.sort ?? 'newest', JSON.stringify(view.criteria ?? {}), view.page ?? 0, view.pageSize ?? DEFAULT_PAGE_SIZE] as const
/** Two list keys for one place and view, whatever their page. */
const samePlace = (a: readonly unknown[], b: readonly unknown[]) => a.length === b.length && a.every((part, i) => i === a.length - 2 || part === b[i])
const countsKey = (group?: string, conversations = false) => ['mail', 'counts', group ?? null, conversations] as const
const threadKey = (id: string, group?: string) => ['mail', 'thread', id, group ?? null] as const
const contentKey = (id: string) => ['mail', 'content', id] as const
const scoped = (group?: string) => (group ? { group } : {})

/** Fetched again this often while the app is open (web push comes later). */
const POLL_MS = 30_000

/** No address key yet: the Account app makes it at sign-in. */
export class NoAddressKey extends Error {
  constructor() {
    super('this account has no mail address key yet')
  }
}

export function useMailAccount() {
  const session = useRequiredSession()
  return useQuery({
    queryKey: ['mail', 'account', session.sessionId],
    staleTime: Infinity,
    retry: (count, error) => !(error instanceof NoAddressKey) && count < 1,
    queryFn: async (): Promise<MailAccount> => {
      const { data } = await api.get<
        { id: string; address: string; keys: { fingerprint: string; publicKey: string; privateKeyEnvelope: string; primary: boolean }[] }[]
      >('/mail/addresses')
      let address = data[0]
      if (address && address.keys.length === 0) {
        // Not made at sign-in yet (or that failed): make it now.
        await addFirstAddressKey(session, address).catch(() => undefined)
        address = (await api.get<typeof data>('/mail/addresses')).data[0]
      }
      const primary = address?.keys.find((k) => k.primary)
      if (!address || !primary) throw new NoAddressKey()
      const identity = await api
        .get<MailIdentity>('/mail/identity')
        .then((r) => r.data)
        .catch(() => null)
      const sealed = (key: { privateKeyEnvelope: string; fingerprint: string }): SealedMailKey => ({
        masterKeyBase64: toBase64(session.masterKey),
        binding: session.envelopeBinding,
        address: address.address,
        envelope: key.privateKeyEnvelope,
        fingerprint: key.fingerprint,
      })
      return {
        address: address.address,
        domain: address.address.split('@')[1] ?? '',
        name: identity?.displayName || session.username || '',
        signature: sanitizeSignature(identity?.signature ?? ''),
        publicKey: primary.publicKey,
        key: sealed(primary),
        olderKeys: address.keys.filter((k) => k !== primary).map(sealed),
      }
    },
  })
}

/** An address's display name and signature, as Proton's Identity settings. */
export interface MailIdentity {
  address: string
  displayName: string
  /** HTML from the signature editor. */
  signature: string
}

export function useMailIdentity() {
  return useQuery({
    queryKey: ['mail', 'identity'],
    queryFn: async () => (await api.get<MailIdentity>('/mail/identity')).data,
  })
}

export function useUpdateMailIdentity() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (change: Partial<Pick<MailIdentity, 'displayName' | 'signature'>>) => (await api.patch<MailIdentity>('/mail/identity', change)).data,
    onSuccess: (identity) => {
      queryClient.setQueryData(['mail', 'identity'], identity)
      // The composer reads both from the account.
      void queryClient.invalidateQueries({ queryKey: ['mail', 'account'] })
    },
  })
}

/** When the auto-reply is on and what it says (docs/plans/mail-parity.md), as Proton's AutoResponder. Times are wall-clock times in `zone`. */
export interface AutoReplySettings {
  enabled: boolean
  repeat: 'fixed' | 'daily' | 'weekly' | 'monthly' | 'permanent'
  /** An IANA time zone. */
  zone: string
  /** Fixed: `YYYY-MM-DDTHH:MM`. */
  start?: string | null
  end?: string | null
  /** Daily: weekdays, 0 Sunday to 6 Saturday. */
  days: number[]
  /** Weekly: a weekday 0–6; monthly: a day of the month 1–31. */
  startDay?: number | null
  endDay?: number | null
  /** Minutes after midnight. */
  startMinute?: number | null
  endMinute?: number | null
  messageHtml: string
  messageText: string
}

export interface AutoReply {
  /** None until one is saved. */
  settings: AutoReplySettings | null
  /** Answering now: on and inside its schedule. */
  active: boolean
}

export function useAutoReply() {
  return useQuery({
    queryKey: ['mail', 'autoReply'],
    queryFn: async () => (await api.get<AutoReply>('/mail/auto-reply')).data,
  })
}

export function useSaveAutoReply() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (settings: AutoReplySettings) => (await api.put<AutoReply>('/mail/auto-reply', settings)).data,
    onSuccess: (saved) => queryClient.setQueryData(['mail', 'autoReply'], saved),
  })
}

/** A page of one place; by conversation when `conversations` (the account's View mode). */
/** Proton's list filters: Unread, Read, Has attachments. */
export type ListFilter = 'unread' | 'read' | 'attachments'
/** Proton's sort options. */
export type ListSort = 'newest' | 'oldest' | 'largest' | 'smallest'

/** How a place is listed: searched, in a shared mailbox, by conversation, filtered, sorted. */
export interface ListView {
  q?: string
  /** Advanced search beyond the keyword (as `listCriteria` makes it). */
  criteria?: { from?: string; to?: string; since?: string; until?: string; address?: string }
  group?: string
  /** One row per conversation (the account's View mode). */
  conversations?: boolean
  filter?: ListFilter | null
  sort?: ListSort
  /** Page number from 0 (Proton's paging). */
  page?: number
  /** The account's page size: 50, 100 or 200. */
  pageSize?: number
}

/** Proton's default page size (`DEFAULT_MAIL_PAGE_SIZE`). */
export const DEFAULT_PAGE_SIZE = 50
/** Proton's page sizes (`MAIL_PAGE_SIZE`). */
export const PAGE_SIZES = [50, 100, 200] as const

export function useFolder(folder: PlaceKey, view: ListView = {}, enabled = true) {
  const { q, criteria, group, conversations, filter, sort, page = 0, pageSize = DEFAULT_PAGE_SIZE } = view
  // One numbered page per key, kept in the infinite shape the cache
  // updates (patchMessages, patchLabels) work on.
  return useInfiniteQuery<Page, Error, InfiniteData<Page, number>, ReturnType<typeof folderKey>, number>({
    queryKey: folderKey(folder, view),
    enabled,
    initialPageParam: page,
    // The page before stays while the next loads, within one view only.
    placeholderData: (previous, previousQuery) => (previousQuery && samePlace(previousQuery.queryKey, folderKey(folder, view)) ? previous : undefined),
    queryFn: async ({ pageParam }) =>
      (
        await api.get<Page>('/mail/messages', {
          params: {
            folder,
            ...(q ? { q } : {}),
            ...criteria,
            page: pageParam,
            limit: pageSize,
            ...scoped(group),
            ...(conversations ? { conversations: true } : {}),
            ...(filter === 'unread' ? { unread: true } : filter === 'read' ? { unread: false } : filter === 'attachments' ? { attachments: true } : {}),
            ...(sort && sort !== 'newest' ? { sort } : {}),
          },
        })
      ).data,
    getNextPageParam: () => null,
    refetchInterval: POLL_MS,
  })
}

/** Your limits on mail to outside addresses, and whether it is paused. */
export interface SendingStatus {
  perHour: number
  perDay: number
  sentHour: number
  sentDay: number
  /** The lower limits of an account's first week apply. */
  newAccount: boolean
  paused: 'admin' | 'bounces' | 'spam' | null
  /** Whether this server sends your mail to outside addresses yet (`MAIL_OUTSIDE_SENDING`). */
  outsideAllowed: boolean
}

export function useSendingStatus(enabled = true) {
  return useQuery({
    queryKey: ['mail', 'sending'],
    enabled,
    queryFn: async () => (await api.get<SendingStatus>('/mail/sending')).data,
  })
}

/** Unread and total per place: conversations or messages, as the list shows them (Proton's counters follow View mode). */
export function useCounts(group?: string) {
  const settings = useMailSettings()
  const conversations = (settings.data?.viewMode ?? 'conversation') === 'conversation'
  return useQuery({
    queryKey: countsKey(group, conversations),
    enabled: !settings.isPending,
    queryFn: async () => (await api.get<FolderCount[]>('/mail/counts', { params: { ...scoped(group), ...(conversations ? { conversations: true } : {}) } })).data,
    refetchInterval: POLL_MS,
  })
}

export function useThread(threadId: string | undefined, group?: string) {
  return useQuery({
    queryKey: threadKey(threadId ?? '', group),
    enabled: !!threadId,
    queryFn: async () => (await api.get<MailMessage[]>(`/mail/threads/${threadId}`, { params: scoped(group) })).data,
  })
}

/** A shared mailbox being read: its id and the group keys the reader holds. */
export interface GroupScope {
  groupId: string
  keys: GroupMailKey[]
}

export interface OpenedMessage {
  parsed: ParsedMessage
  /** The decrypted message, for "Download" and replies. */
  raw: Uint8Array
  signed: boolean
  /**
   * A signature that checks against the sender's Kutup key list, or for
   * OpenPGP mail from outside against a key pinned to the sender; false for
   * unsigned mail and for a signature that does not check.
   */
  verified: boolean
  /** OpenPGP mail from outside Kutup (docs/plans/mail.md, C3). */
  pgp?: {
    encrypted: boolean
    /** The sender has a key pinned to check signatures with. */
    pinned: boolean
  }
  /**
   * A key the sender offers (Autocrypt header or attached key), usable for
   * their address and not trusted yet: Mail offers to trust it, first, the
   * keys trusted before kept after it (`replacesPinned`: there are some).
   */
  offeredKey?: { publicKey: string; fingerprint: string; replacesPinned: boolean }
}

/** Keys attached to a message as files (`application/pgp-keys`, `.asc`). */
function attachedKeys(parsed: ParsedMessage): Uint8Array[] {
  return parsed.attachments
    .filter((a) => a.content.length <= 256 * 1024)
    .filter((a) => a.mimeType === 'application/pgp-keys' || /\.(asc|key)$/i.test(a.filename))
    .filter((a) => new TextDecoder().decode(a.content.subarray(0, 4096)).includes('-----BEGIN PGP PUBLIC KEY BLOCK-----') || a.mimeType === 'application/pgp-keys')
    .map((a) => a.content)
}

async function offeredKey(raw: Uint8Array, parsed: ParsedMessage, from: string, pinned: PinnedAddress | undefined) {
  const candidates = [autocryptKey(raw, from), ...attachedKeys(parsed)].filter((k): k is Uint8Array => k !== null)
  const trusted = pinned?.keys ?? []
  for (const candidate of candidates) {
    try {
      const info = await inspectExternalMailKey(candidate, from)
      // Already trusted, used for sending or kept as history.
      if (trusted.some((key) => key.fingerprint === info.fingerprint)) return undefined
      return { publicKey: info.publicKey, fingerprint: info.fingerprint, replacesPinned: trusted.length > 0 }
    } catch {
      // Not a usable key for the sender: offer nothing for it.
    }
  }
  return undefined
}

/**
 * One message's text for body search (docs/plans/mail-body-search.md): opened
 * as for reading (OpenPGP from outside decrypted too), signatures not checked,
 * which search does not need.
 */
export async function openMessageText(account: MailAccount, message: MailMessage): Promise<string> {
  const response = await api.get<ArrayBuffer>(`/mail/messages/${message.id}/content`, { responseType: 'arraybuffer' })
  const opened = await openWithKeys(account, new Uint8Array(response.data))
  const sender = message.from?.address
  const outside = message.direction === 'inbound' && !!sender && !sender.endsWith(`@${account.domain}`)
  const pgp = outside
    ? await openPgp(
        opened.data,
        {
          decrypt: (bytes, signerKey) => openWithKeys(account, bytes, signerKey),
          verifyDetached: (signature, content, key) => verifyMailDetachedSignature(signature, content, key),
          verifyCleartext: (text, key) => verifyMailCleartext(text, key),
        },
        [],
      ).catch(() => null)
    : null
  const parsed = await parseMessage(pgp?.message ?? opened.data)
  return searchText(message.subject, parsed)
}

/**
 * Fetches, opens and parses one message; its sender's key checked when it
 * is from a Kutup user. OpenPGP mail from outside is opened a second time
 * (PGP/MIME, inline) or verified (multipart/signed, cleartext) with the
 * keys pinned to the sender.
 */
export async function openMessage(account: MailAccount, message: MailMessage, pinned: PinnedKeys, scope?: GroupScope): Promise<OpenedMessage> {
  const response = await api.get<ArrayBuffer>(`/mail/messages/${message.id}/content`, {
    responseType: 'arraybuffer',
    params: scoped(scope?.groupId),
  })
  const stored = new Uint8Array(response.data)
  // A shared mailbox's mail opens with a group key the reader holds.
  const open = scope ? (bytes: Uint8Array, signer?: string) => openWithGroupKeys(scope.keys, bytes, signer) : (bytes: Uint8Array, signer?: string) => openWithKeys(account, bytes, signer)
  const sender = message.from?.address
  let candidates: string[] = []
  if (sender === account.address) {
    candidates = [account.publicKey]
  } else if (sender && message.protection === 'end_to_end') {
    candidates = await addressKeys(sender)
      .then((keys) => keys.all)
      .catch(() => [])
  }
  let opened = await open(stored, candidates[0])
  for (const candidate of candidates.slice(1)) {
    if (!opened.signed || opened.verified) break
    opened = await open(stored, candidate)
  }
  const outside = message.direction === 'inbound' && sender && !sender.endsWith(`@${account.domain}`)
  // A Kutup user's mail they sent with Encrypt off (docs/plans/mail-encrypt-sign.md):
  // readable on the way, encrypted on arrival; its signature, if any, is
  // checked against the sender's own key list.
  const readableFromKutup = message.direction === 'inbound' && !!sender && !outside && message.protection === 'zero_access'
  if (!outside && !readableFromKutup) return { parsed: await parseMessage(opened.data), raw: opened.data, signed: opened.signed, verified: opened.verified }

  const pin = outside ? pinned(sender) : undefined
  // Signatures check against every trusted key, as Proton's (Sign is about sending).
  const signingKeys = outside
    ? (pin?.keys ?? []).map((key) => key.publicKey)
    : await addressKeys(sender)
        .then((keys) => keys.all)
        .catch(() => [])
  const pgp = await openPgp(
    opened.data,
    {
      decrypt: (bytes, signerKey) => open(bytes, signerKey),
      verifyDetached: (signature, content, key) => verifyMailDetachedSignature(signature, content, key),
      verifyCleartext: (text, key) => verifyMailCleartext(text, key),
    },
    signingKeys,
  )
  const parsed = await parseMessage(pgp?.message ?? opened.data)
  return {
    parsed,
    raw: opened.data,
    signed: pgp?.signed ?? false,
    verified: pgp?.verified ?? false,
    ...(pgp ? { pgp: { encrypted: pgp.encrypted, pinned: signingKeys.length > 0 } } : {}),
    // A Kutup sender's key comes from their key list, never from the mail.
    offeredKey: outside ? await offeredKey(opened.data, parsed, sender, pin) : undefined,
  }
}

/** Opens a message once the sender's pinned keys are known (`pinned` undefined while Contacts load). */
export function useOpenedMessage(
  account: MailAccount | undefined,
  message: MailMessage | undefined,
  pinned: PinnedKeys | undefined,
  scope?: GroupScope | null,
) {
  return useQuery({
    queryKey: contentKey(message?.id ?? ''),
    // In a shared mailbox, once its keys are known (`scope` null while they load).
    enabled: !!account && !!message && !!pinned && scope !== null,
    staleTime: Infinity,
    gcTime: 5 * 60_000,
    queryFn: () => openMessage(account!, message!, pinned!, scope ?? undefined),
  })
}

function patchCached(queryClient: ReturnType<typeof useQueryClient>, ids: string[], change: Partial<MailMessage>) {
  const set = new Set(ids)
  // A conversation row changes as a whole when all its messages do; otherwise the refetch after the change tells.
  const patch = (m: MailMessage): MailMessage => {
    const row = set.has(m.id) ? { ...m, ...change } : m
    if (!m.conversation || !m.conversation.members.every((member) => set.has(member.id))) return row
    return {
      ...row,
      conversation: {
        ...m.conversation,
        ...(change.seen !== undefined ? { unread: change.seen ? 0 : m.conversation.members.length } : {}),
        ...(change.starred !== undefined ? { starred: change.starred } : {}),
      },
    }
  }
  queryClient.setQueriesData<InfiniteData<Page>>({ queryKey: ['mail', 'folder'] }, (data) =>
    data ? { ...data, pages: data.pages.map((page) => ({ ...page, messages: page.messages.map(patch) })) } : data,
  )
  queryClient.setQueriesData<MailMessage[]>({ queryKey: ['mail', 'thread'] }, (data) =>
    data?.map((m) => (set.has(m.id) ? { ...m, ...change } : m)),
  )
}

/** Labels added and removed at once in the cached lists and threads. */
function patchLabels(queryClient: ReturnType<typeof useQueryClient>, ids: string[], add: string[], remove: string[]) {
  const set = new Set(ids)
  const next = (m: MailMessage) => (set.has(m.id) ? { ...m, labels: [...new Set([...m.labels, ...add])].filter((l) => !remove.includes(l)) } : m)
  queryClient.setQueriesData<InfiniteData<Page>>({ queryKey: ['mail', 'folder'] }, (data) =>
    data ? { ...data, pages: data.pages.map((page) => ({ ...page, messages: page.messages.map(next) })) } : data,
  )
  queryClient.setQueriesData<MailMessage[]>({ queryKey: ['mail', 'thread'] }, (data) => data?.map(next))
}

export interface MessageChange {
  ids: string[]
  /** A shared mailbox's id. */
  group?: string
  seen?: boolean
  starred?: boolean
  folder?: 'inbox' | 'archive' | 'spam' | 'trash' | 'sent' | 'custom'
  /** One of the account's folders, with `folder: 'custom'`. */
  customFolder?: string
  addLabels?: string[]
  removeLabels?: string[]
}

/**
 * Unsubscribes from a message's mailing list (Proton's): with `oneClickUrl`
 * the server sends RFC 8058's request; without it, the reader went another
 * way and the message is only marked. Either way it then says
 * "Unsubscribed".
 */
export function useUnsubscribe(group?: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ id, oneClickUrl }: { id: string; oneClickUrl?: string }) => {
      await api.post(`/mail/messages/${id}/unsubscribe`, { ...(oneClickUrl ? { oneClickUrl } : {}), ...scoped(group) })
      return id
    },
    onSuccess: (id) => patchCached(queryClient, [id], { unsubscribed: true }),
  })
}

/** The mailbox `Name <address>` or `address` names, or null. */
function receiptAddress(value: string): Mailbox | null {
  const angle = /<([^<>\s]+@[^<>\s]+)>/.exec(value)
  const address = (angle?.[1] ?? value).trim()
  if (!/^[^\s@<>,]+@[^\s@<>,]+$/.test(address)) return null
  const name = angle ? value.slice(0, angle.index).trim().replace(/^"|"$/g, '') : ''
  return { address, name }
}

/**
 * Sends the read receipt a message asks for (Proton's "Send read
 * receipt"): an RFC 8098 report from the reader, written by the client and
 * sent like any mail (end to end to a Kutup sender), then noted on the
 * message so it says "Read receipt sent".
 */
export function useSendReceipt() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ account, message, parsed, pinned, subject, text }: { account: MailAccount; message: MailMessage; parsed: ParsedMessage; pinned: PinnedKeys; subject: string; text: string }) => {
      const to = parsed.receiptTo ? receiptAddress(parsed.receiptTo) : null
      if (!to) throw new Error('no receipt address')
      const html = `<p>${text.replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[c]!)}</p>`
      const original = parsed.messageId
      await sendDraft(
        account,
        emptyDraft(account, {
          to: [to],
          subject,
          text,
          html,
          inReplyTo: original,
          references: original ? [...parsed.references, original] : parsed.references,
          receipt: { finalRecipient: account.address, originalMessageId: original },
        }),
        [],
        pinned,
      )
      await api.post(`/mail/messages/${message.id}/receipt`, {})
      return message.id
    },
    onSuccess: (id) => patchCached(queryClient, [id], { receiptSent: true }),
  })
}

/** Read, star, or file messages; the lists update at once and are fetched again after. */
export function useUpdateMessages() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (change: MessageChange) => (await api.patch<{ updated: number }>('/mail/messages', change)).data.updated,
    onMutate: ({ ids, folder: _folder, customFolder: _custom, addLabels, removeLabels, ...flags }) => {
      patchCached(queryClient, ids, flags)
      if (addLabels?.length || removeLabels?.length) {
        patchLabels(queryClient, ids, addLabels ?? [], removeLabels ?? [])
      }
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: mailKey }),
  })
}

/** Every message of a place at once (Proton's select all), as `PATCH /mail/messages` changes them. */
export interface PlaceChange extends Omit<MessageChange, 'ids' | 'starred'> {
  /** The list's place, All mail aside. */
  place: PlaceKey
}

export function useBatchMessages() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (change: PlaceChange) => (await api.post<{ updated: number }>('/mail/messages/batch', change)).data.updated,
    onSettled: () => queryClient.invalidateQueries({ queryKey: mailKey }),
  })
}

/** One remote image through the Kutup image proxy (Proton's `core/v4/images`). */
export type ProxiedImage = { kind: 'image'; blob: Blob } | { kind: 'tracker' } | { kind: 'failed' } | { kind: 'busy' }

export async function fetchMailImage(url: string): Promise<ProxiedImage> {
  try {
    // The address goes in the body, never in a URL a log would keep.
    const response = await api.post<ArrayBuffer>('/mail/images', { url }, { responseType: 'arraybuffer' })
    // 204: a known tracking pixel the server would not fetch.
    if (response.status === 204) return { kind: 'tracker' }
    const type = String(response.headers['content-type'] ?? '')
    if (!type.startsWith('image/')) return { kind: 'failed' }
    return { kind: 'image', blob: new Blob([response.data], { type }) }
  } catch (error) {
    // Limits a sender could force: never a reason to load the image directly.
    const status = isAxiosError(error) ? error.response?.status : undefined
    return status === 429 || status === 503 ? { kind: 'busy' } : { kind: 'failed' }
  }
}

/** New mail to tell the reader about (Proton's new-email notifications). */
export interface NewMail {
  id: string
  threadId: string
  folder: string
  customFolder: string | null
  subject: string
  fromAddress: string
  fromName: string
}

/** New mail since `after` (the last answer's `now`); without it, only `now`. */
export async function fetchNewMail(after: string | null): Promise<{ now: string; messages: NewMail[]; more: boolean }> {
  return (await api.get<{ now: string; messages: NewMail[]; more: boolean }>('/mail/notifications', { params: after ? { after } : {} })).data
}

/** What advanced search's Address can be: your addresses and lists, or a shared mailbox's address. */
export function useSearchAddresses(group?: string, enabled = true) {
  return useQuery({
    queryKey: ['mail', 'search-addresses', group ?? null],
    enabled,
    staleTime: 5 * 60_000,
    queryFn: async () => (await api.get<string[]>('/mail/search-addresses', { params: scoped(group) })).data,
  })
}

const imageSendersKey = ['mail', 'image-senders'] as const

/** Senders whose remote images always load (chosen when loading them). */
export function useImageSenders() {
  return useQuery({
    queryKey: imageSendersKey,
    staleTime: 5 * 60_000,
    queryFn: async () => (await api.get<{ address: string; createdAt: string }[]>('/mail/image-senders')).data,
  })
}

export function useAddImageSender() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (address: string) => {
      await api.post('/mail/image-senders', { address })
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: imageSendersKey }),
  })
}

export function useRemoveImageSender() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (address: string) => {
      await api.post('/mail/image-senders/delete', { address })
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: imageSendersKey }),
  })
}

/** Proton's Snooze: Inbox messages wait in Snoozed until `until` (ISO 8601); without it, back now. */
export function useSnooze() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ ids, until, group }: { ids: string[]; until?: string; group?: string }) =>
      (await api.post<{ updated: number }>('/mail/messages/snooze', { ids, ...(until ? { until } : {}), ...scoped(group) })).data.updated,
    onSettled: () => queryClient.invalidateQueries({ queryKey: mailKey }),
  })
}

/** Deletes for good (from Trash, Spam and Drafts). */
export function useDeleteMessages() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ ids, group }: { ids: string[]; group?: string }) =>
      (await api.post<{ updated: number }>('/mail/messages/delete', { ids, ...scoped(group) })).data.updated,
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: mailKey })
      void queryClient.invalidateQueries({ queryKey: ['storage'] })
    },
  })
}

/** Deletes everything in Trash or Spam for good (Proton's "Delete all"). */
export function useEmptyFolder() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ folder, group }: { folder: 'trash' | 'spam'; group?: string }) =>
      (await api.post<{ updated: number }>('/mail/messages/empty', { folder, ...scoped(group) })).data.updated,
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: mailKey })
      void queryClient.invalidateQueries({ queryKey: ['storage'] })
    },
  })
}

/** The account's mail settings (docs/plans/mail-parity.md), as Proton's. */
export interface MailSettings {
  /** 30 to delete Trash and Spam after 30 days, 0 not to. */
  autoDeleteDays: 0 | 30
  /** All mail leaves out Spam and Trash. */
  almostAllMail: boolean
  /** The reading pane beside the list, or below it (Proton's ViewLayout). */
  viewLayout: 'column' | 'row'
  /** List rows: Proton's Density. */
  density: 'comfortable' | 'compact'
  /** How the composer opens (Proton's ComposerMode). */
  composerMode: 'popup' | 'maximized'
  /** One row per conversation, or per message (Proton's ViewMode). */
  viewMode: 'conversation' | 'message'
  /** A link that leads outside Kutup asks first (Proton's ConfirmLink). */
  confirmLink: boolean
  /** Rows on a page of the list: 50, 100 or 200 (Proton's PageSize). */
  pageSize: number
  /** Moving list mail to Spam: ask, just move, or move and unsubscribe (Proton's SpamAction). */
  spamAction: 'ask' | 'just_spam' | 'spam_and_unsubscribe'
  /** Remote images: blocked until loaded, or always (Proton's "Auto show remote images"); never automatic in Spam. */
  remoteImages: 'ask' | 'always'
  /** Remote images load through the Kutup server, known trackers never load, and links lose tracking parameters (Proton's "Protect against email tracking"). */
  imageProxy: boolean
  /** A message's own (embedded) images show at once (Proton's "Auto show embedded images"). */
  embeddedImages: boolean
  /** Where the insert-image question's "Remove metadata" starts (Proton's RemoveImageMetadata). */
  removeImageMetadata: boolean
  /** Undo send: seconds a send waits before it goes (Proton's DelaySendSeconds: 0, 5, 10, 20). */
  delaySendSeconds: number
  /** Composer defaults (Proton's Composer mode, text direction, default font/size). */
  draftType: 'html' | 'plain'
  textDirection: 'ltr' | 'rtl'
  fontFace: string
  fontSize: number
  /** New mail to people outside Kutup starts with Sign on (Proton's "Sign external messages"). */
  signOutside: boolean
  /** Every new message carries your public key as an attachment (Proton's AttachPublicKey). */
  attachPublicKey: boolean
  /** How mail to outside OpenPGP users is encrypted or signed (Proton's PGPScheme); Inline is plain text. */
  pgpScheme: 'pgp_mime' | 'inline'
}

export const mailSettingsKey = ['mail', 'settings'] as const

export function useMailSettings() {
  return useQuery({
    queryKey: mailSettingsKey,
    staleTime: 5 * 60_000,
    queryFn: async () => (await api.get<MailSettings>('/mail/settings')).data,
  })
}

export function useUpdateMailSettings() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (change: Partial<MailSettings>) => (await api.patch<MailSettings>('/mail/settings', change)).data,
    onSuccess: (settings) => {
      queryClient.setQueryData(mailSettingsKey, settings)
      // All mail may now show Spam and Trash, or not.
      void queryClient.invalidateQueries({ queryKey: ['mail', 'folder', 'all'] })
    },
  })
}

// --- Writing ---------------------------------------------------------------

export interface Draft {
  /** The saved draft, once it has been saved. */
  id?: string
  to: Mailbox[]
  cc: Mailbox[]
  bcc: Mailbox[]
  subject: string
  html: string
  text: string
  messageId: string
  inReplyTo?: string | null
  references?: string[]
  threadId?: string | null
  /** Attachment parts already uploaded with the draft. */
  attachments: DraftAttachment[]
  /** Ask the recipients for a read receipt (Proton's composer option). */
  requestReceipt?: boolean
  /** The message is a read receipt for another (RFC 8098). */
  receipt?: Receipt
  /** Scheduled send: when it goes (ISO 8601); it waits in Scheduled. */
  scheduleAt?: string
  /** Plain text: sent as text/plain alone (Proton's plain text mode). */
  plain?: boolean
  /** An expiring message (ISO 8601): every Kutup copy is deleted then. */
  expiresAt?: string
}

export interface DraftAttachment {
  id: string
  name: string
  type: string
  /** The file's size, before encoding. */
  size: number
}

function meta(account: MailAccount, draft: Draft) {
  return {
    subject: draft.subject,
    fromName: account.name,
    to: draft.to,
    cc: draft.cc,
    bcc: draft.bcc,
    messageId: draft.messageId,
    ...(draft.inReplyTo ? { inReplyTo: draft.inReplyTo } : {}),
    references: draft.references ?? [],
    attachmentCount: draft.attachments.length,
    attachments: draft.attachments.map(({ name, type, size }) => ({ name, type, size })),
    ...(draft.threadId ? { threadId: draft.threadId } : {}),
  }
}

function joined(sealed: { keyPackets: string[]; dataPacket: Uint8Array }): Uint8Array {
  const key = Uint8Array.from(atob(sealed.keyPackets[0]), (c) => c.charCodeAt(0))
  const out = new Uint8Array(key.length + sealed.dataPacket.length)
  out.set(key)
  out.set(sealed.dataPacket, key.length)
  return out
}

/** Encrypts `bytes` to the account's own key alone: a whole OpenPGP message. */
export async function sealForSelf(account: MailAccount, bytes: Uint8Array): Promise<Uint8Array> {
  return joined(await encryptMailMessage(account.key, [account.publicKey], bytes))
}

function blob(bytes: Uint8Array, type = 'application/octet-stream'): Blob {
  return new Blob([bytes as BlobPart], { type })
}

/** A new, empty draft's fields. */
export function emptyDraft(account: MailAccount, init: Partial<Draft> = {}): Draft {
  return { to: [], cc: [], bcc: [], subject: '', html: '', text: '', attachments: [], messageId: newMessageId(account.domain), ...init }
}

/** Saves a draft's text and fields (its attachments are uploaded on their own). */
export async function saveDraft(account: MailAccount, draft: Draft): Promise<MailMessage> {
  const body = buildMessage({
    from: { address: account.address, name: account.name },
    to: draft.to,
    cc: draft.cc,
    subject: draft.subject,
    messageId: draft.messageId,
    inReplyTo: draft.inReplyTo,
    references: draft.references,
    html: draft.html,
    text: draft.text,
    // Kept in the draft itself, so it is still asked for when the draft opens again.
    requestReceipt: draft.requestReceipt,
    plain: draft.plain,
  })
  const form = new FormData()
  form.append('meta', new Blob([JSON.stringify(meta(account, draft))], { type: 'application/json' }))
  form.append('body', blob(await sealForSelf(account, body)))
  const { data } = draft.id ? await api.put<MailMessage>(`/mail/drafts/${draft.id}`, form) : await api.post<MailMessage>('/mail/drafts', form)
  return data
}

/** Uploads one attachment part (from `attachmentPart`) to a saved draft. */
export async function addDraftAttachment(account: MailAccount, draftId: string, part: Uint8Array): Promise<string> {
  const form = new FormData()
  form.append('part', blob(await sealForSelf(account, part)))
  return (await api.post<{ id: string }>(`/mail/drafts/${draftId}/attachments`, form)).data.id
}

export async function removeDraftAttachment(draftId: string, attachmentId: string) {
  await api.delete(`/mail/drafts/${draftId}/attachments/${attachmentId}`)
}

/** A draft attachment's part, opened. */
export async function draftAttachmentPart(account: MailAccount, draftId: string, attachmentId: string): Promise<Uint8Array> {
  const { data } = await api.get<ArrayBuffer>(`/mail/drafts/${draftId}/attachments/${attachmentId}`, { responseType: 'arraybuffer' })
  return (await openWithKeys(account, new Uint8Array(data))).data
}

/** A send held for undo send: it goes at `deliverAt` unless taken back. */
export interface HeldSend {
  outboxId: string
  deliverAt: string
}

export const isHeld = (outcome: SendRecipient[] | HeldSend): outcome is HeldSend => !Array.isArray(outcome)

/** How a held send went: its recipients once sent, the send's error body once failed. */
export interface OutboxStatus {
  state: 'pending' | 'sending' | 'sent' | 'cancelled' | 'failed'
  result: { recipients?: SendRecipient[]; error?: string; code?: string } | null
}

export async function outboxStatus(id: string): Promise<OutboxStatus> {
  return (await api.get<OutboxStatus>(`/mail/outbox/${id}`)).data
}

/** Undo: the send does not go (false once it already went). */
export async function cancelSend(id: string): Promise<boolean> {
  try {
    await api.post(`/mail/outbox/${id}/cancel`)
    return true
  } catch (error) {
    if (isAxiosError(error) && error.response?.status === 409) return false
    throw error
  }
}

export interface SendRecipient {
  address: string
  /** `failed`: refused by the mail server after mail to others had gone out. */
  status: 'delivered' | 'sent' | 'full' | 'failed'
}

/** A Kutup recipient address that does not exist. */
export class UnknownRecipient extends Error {
  constructor(readonly address: string) {
    super(`${address} is not a Kutup address`)
  }
}

/**
 * What Contacts say about an outside address (docs/plans/contact-keys.md):
 * its trusted keys in order (the first that can encrypt is used for sending,
 * all of them check signatures) and its preferences.
 */
export interface PinnedAddress {
  keys: ContactKey[]
  pgp: ContactEmailPgp
}

/** What Contacts say about an address, if its contact says anything. */
export type PinnedKeys = (address: string) => PinnedAddress | undefined

/**
 * The trusted keys and preferences in Contacts, by address; `undefined`
 * while Contacts load. When the address book cannot be read, nothing is
 * pinned.
 */
export function usePinnedKeys(): PinnedKeys | undefined {
  const account = useAccountAddress()
  const contacts = useContacts()
  const failed = account.isError || contacts.isError
  const data = contacts.data
  return useMemo(() => {
    if (!data && !failed) return undefined
    const byAddress = new Map<string, PinnedAddress>()
    for (const contact of data?.contacts ?? []) {
      for (const email of contact.draft.emails) {
        const address = email.address.trim().toLowerCase()
        if (byAddress.has(address)) continue
        const keys = keysFor(contact.draft, address)
        if (keys.length || email.pgp) byAddress.set(address, { keys, pgp: email.pgp ?? {} })
      }
    }
    return (address: string) => byAddress.get(address.toLowerCase())
  }, [data, failed])
}

/**
 * Builds, encrypts and sends a draft (its attachments assembled from their
 * parts). Kutup recipients get it end to end; outside recipients with an
 * OpenPGP key (pinned, or found) get PGP/MIME, To and Cc in one message and
 * each Bcc recipient in their own; the rest get the plaintext. Every copy
 * carries the sender's key in an Autocrypt header.
 */
/** Writing as a shared mailbox: its address, name, primary key and the writer's share of it. */
export interface SendAs {
  groupId: string
  address: string
  name: string
  /** The group's primary public key (base64). */
  publicKey: string
  key: GroupMailKey
}

/**
 * Encrypt and Sign for one message (docs/plans/mail-encrypt-sign.md). Encrypt
 * off sends Kutup recipients the readable message (the server encrypts it on
 * arrival) and outside ones plain mail; lists and shared mailboxes stay end
 * to end. Sign off leaves the signature out.
 */
const encoder = new TextEncoder()

export interface SendOptions {
  encrypt: boolean
  sign: boolean
  /**
   * How outside OpenPGP recipients get it (Proton's PGP scheme): PGP/MIME,
   * or Inline, plain text with each attachment encrypted (or signed) on its
   * own. Kutup recipients are not affected.
   */
  pgpScheme?: 'pgp_mime' | 'inline'
}

export async function sendDraft(
  account: MailAccount,
  draft: Draft,
  attachmentParts: Uint8Array[],
  pinned: PinnedKeys,
  as?: SendAs,
  options: SendOptions = { encrypt: true, sign: true },
): Promise<SendRecipient[] | HeldSend> {
  // As a shared mailbox: its address, its key for the sent copy and Autocrypt,
  // and signed by it.
  const self = as ? { address: as.address, name: as.name, publicKey: as.publicKey } : { address: account.address, name: account.name, publicKey: account.publicKey }
  const seal = (keys: string[], plaintext: Uint8Array) =>
    !options.sign
      ? encryptMailMessageUnsigned(keys, plaintext)
      : as
        ? encryptMailMessageAsGroup(as.key, keys, plaintext)
        : encryptMailMessage(account.key, keys, plaintext)
  const sealPgp = (keys: string[], plaintext: Uint8Array) =>
    !options.sign
      ? encryptMailPgpUnsigned(keys, plaintext)
      : as
        ? encryptMailPgpAsGroup(as.key, keys, plaintext)
        : encryptMailPgp(account.key, keys, plaintext)
  const signDetached = (content: Uint8Array) => (as ? signMailDetachedAsGroup(as.key, content) : signMailDetached(account.key, content))
  const signCleartext = (text: string) => (as ? signMailCleartextAsGroup(as.key, text) : signMailCleartext(account.key, text))
  const inline = options.pgpScheme === 'inline'
  const header = {
    from: { address: self.address, name: self.name },
    to: draft.to,
    cc: draft.cc,
    subject: draft.subject,
    messageId: draft.messageId,
    inReplyTo: draft.inReplyTo,
    references: draft.references,
    date: new Date(),
    autocryptKey: self.publicKey,
    requestReceipt: draft.requestReceipt,
  }
  const content = { html: draft.html, text: draft.text, attachments: attachmentParts, receipt: draft.receipt, plain: draft.plain }
  const message = buildMessage({ ...header, ...content })
  const everyone = [...new Set([...draft.to, ...draft.cc, ...draft.bcc].map((m) => m.address.toLowerCase()))]
  const local = everyone.filter((address) => address.endsWith(`@${account.domain}`))
  const external = everyone.filter((address) => !local.includes(address))
  const bcc = new Set(draft.bcc.map((m) => m.address.toLowerCase()))

  // Outside recipients' keys, and the PGP/MIME messages for them.
  const protections = await Promise.all(external.map((address) => protectionFor(address, account.domain, pinned(address))))
  const unusable = external.find((_, i) => protections[i].kind === 'pinnedUnusable')
  if (unusable) throw new PinnedKeyUnusable(unusable)
  // Encrypt off: no outside recipient gets a PGP message.
  // Each with its scheme: its contact's, else the account's (Proton's X-PM-SCHEME).
  const keyed = options.encrypt
    ? external.flatMap((address, i) => {
        const key = pgpKey(protections[i])
        const scheme = pinned(address)?.pgp.scheme ?? options.pgpScheme ?? 'pgp_mime'
        return key ? [{ address, key, inline: scheme === 'inline' }] : []
      })
    : []
  // To and Cc together per scheme; each Bcc on their own (key IDs would name them).
  const groups = [
    keyed.filter((r) => !bcc.has(r.address) && !r.inline),
    keyed.filter((r) => !bcc.has(r.address) && r.inline),
    ...keyed.filter((r) => bcc.has(r.address)).map((r) => [r]),
  ].filter((g) => g.length)
  const plain = external.filter((address) => !keyed.some((r) => r.address === address))
  const body = groups.some((g) => !g[0].inline) ? buildBody(content) : null
  const files = attachmentParts.map((part) => ({ ...describePart(part), bytes: partContent(part) }))
  const packages = await Promise.all(
    groups.map(async (group) => {
      const keys = [...group.map((r) => r.key), self.publicKey]
      // Inline: the plain text encrypted, and each file encrypted on its own as `name.pgp`.
      const message = group[0].inline
        ? buildInlineMessage(
            header,
            await sealPgp(keys, encoder.encode(draft.text)),
            await Promise.all(files.map(async (file) => attachmentPart({ name: `${file.name}.pgp`, type: 'application/pgp-encrypted', bytes: encoder.encode(await sealPgp(keys, file.bytes)) }))),
          )
        : buildPgpMessage(header, await sealPgp(keys, body!))
      return { recipients: group.map((r) => r.address), message }
    }),
  )

  // The readable message, for outside recipients without a PGP message and
  // Kutup recipients with Encrypt off: signed (multipart/signed) when Sign is on.
  let readableMessage: Promise<Uint8Array> | null = null
  const readableFor = (): Promise<Uint8Array> => {
    readableMessage ??= !options.sign
      ? Promise.resolve(message)
      : inline
        ? // Inline: the plain text cleartext-signed, each file with its detached `name.sig`.
          (async () =>
            buildInlineMessage(header, await signCleartext(draft.text), [
              ...attachmentParts,
              ...(await Promise.all(files.map(async (file) => attachmentPart({ name: `${file.name}.sig`, type: 'application/pgp-signature', bytes: encoder.encode(await signDetached(file.bytes)) })))),
            ]))()
        : (async () => {
            const signedBody = buildBody(content)
            return buildSignedMessage(header, signedBody, await signDetached(signedBody))
          })()
    return readableMessage
  }

  const attempt = async (): Promise<SendRecipient[] | HeldSend> => {
    // Each Kutup address, or each member of a group (once, and not you).
    const targets = new Map<string, string>()
    const readable: string[] = []
    for (const address of local) {
      try {
        const keys = await addressKeys(address)
        if (options.encrypt) targets.set(address, keys.primary)
        else readable.push(address)
      } catch (error) {
        if (error instanceof NoKutupAddress) throw new UnknownRecipient(address)
        if (!(error instanceof GroupAddress)) throw error
        for (const member of await groupMembers(address)) {
          if (member.address !== self.address && !targets.has(member.address)) targets.set(member.address, member.primary)
        }
      }
    }
    const addresses = [...targets.keys()]
    const sealed = await seal([self.publicKey, ...addresses.map((a) => targets.get(a)!)], message)
    const keyPackets: Record<string, string> = { self: sealed.keyPackets[0] }
    addresses.forEach((address, i) => {
      keyPackets[address] = sealed.keyPackets[i + 1]
    })
    const form = new FormData()
    const pgp = packages.map((p) => ({ recipients: p.recipients }))
    form.append(
      'meta',
      new Blob(
        [
          JSON.stringify({
            ...meta(account, draft),
            ...(draft.scheduleAt ? { scheduleAt: draft.scheduleAt } : {}),
            ...(draft.expiresAt ? { expiresAt: draft.expiresAt } : {}),
            // Every part sent, forwarded ones and an attached key too.
            attachmentCount: attachmentParts.filter((part) => !inlineContentId(part)).length,
            attachments: attachmentParts.filter((part) => !inlineContentId(part)).map(describePart),
            ...(as ? { fromName: as.name, fromGroup: as.groupId } : {}),
            keyPackets,
            pgp,
            ...(readable.length ? { readable } : {}),
            ...(draft.id ? { draftId: draft.id } : {}),
          }),
        ],
        { type: 'application/json' },
      ),
    )
    form.append('data', blob(sealed.dataPacket))
    packages.forEach((p, i) => form.append(`pgp${i}`, blob(p.message, 'message/rfc822')))
    if (plain.length > 0 || readable.length > 0) form.append('mime', blob(await readableFor(), 'message/rfc822'))
    const { status, data } = await api.post<{ recipients: SendRecipient[] } | HeldSend>('/mail/send', form)
    // 202: held for undo send; it goes when the delay is up.
    if (status === 202) return data as HeldSend
    return (data as { recipients: SendRecipient[] }).recipients
  }

  try {
    return await attempt()
  } catch (error) {
    const response = (error as { response?: { status?: number; data?: { code?: string; address?: string } } }).response
    if (response?.status === 409 && (response.data?.code === 'keyChanged' || response.data?.code === 'groupChanged')) {
      // A recipient rotated their key, or a group's members changed, since
      // they were looked up: once more.
      forgetKeys(response.data.code === 'keyChanged' ? response.data.address : undefined)
      return attempt()
    }
    if (response?.status === 422 && response.data?.code === 'unknownRecipient' && response.data.address) {
      throw new UnknownRecipient(response.data.address)
    }
    throw error
  }
}

/** Refreshes everything a send or save changed. */
export function useMailRefresh() {
  const queryClient = useQueryClient()
  return () => {
    void queryClient.invalidateQueries({ queryKey: mailKey })
    void queryClient.invalidateQueries({ queryKey: ['storage'] })
  }
}
