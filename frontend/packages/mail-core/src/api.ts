import { useInfiniteQuery, useMutation, useQuery, useQueryClient, type InfiniteData } from '@tanstack/react-query'
import { useMemo } from 'react'
import {
  encryptMailMessage,
  encryptMailMessageAsGroup,
  encryptMailPgp,
  encryptMailPgpAsGroup,
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
import type { ContactKey } from '@kutup/contacts-core/model'
import api from '@kutup/session/client'
import { useRequiredSession } from '@kutup/session/store'
import { addFirstAddressKey } from './addressKey'
import { addressKeys, forgetKeys, GroupAddress, groupMembers, NoKutupAddress } from './keys'
import { buildBody, buildMessage, buildPgpMessage, newMessageId, parseMessage, type Mailbox, type ParsedMessage } from './mime'
import { autocryptKey, openPgp } from './pgp'
import { PinnedKeyUnusable, pgpKey, protectionFor } from './protection'

// Mail (docs/plans/mail.md): the folders' readable fields from the server,
// each message opened here with the address key, and messages written here,
// encrypted once for every Kutup recipient and the sender's own copy.

export type FolderId = 'inbox' | 'drafts' | 'sent' | 'archive' | 'spam' | 'trash' | 'starred' | 'all'
export const FOLDERS: FolderId[] = ['inbox', 'drafts', 'sent', 'starred', 'archive', 'spam', 'trash']

export interface MailMessage {
  id: string
  threadId: string
  direction: 'inbound' | 'outbound'
  folder: Exclude<FolderId, 'starred' | 'all'>
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
  /** The distribution list or shared mailbox it came through. */
  groupAddress: string | null
  /** A shared mailbox's sent mail: the member who sent it. */
  sentBy: string | null
}

interface Page {
  messages: MailMessage[]
  next?: string | null
}

export interface FolderCount {
  folder: FolderId
  unread: number
  total: number
}

/** The account's own address and its key, as the browser uses them. */
export interface MailAccount {
  address: string
  domain: string
  /** The display name outgoing mail carries. */
  name: string
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
const folderKey = (folder: FolderId, q: string, group?: string) => ['mail', 'folder', folder, q, group ?? null] as const
const countsKey = (group?: string) => ['mail', 'counts', group ?? null] as const
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
      const sealed = (key: { privateKeyEnvelope: string; fingerprint: string }): SealedMailKey => ({
        masterKeyBase64: toBase64(session.masterKey),
        loginEmail: session.email,
        address: address.address,
        envelope: key.privateKeyEnvelope,
        fingerprint: key.fingerprint,
      })
      return {
        address: address.address,
        domain: address.address.split('@')[1] ?? '',
        name: session.username ?? '',
        publicKey: primary.publicKey,
        key: sealed(primary),
        olderKeys: address.keys.filter((k) => k !== primary).map(sealed),
      }
    },
  })
}

export function useFolder(folder: FolderId, q = '', group?: string) {
  return useInfiniteQuery({
    queryKey: folderKey(folder, q, group),
    initialPageParam: null as string | null,
    queryFn: async ({ pageParam }) =>
      (
        await api.get<Page>('/mail/messages', {
          params: { folder, ...(q ? { q } : {}), ...(pageParam ? { before: pageParam } : {}), limit: 50, ...scoped(group) },
        })
      ).data,
    getNextPageParam: (last) => last.next ?? null,
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

export function useCounts(group?: string) {
  return useQuery({
    queryKey: countsKey(group),
    queryFn: async () => (await api.get<FolderCount[]>('/mail/counts', { params: scoped(group) })).data,
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
   * their address and not the one already pinned: Mail offers to trust it.
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

async function offeredKey(raw: Uint8Array, parsed: ParsedMessage, from: string, pinned: ContactKey | undefined) {
  const candidates = [autocryptKey(raw, from), ...attachedKeys(parsed)].filter((k): k is Uint8Array => k !== null)
  for (const candidate of candidates) {
    try {
      const info = await inspectExternalMailKey(candidate, from)
      if (info.fingerprint === pinned?.fingerprint) return undefined
      return { publicKey: info.publicKey, fingerprint: info.fingerprint, replacesPinned: !!pinned }
    } catch {
      // Not a usable key for the sender: offer nothing for it.
    }
  }
  return undefined
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
  if (!outside) return { parsed: await parseMessage(opened.data), raw: opened.data, signed: opened.signed, verified: opened.verified }

  const pin = pinned(sender)
  const signingKeys = pin?.sign ? [pin.publicKey] : []
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
    offeredKey: await offeredKey(opened.data, parsed, sender, pin),
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
  queryClient.setQueriesData<InfiniteData<Page>>({ queryKey: ['mail', 'folder'] }, (data) =>
    data
      ? { ...data, pages: data.pages.map((page) => ({ ...page, messages: page.messages.map((m) => (set.has(m.id) ? { ...m, ...change } : m)) })) }
      : data,
  )
  queryClient.setQueriesData<MailMessage[]>({ queryKey: ['mail', 'thread'] }, (data) =>
    data?.map((m) => (set.has(m.id) ? { ...m, ...change } : m)),
  )
}

export interface MessageChange {
  ids: string[]
  /** A shared mailbox's id. */
  group?: string
  seen?: boolean
  starred?: boolean
  folder?: 'inbox' | 'archive' | 'spam' | 'trash' | 'sent'
}

/** Read, star, or file messages; the lists update at once and are fetched again after. */
export function useUpdateMessages() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (change: MessageChange) => (await api.patch<{ updated: number }>('/mail/messages', change)).data.updated,
    onMutate: ({ ids, folder: _folder, ...flags }) => patchCached(queryClient, ids, flags),
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

/** The key pinned in Contacts for an address, if any. */
export type PinnedKeys = (address: string) => ContactKey | undefined

/**
 * The keys pinned in Contacts, by address; `undefined` while Contacts load.
 * When the address book cannot be read, nothing is pinned.
 */
export function usePinnedKeys(): PinnedKeys | undefined {
  const account = useAccountAddress()
  const contacts = useContacts()
  const failed = account.isError || contacts.isError
  const data = contacts.data
  return useMemo(() => {
    if (!data && !failed) return undefined
    const keys = new Map<string, ContactKey>()
    for (const contact of data?.contacts ?? []) for (const key of contact.draft.keys) keys.set(key.address, key)
    return (address: string) => keys.get(address.toLowerCase())
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

export async function sendDraft(
  account: MailAccount,
  draft: Draft,
  attachmentParts: Uint8Array[],
  pinned: PinnedKeys,
  as?: SendAs,
): Promise<SendRecipient[]> {
  // As a shared mailbox: its address, its key for the sent copy and Autocrypt,
  // and signed by it.
  const self = as ? { address: as.address, name: as.name, publicKey: as.publicKey } : { address: account.address, name: account.name, publicKey: account.publicKey }
  const seal = (keys: string[], plaintext: Uint8Array) =>
    as ? encryptMailMessageAsGroup(as.key, keys, plaintext) : encryptMailMessage(account.key, keys, plaintext)
  const sealPgp = (keys: string[], plaintext: Uint8Array) =>
    as ? encryptMailPgpAsGroup(as.key, keys, plaintext) : encryptMailPgp(account.key, keys, plaintext)
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
  }
  const content = { html: draft.html, text: draft.text, attachments: attachmentParts }
  const message = buildMessage({ ...header, ...content })
  const everyone = [...new Set([...draft.to, ...draft.cc, ...draft.bcc].map((m) => m.address.toLowerCase()))]
  const local = everyone.filter((address) => address.endsWith(`@${account.domain}`))
  const external = everyone.filter((address) => !local.includes(address))
  const bcc = new Set(draft.bcc.map((m) => m.address.toLowerCase()))

  // Outside recipients' keys, and the PGP/MIME messages for them.
  const protections = await Promise.all(external.map((address) => protectionFor(address, account.domain, pinned(address))))
  const unusable = external.find((_, i) => protections[i].kind === 'pinnedUnusable')
  if (unusable) throw new PinnedKeyUnusable(unusable)
  const keyed = external.flatMap((address, i) => {
    const key = pgpKey(protections[i])
    return key ? [{ address, key }] : []
  })
  const groups = [keyed.filter((r) => !bcc.has(r.address)), ...keyed.filter((r) => bcc.has(r.address)).map((r) => [r])].filter((g) => g.length)
  const plain = external.filter((address) => !keyed.some((r) => r.address === address))
  const body = groups.length ? buildBody(content) : null
  const packages = await Promise.all(
    groups.map(async (group) => ({
      recipients: group.map((r) => r.address),
      message: buildPgpMessage(header, await sealPgp([...group.map((r) => r.key), self.publicKey], body!)),
    })),
  )

  const attempt = async (): Promise<SendRecipient[]> => {
    // Each Kutup address, or each member of a group (once, and not you).
    const targets = new Map<string, string>()
    for (const address of local) {
      try {
        targets.set(address, (await addressKeys(address)).primary)
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
            ...(as ? { fromName: as.name, fromGroup: as.groupId } : {}),
            keyPackets,
            pgp,
            ...(draft.id ? { draftId: draft.id } : {}),
          }),
        ],
        { type: 'application/json' },
      ),
    )
    form.append('data', blob(sealed.dataPacket))
    packages.forEach((p, i) => form.append(`pgp${i}`, blob(p.message, 'message/rfc822')))
    if (plain.length > 0) form.append('mime', blob(message, 'message/rfc822'))
    return (await api.post<{ recipients: SendRecipient[] }>('/mail/send', form)).data.recipients
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
