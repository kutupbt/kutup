import { useInfiniteQuery, useMutation, useQuery, useQueryClient, type InfiniteData } from '@tanstack/react-query'
import { encryptMailMessage, openMailMessage, toBase64, type SealedMailKey } from '@kutup/crypto'
import api from '@kutup/session/client'
import { useRequiredSession } from '@kutup/session/store'
import { addFirstAddressKey } from './addressKey'
import { addressKeys, forgetKeys, NoKutupAddress } from './keys'
import { buildMessage, newMessageId, parseMessage, type Mailbox, type ParsedMessage } from './mime'

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
  key: SealedMailKey
}

export const mailKey = ['mail'] as const
const folderKey = (folder: FolderId, q: string) => ['mail', 'folder', folder, q] as const
const countsKey = ['mail', 'counts'] as const
const threadKey = (id: string) => ['mail', 'thread', id] as const
const contentKey = (id: string) => ['mail', 'content', id] as const

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
      return {
        address: address.address,
        domain: address.address.split('@')[1] ?? '',
        name: session.username ?? '',
        publicKey: primary.publicKey,
        key: {
          masterKeyBase64: toBase64(session.masterKey),
          loginEmail: session.email,
          address: address.address,
          envelope: primary.privateKeyEnvelope,
          fingerprint: primary.fingerprint,
        },
      }
    },
  })
}

export function useFolder(folder: FolderId, q = '') {
  return useInfiniteQuery({
    queryKey: folderKey(folder, q),
    initialPageParam: null as string | null,
    queryFn: async ({ pageParam }) =>
      (
        await api.get<Page>('/mail/messages', {
          params: { folder, ...(q ? { q } : {}), ...(pageParam ? { before: pageParam } : {}), limit: 50 },
        })
      ).data,
    getNextPageParam: (last) => last.next ?? null,
    refetchInterval: POLL_MS,
  })
}

export function useCounts() {
  return useQuery({
    queryKey: countsKey,
    queryFn: async () => (await api.get<FolderCount[]>('/mail/counts')).data,
    refetchInterval: POLL_MS,
  })
}

export function useThread(threadId: string | undefined) {
  return useQuery({
    queryKey: threadKey(threadId ?? ''),
    enabled: !!threadId,
    queryFn: async () => (await api.get<MailMessage[]>(`/mail/threads/${threadId}`)).data,
  })
}

export interface OpenedMessage {
  parsed: ParsedMessage
  /** The decrypted message, for "Download" and replies. */
  raw: Uint8Array
  signed: boolean
  /**
   * A signature that checks against the sender's Kutup key list; false for
   * unsigned mail and for a signature that does not check.
   */
  verified: boolean
}

/** Fetches, opens and parses one message; its sender's key checked when it is from a Kutup user. */
export async function openMessage(account: MailAccount, message: MailMessage): Promise<OpenedMessage> {
  const response = await api.get<ArrayBuffer>(`/mail/messages/${message.id}/content`, { responseType: 'arraybuffer' })
  const stored = new Uint8Array(response.data)
  const sender = message.from?.address
  let candidates: string[] = []
  if (sender === account.address) {
    candidates = [account.publicKey]
  } else if (sender && message.protection === 'end_to_end') {
    candidates = await addressKeys(sender)
      .then((keys) => keys.all)
      .catch(() => [])
  }
  let opened = await openMailMessage(account.key, stored, candidates[0])
  for (const candidate of candidates.slice(1)) {
    if (!opened.signed || opened.verified) break
    opened = await openMailMessage(account.key, stored, candidate)
  }
  return { parsed: await parseMessage(opened.data), raw: opened.data, signed: opened.signed, verified: opened.verified }
}

export function useOpenedMessage(account: MailAccount | undefined, message: MailMessage | undefined) {
  return useQuery({
    queryKey: contentKey(message?.id ?? ''),
    enabled: !!account && !!message,
    staleTime: Infinity,
    gcTime: 5 * 60_000,
    queryFn: () => openMessage(account!, message!),
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
    mutationFn: async (ids: string[]) => (await api.post<{ updated: number }>('/mail/messages/delete', { ids })).data.updated,
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
  return (await openMailMessage(account.key, new Uint8Array(data))).data
}

export interface SendRecipient {
  address: string
  status: 'delivered' | 'sent' | 'full'
}

/** A Kutup recipient address that does not exist. */
export class UnknownRecipient extends Error {
  constructor(readonly address: string) {
    super(`${address} is not a Kutup address`)
  }
}

/** Builds, encrypts and sends a draft (its attachments assembled from their parts). */
export async function sendDraft(account: MailAccount, draft: Draft, attachmentParts: Uint8Array[]): Promise<SendRecipient[]> {
  const message = buildMessage({
    from: { address: account.address, name: account.name },
    to: draft.to,
    cc: draft.cc,
    subject: draft.subject,
    messageId: draft.messageId,
    inReplyTo: draft.inReplyTo,
    references: draft.references,
    html: draft.html,
    text: draft.text,
    attachments: attachmentParts,
  })
  const everyone = [...new Set([...draft.to, ...draft.cc, ...draft.bcc].map((m) => m.address.toLowerCase()))]
  const local = everyone.filter((address) => address.endsWith(`@${account.domain}`))
  const external = everyone.filter((address) => !local.includes(address))

  const attempt = async (): Promise<SendRecipient[]> => {
    const keys = await Promise.all(
      local.map((address) =>
        addressKeys(address).catch((error) => {
          throw error instanceof NoKutupAddress ? new UnknownRecipient(address) : error
        }),
      ),
    )
    const sealed = await encryptMailMessage(account.key, [account.publicKey, ...keys.map((k) => k.primary)], message)
    const keyPackets: Record<string, string> = { self: sealed.keyPackets[0] }
    local.forEach((address, i) => {
      keyPackets[address] = sealed.keyPackets[i + 1]
    })
    const form = new FormData()
    form.append('meta', new Blob([JSON.stringify({ ...meta(account, draft), keyPackets, ...(draft.id ? { draftId: draft.id } : {}) })], { type: 'application/json' }))
    form.append('data', blob(sealed.dataPacket))
    if (external.length > 0) form.append('mime', blob(message, 'message/rfc822'))
    return (await api.post<{ recipients: SendRecipient[] }>('/mail/send', form)).data.recipients
  }

  try {
    return await attempt()
  } catch (error) {
    const response = (error as { response?: { status?: number; data?: { code?: string; address?: string } } }).response
    if (response?.status === 409 && response.data?.code === 'keyChanged') {
      // A recipient rotated their key since it was looked up: once more.
      forgetKeys(response.data.address)
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

