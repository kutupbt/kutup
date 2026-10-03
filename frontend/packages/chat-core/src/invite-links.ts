import axios from 'axios'
import { canonicalAccountAddress, parseAccountAddress } from './identity'
import type { MlsConversationService } from './mls-service'
import type {
  AccountAddress,
  ChatTransportPort,
  GroupJoinRequest,
  InviteLinkCrypto,
  InviteLinkOperation,
  InviteLinkPreview,
  InviteLinkResult,
  LocalMlsConversationRecord,
  MlsGroupInviteLink,
  OwnJoinRequest,
} from './types'

// Group invite links (docs/chat-invite-links.md). The link's secret lives in
// the group information (MLS-encrypted, so every member has it) and in the
// URL fragment of the shared link. Its host keeps a mailbox it cannot read:
// the group's sealed preview and the sealed requests to join. Administrators'
// clients read the requests and add people with an ordinary MLS addition; the
// requester's client accepts the resulting invitation by itself.

/** How often the service looks at links (each kind below keeps its own pace). */
export const INVITE_LINK_POLL_MS = 15_000
/** Administrators of a link anyone may use look this often, so joining is quick. */
const OPEN_LINK_CHECK_MS = 15_000
/** Administrators who approve each request, and requesters, look this often. */
const APPROVAL_CHECK_MS = 60_000
/** Without approval, the first administrator adds people; any after this long. */
const FALLBACK_ADDER_AFTER_MS = 5 * 60_000
const STORAGE_PREFIX = 'kutup.chat.join-requests.v1:'

export type InviteLinkErrorKind = 'invalid' | 'gone' | 'busy' | 'unreachable' | 'unnamed'

export class InviteLinkError extends Error {
  constructor(readonly kind: InviteLinkErrorKind, message?: string) {
    super(message ?? `group link: ${kind}`)
    this.name = 'InviteLinkError'
  }
}

/** `https://chat.example/join#…` for a link fragment, on this app's origin. */
export function inviteLinkUrl(origin: string, fragment: string): string {
  return `${origin.replace(/\/$/, '')}/join#${fragment}`
}

/** The fragment of a Kutup group link, whatever server's app it points at. */
export function inviteFragmentFromUrl(text: string): string | null {
  let url: URL
  try {
    url = new URL(text.trim())
  } catch {
    return null
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null
  if (!/\/join\/?$/.test(url.pathname)) return null
  const fragment = url.hash.slice(1)
  return /^[A-Za-z0-9_-]{44,400}$/.test(fragment) ? fragment : null
}

function statusOf(error: unknown): number | undefined {
  return axios.isAxiosError(error) ? error.response?.status : undefined
}

function asLinkError(error: unknown): unknown {
  switch (statusOf(error)) {
    case 400:
      return new InviteLinkError('invalid')
    case 404:
      return new InviteLinkError('gone')
    case 429:
      return new InviteLinkError('busy')
    case 502:
    case 503:
    case 504:
      return new InviteLinkError('unreachable')
    default:
      return error
  }
}

export function previewOf(
  conversation: LocalMlsConversationRecord,
  link: MlsGroupInviteLink,
): InviteLinkPreview {
  const info = conversation.currentGroupInfo
  if (!info) throw new InviteLinkError('unnamed')
  return {
    conversationId: conversation.request.genesis.conversationId,
    name: info.name,
    ...(info.description ? { description: info.description } : {}),
    ...(info.avatar ? { avatar: info.avatar } : {}),
    memberCount: conversation.currentRoster.length,
    approvalRequired: link.approvalRequired,
  }
}

export type InviteLinkChange =
  | { kind: 'enable'; approvalRequired: boolean }
  | { kind: 'approval'; approvalRequired: boolean }
  | { kind: 'reset' }
  | { kind: 'disable' }

export interface InviteLinkLookup {
  link: MlsGroupInviteLink
  linkId: string
  preview: InviteLinkPreview
  /** Already a member: open the group instead. */
  member: boolean
  /** This account's earlier request through the same link. */
  request?: OwnJoinRequest
}

export class InviteLinkService {
  /** Pending requests an administrator decides, per conversation. */
  private readonly waiting = new Map<string, Array<GroupJoinRequest & { requestIds: string[] }>>()
  /** The preview last stored per link id, so it is sealed again only on a change. */
  private readonly storedPreviews = new Map<string, string>()
  private readonly checkedAt = new Map<string, number>()
  private statusCheckedAt = 0

  constructor(
    private readonly mls: MlsConversationService,
    private readonly transport: ChatTransportPort,
    private readonly crypto: InviteLinkCrypto,
    private readonly self: AccountAddress & { server: string },
    private readonly storage: Pick<Storage, 'getItem' | 'setItem' | 'removeItem'> | null,
  ) {}

  private get selfAddress(): string {
    return canonicalAccountAddress(this.self)
  }

  private async call(host: string, operation: InviteLinkOperation): Promise<InviteLinkResult> {
    try {
      return await this.transport.callInviteLink(host, operation)
    } catch (error) {
      throw asLinkError(error)
    }
  }

  private async putPreview(
    conversation: LocalMlsConversationRecord,
    link: MlsGroupInviteLink,
  ): Promise<void> {
    const preview = previewOf(conversation, link)
    const { linkId, manageToken } = this.crypto.inviteLinkKeys(link)
    await this.call(link.host, {
      op: 'put',
      linkId,
      manageToken,
      preview: this.crypto.inviteLinkSealPreview(link, preview),
    })
    this.storedPreviews.set(linkId, JSON.stringify(preview))
  }

  private async deleteMailbox(link: MlsGroupInviteLink): Promise<void> {
    const { linkId, manageToken } = this.crypto.inviteLinkKeys(link)
    try {
      await this.call(link.host, { op: 'delete', linkId, manageToken })
    } catch (error) {
      // The link no longer works either way: it is gone from the group.
      // An unreachable host forgets the mailbox once nobody reads it.
      console.warn('chat: could not delete an old group link mailbox', error)
    }
    this.storedPreviews.delete(linkId)
  }

  // --- Administrators -----------------------------------------------------

  /** Turn the link on or off, reset it, or change whether requests need approval. */
  async change(conversationId: string, change: InviteLinkChange): Promise<void> {
    const conversation = await this.activeConversation(conversationId)
    const info = conversation.currentGroupInfo
    if (!info) throw new InviteLinkError('unnamed')
    const current = info.inviteLink
    const commit = (inviteLink: MlsGroupInviteLink | null) =>
      this.mls.setGroupInfo(conversationId, {
        name: info.name,
        ...(info.description ? { description: info.description } : {}),
        ...(info.avatar ? { avatar: info.avatar } : {}),
        inviteLink,
      })
    switch (change.kind) {
      case 'enable':
      case 'reset': {
        const approvalRequired = change.kind === 'enable'
          ? change.approvalRequired
          : current?.approvalRequired ?? true
        const link = this.crypto.inviteLinkNew(this.self.server, approvalRequired)
        // The mailbox first: a link in the group must always lead somewhere.
        await this.putPreview(conversation, link)
        try {
          await commit(link)
        } catch (error) {
          await this.deleteMailbox(link)
          throw error
        }
        if (current) await this.deleteMailbox(current)
        return
      }
      case 'approval': {
        if (!current || current.approvalRequired === change.approvalRequired) return
        const link = { ...current, approvalRequired: change.approvalRequired }
        const finalized = await commit(link)
        await this.putPreview(finalized.conversation, link)
        return
      }
      case 'disable':
        if (!current) return
        await commit(null)
        await this.deleteMailbox(current)
        this.waiting.delete(conversationId)
    }
  }

  /** The shareable URL of a group's link, on this app's origin. */
  url(link: MlsGroupInviteLink, origin: string): string {
    return inviteLinkUrl(origin, this.crypto.inviteLinkFragment(link))
  }

  /** Requests waiting for an administrator, per conversation (no network). */
  joinRequests(): GroupJoinRequest[] {
    return [...this.waiting.values()].flat().map(({ conversationId, requester, createdAtMs }) => ({
      conversationId,
      requester,
      createdAtMs,
    }))
  }

  /** Let a waiting requester in, or turn them away. */
  async decide(conversationId: string, requester: string, approve: boolean): Promise<void> {
    const conversation = await this.activeConversation(conversationId)
    const link = conversation.currentGroupInfo?.inviteLink
    const entry = this.waiting.get(conversationId)?.find(item => item.requester === requester)
    if (!link || !entry) return
    const address = parseAccountAddress(requester)
    if (!address) return
    if (approve && !this.isMember(conversation, requester)) {
      await this.mls.addMember(conversationId, address)
    }
    await this.decideAll(link, entry.requestIds, approve)
    this.waiting.set(
      conversationId,
      (this.waiting.get(conversationId) ?? []).filter(item => item.requester !== requester),
    )
  }

  private async decideAll(link: MlsGroupInviteLink, requestIds: string[], approve: boolean) {
    const { linkId, manageToken } = this.crypto.inviteLinkKeys(link)
    for (const requestId of requestIds) {
      await this.call(link.host, { op: 'decide', linkId, manageToken, requestId, approve })
    }
  }

  private isMember(conversation: LocalMlsConversationRecord, address: string): boolean {
    return conversation.currentRoster.some(
      member => canonicalAccountAddress(member.address) === address,
    )
  }

  private async activeConversation(conversationId: string): Promise<LocalMlsConversationRecord> {
    const conversation = (await this.mls.conversations()).find(
      record => record.request.genesis.conversationId === conversationId,
    )
    if (!conversation || conversation.status !== 'active' || conversation.left) {
      throw new Error('this group is not active here')
    }
    return conversation
  }

  /**
   * For each group this account administers with a link on: keep its
   * mailbox and preview current, add people who asked when no approval is
   * needed, and collect the requests an administrator decides. `force`
   * skips the per-group pause (opening a group's details).
   */
  async reconcileRequests(force = false): Promise<boolean> {
    let changed = false
    const now = Date.now()
    const active = new Set<string>()
    for (const conversation of await this.mls.conversations()) {
      const conversationId = conversation.request.genesis.conversationId
      const link = conversation.currentGroupInfo?.inviteLink
      const self = conversation.currentRoster.find(
        member => canonicalAccountAddress(member.address) === this.selfAddress,
      )
      if (conversation.status !== 'active' || conversation.left || !link || !self?.isAdmin) continue
      active.add(conversationId)
      const pace = link.approvalRequired ? APPROVAL_CHECK_MS : OPEN_LINK_CHECK_MS
      if (!force && now - (this.checkedAt.get(conversationId) ?? 0) < pace - 1_000) continue
      this.checkedAt.set(conversationId, now)
      try {
        changed = (await this.reconcileLink(conversation, link)) || changed
      } catch (error) {
        console.warn('chat: could not check a group link', error)
      }
    }
    for (const conversationId of [...this.waiting.keys()]) {
      if (!active.has(conversationId)) {
        this.waiting.delete(conversationId)
        changed = true
      }
    }
    return changed
  }

  private async reconcileLink(
    conversation: LocalMlsConversationRecord,
    link: MlsGroupInviteLink,
  ): Promise<boolean> {
    const conversationId = conversation.request.genesis.conversationId
    const { linkId, manageToken } = this.crypto.inviteLinkKeys(link)
    let result: InviteLinkResult
    try {
      result = await this.call(link.host, { op: 'requests', linkId, manageToken })
    } catch (error) {
      if (error instanceof InviteLinkError && error.kind === 'gone') {
        // The host forgot it (idle, or restored): the link is still on here.
        await this.putPreview(conversation, link)
        return false
      }
      throw error
    }
    if (result.result !== 'requests') throw new Error('group link host sent another answer')
    if (this.storedPreviews.get(linkId) !== JSON.stringify(previewOf(conversation, link))) {
      await this.putPreview(conversation, link)
    }
    const admins = conversation.currentRoster
      .filter(member => member.isAdmin)
      .map(member => canonicalAccountAddress(member.address))
      .sort()
    const firstAdmin = admins[0] === this.selfAddress
    const waiting = new Map<string, GroupJoinRequest & { requestIds: string[] }>()
    for (const entry of result.requests) {
      if (entry.status !== 'pending') continue
      let requester: string
      try {
        const request = this.crypto.inviteLinkOpenRequest(link, entry.request)
        if (request.requester.server !== entry.originDomain) {
          throw new Error('an invite request names an account of another server')
        }
        requester = canonicalAccountAddress(request.requester)
      } catch (error) {
        console.warn('chat: turning away a malformed group link request', error)
        await this.decideAll(link, [entry.requestId], false)
        continue
      }
      if (this.isMember(conversation, requester)) {
        await this.decideAll(link, [entry.requestId], true)
        continue
      }
      const existing = waiting.get(requester)
      if (existing) {
        existing.requestIds.push(entry.requestId)
        continue
      }
      waiting.set(requester, {
        conversationId,
        requester,
        createdAtMs: entry.createdAtMs,
        requestIds: [entry.requestId],
      })
    }
    if (!link.approvalRequired) {
      for (const [requester, entry] of [...waiting]) {
        // One administrator adds, so two do not race to commit the same
        // addition; another steps in when that one is away.
        if (!firstAdmin && Date.now() - entry.createdAtMs < FALLBACK_ADDER_AFTER_MS) continue
        const address = parseAccountAddress(requester)
        if (!address) continue
        try {
          await this.mls.addMember(conversationId, address)
        } catch (error) {
          console.warn('chat: could not add someone who joined by link', error)
          break
        }
        await this.decideAll(link, entry.requestIds, true)
        waiting.delete(requester)
      }
    }
    const before = JSON.stringify(this.waiting.get(conversationId) ?? [])
    const after = [...waiting.values()]
    this.waiting.set(conversationId, after)
    return before !== JSON.stringify(after)
  }

  // --- Requesters ---------------------------------------------------------

  private storageKey(): string {
    return `${STORAGE_PREFIX}${this.selfAddress}`
  }

  ownRequests(): OwnJoinRequest[] {
    try {
      const stored = this.storage?.getItem(this.storageKey())
      const parsed: unknown = stored ? JSON.parse(stored) : []
      return Array.isArray(parsed) ? (parsed as OwnJoinRequest[]) : []
    } catch {
      return []
    }
  }

  private saveOwnRequests(requests: OwnJoinRequest[]): void {
    try {
      if (requests.length === 0) this.storage?.removeItem(this.storageKey())
      else this.storage?.setItem(this.storageKey(), JSON.stringify(requests))
    } catch (error) {
      console.warn('chat: could not keep group link requests', error)
    }
  }

  /** What a link leads to. Throws an {@link InviteLinkError} when it leads nowhere. */
  async lookUp(url: string): Promise<InviteLinkLookup> {
    const fragment = inviteFragmentFromUrl(url)
    if (!fragment) throw new InviteLinkError('invalid')
    let parsed: { secret: string; host: string }
    try {
      parsed = this.crypto.inviteLinkParse(fragment)
    } catch {
      throw new InviteLinkError('invalid')
    }
    const link: MlsGroupInviteLink = { ...parsed, approvalRequired: false }
    const { linkId } = this.crypto.inviteLinkKeys(link)
    const result = await this.call(link.host, { op: 'preview', linkId })
    if (result.result !== 'preview') throw new InviteLinkError('invalid')
    let preview: InviteLinkPreview
    try {
      preview = this.crypto.inviteLinkOpenPreview(link, result.preview)
    } catch {
      throw new InviteLinkError('invalid')
    }
    const member = (await this.mls.conversations()).some(record =>
      record.request.genesis.conversationId === preview.conversationId
      && record.status === 'active'
      && !record.left)
    const request = this.ownRequests().find(item => item.linkId === linkId)
    return {
      link: { ...link, approvalRequired: preview.approvalRequired },
      linkId,
      preview,
      member,
      ...(request ? { request } : {}),
    }
  }

  /** Ask to join through a looked-up link. */
  async requestToJoin(lookup: InviteLinkLookup): Promise<OwnJoinRequest> {
    const statusToken = this.crypto.inviteStatusToken()
    const request = this.crypto.inviteLinkSealRequest(lookup.link, {
      requester: { username: this.self.username, server: this.self.server },
      createdAtMs: Date.now(),
    })
    const result = await this.call(lookup.link.host, {
      op: 'request',
      linkId: lookup.linkId,
      request,
      statusToken,
    })
    if (result.result !== 'requested') throw new InviteLinkError('invalid')
    const own: OwnJoinRequest = {
      linkId: lookup.linkId,
      host: lookup.link.host,
      secret: lookup.link.secret,
      requestId: result.requestId,
      statusToken,
      conversationId: lookup.preview.conversationId,
      groupName: lookup.preview.name,
      requestedAtMs: Date.now(),
      status: 'pending',
    }
    this.saveOwnRequests([
      ...this.ownRequests().filter(item => item.linkId !== own.linkId),
      own,
    ])
    return own
  }

  /** Take a request back, or forget one that was turned down. */
  async cancel(linkId: string): Promise<void> {
    const request = this.ownRequests().find(item => item.linkId === linkId)
    if (!request) return
    if (request.status === 'pending') {
      try {
        await this.call(request.host, {
          op: 'cancel',
          linkId,
          requestId: request.requestId,
          statusToken: request.statusToken,
        })
      } catch (error) {
        if (!(error instanceof InviteLinkError && error.kind === 'gone')) throw error
      }
    }
    this.saveOwnRequests(this.ownRequests().filter(item => item.linkId !== linkId))
  }

  /**
   * Accept the invitation an administrator's addition sends for a request
   * this account made, and learn about requests turned down. Returns whether
   * anything changed.
   */
  async reconcileOwnRequests(force = false): Promise<boolean> {
    let requests = this.ownRequests()
    if (requests.length === 0) return false
    let changed = false
    const joined = new Set(
      (await this.mls.conversations())
        .filter(record => record.status === 'active' && !record.left)
        .map(record => record.request.genesis.conversationId),
    )
    const waiting = requests.filter(request => request.status === 'pending')
    if (waiting.length > 0) {
      const invitations = await this.mls.invitations()
      for (const request of waiting) {
        const invitation = invitations.find(item => item.conversationId === request.conversationId)
        if (!invitation || joined.has(request.conversationId)) continue
        try {
          await this.mls.acceptInvitation(invitation)
          joined.add(request.conversationId)
        } catch (error) {
          console.warn('chat: could not accept a group joined by link', error)
        }
      }
    }
    const remaining = requests.filter(request => !joined.has(request.conversationId))
    if (remaining.length !== requests.length) {
      requests = remaining
      changed = true
    }
    if (force || Date.now() - this.statusCheckedAt >= APPROVAL_CHECK_MS - 1_000) {
      this.statusCheckedAt = Date.now()
      for (const request of requests) {
        if (request.status !== 'pending') continue
        try {
          const result = await this.call(request.host, {
            op: 'status',
            linkId: request.linkId,
            requestId: request.requestId,
            statusToken: request.statusToken,
          })
          if (result.result === 'status' && result.status === 'denied') {
            request.status = 'denied'
            changed = true
          }
        } catch (error) {
          if (error instanceof InviteLinkError && error.kind === 'gone') {
            request.status = 'gone'
            changed = true
          }
        }
      }
    }
    if (changed) this.saveOwnRequests(requests)
    return changed
  }
}
