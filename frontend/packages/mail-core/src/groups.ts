import { useQuery } from '@tanstack/react-query'
import {
  DEFAULT_MAIL_KEY_FLAGS,
  foldAddress,
  generateMailGroupKey,
  MAIL_KEY_FLAGS,
  newMailGroupSigner,
  reshareMailGroupKey,
  reshareMailGroupSigner,
  signMailGroupKeyList,
  verifyMailGroupKeyChain,
  type GroupKeyChainView,
  type GroupKeyMember,
  type GroupMailKey,
  type GroupSignerHolder,
  type MailKeyListInput,
  type SignedMailKeyList,
} from '@kutup/crypto'
import { incarnationIdOfAuthority, verifyDriveKeyBinding } from '@kutup/crypto/identityPins'
import type { DriveIdentity } from '@kutup/drive-core/identity'
import { confirmRecipient } from '@kutup/drive-core/identityPins'
import api from '@kutup/session/client'
import { POLL_MS, type GroupKeyHolderOf } from './api'

// Mail groups (docs/plans/mail-groups.md): distribution lists and shared
// mailboxes. A shared mailbox's key reaches each member as a share, the key's
// secret sealed to their account key (docs/plans/account-ids.md); adding members means sharing every
// key with them, removing one means a new key for everyone who stays. All of
// that happens here, in the browser: the server never holds a group key.

export type GroupKind = 'list' | 'shared'
export type PostPolicy = 'anyone' | 'local' | 'members' | 'managers'
export type GroupRole = 'owner' | 'manager' | 'member'

export interface MailGroup {
  id: string
  address: string
  displayName: string
  description: string
  kind: GroupKind
  postPolicy: PostPolicy
  systemRole: 'postmaster' | 'abuse' | 'security' | 'hostmaster' | null
  storageQuotaBytes: number
  storageUsedBytes: number
  memberCount: number
  createdAt: string
  myRole: GroupRole | null
  /** Whether the signed-in account may send as it. */
  myCanSendAs: boolean
  /**
   * A shared mailbox whose owner or manager was deleted or deactivated: they
   * may still hold its signer's seed, so its keys change only with a new
   * signer (a manager hands over; an administrator starts a new chain).
   */
  needsNewSigner: boolean
}

export interface MailGroupMember {
  userId: string
  username: string
  address: string
  role: GroupRole
  canSendAs: boolean
  active: boolean
  /** A shared mailbox's member whose keys changed (reset): the mailbox's keys go to them again. */
  needsKeys: boolean
}

export interface MailGroupDetail {
  group: MailGroup
  members: MailGroupMember[]
  goesToAdministrators: boolean
}

export interface MailGroupKeyRow {
  fingerprint: string
  publicKey: string
  primary: boolean
  flags: number
  /** The group key's secret sealed to the caller's account key, when they hold it. */
  share: string | null
}

export interface ShareInput {
  userId: string
  share: string
}

/** A new signer of the group's key lists: its seed shared with each owner and manager, handed over from the one in force when there is one. */
export interface NewGroupSigner {
  publicKey: string
  shares: ShareInput[]
  handover?: string
}

export interface NewGroupKey {
  publicKey: string
  shares: ShareInput[]
  /** The next key list naming it, signed by the signer in force after the change. */
  keyList: { data: string; signature: string }
  signer?: NewGroupSigner
}

/** A shared mailbox's keys as the caller holds them, and the signer of its key lists with the caller's share of it (owners and managers). */
export interface MailGroupKeys {
  keys: MailGroupKeyRow[]
  signer?: string
  signingShare?: string
}

export const groupsKey = ['mail', 'groups'] as const

/** The groups the signed-in account belongs to, on Mail's poll: a group an
 * administrator adds the account to shows up while the app is open. */
export function useMyGroups() {
  return useQuery({
    queryKey: groupsKey,
    queryFn: async () => (await api.get<MailGroup[]>('/mail/groups')).data,
    refetchInterval: POLL_MS,
  })
}

export async function groupDetail(id: string): Promise<MailGroupDetail> {
  return (await api.get<MailGroupDetail>(`/mail/groups/${id}`)).data
}

export function useGroupDetail(id: string | undefined) {
  return useQuery({ queryKey: ['mail', 'groups', id, 'detail'], enabled: !!id, queryFn: () => groupDetail(id!) })
}

/** A shared mailbox's keys with the caller's shares. */
export async function groupKeys(id: string): Promise<MailGroupKeys> {
  return (await api.get<MailGroupKeys>(`/mail/groups/${id}/keys`)).data
}

export function useGroupKeys(id: string | undefined) {
  return useQuery({ queryKey: ['mail', 'groups', id, 'keys'], enabled: !!id, staleTime: 60_000, queryFn: () => groupKeys(id!) })
}

/**
 * The keys the caller can open the shared mailbox `groupId`'s mail with,
 * primary first: each share sealed to the caller's account key.
 */
export function heldKeys(rows: MailGroupKeyRow[], groupId: string, holder: GroupKeyHolderOf): GroupMailKey[] {
  return rows.flatMap((row) => (row.share ? [{ ...holder, share: row.share, groupId, fingerprint: row.fingerprint }] : []))
}

/** A Kutup account found by its address. */
export interface AccountRef {
  userId: string
  username: string
  address: string
}

/** The account at a Kutup address; `null` when there is none (or it has no mail key yet). */
export async function resolveAccount(address: string): Promise<AccountRef | null> {
  try {
    return (await api.get<AccountRef>('/mail/accounts', { params: { address } })).data
  } catch (error) {
    if ((error as { response?: { status?: number } }).response?.status === 404) return null
    throw error
  }
}

/** The member's account key, as their server gives it by their account id. */
interface MemberIdentity {
  username: string
  /** `username@server`: the label shown. */
  account: string
  server: string
  accountId: string
  accountIncarnationId: string
  driveHpkePublicKey: string
  driveSigningPublicKey: string
  accountAuthorityPublicKey: string
  driveKeyBinding?: string | null
}

/** The member's account key is not one their account signed. */
export class MemberKeyUnproven extends Error {
  constructor(readonly userId: string) {
    super('a member\'s account key is not signed by their account')
  }
}

/** How the members' keys are trusted: the caller's identity, and whether they confirmed identities in doubt. */
export interface MemberTrust {
  me: DriveIdentity
  /** The caller saw the warning for a member whose identity is in doubt and chose to go on. */
  confirmed: boolean
}

/**
 * A member's account key (docs/plans/account-ids.md): looked up by their
 * account id, kept only when their account authority's Drive key binding
 * vouches for it, and checked against the caller's pins as Drive checks a
 * recipient before sharing (`confirmRecipient`): someone never met is pinned
 * on first use; another authority than the pinned one stops with
 * `IdentityNotConfirmed` until the caller confirms. Nothing is sealed to keys
 * the server alone vouches for.
 */
async function memberKey(member: { userId: string }, trust: MemberTrust): Promise<GroupKeyMember> {
  const { data } = await api.get<MemberIdentity>(`/users/by-id/${encodeURIComponent(member.userId)}`)
  const account = { server: data.server, accountId: data.accountId }
  const bound =
    data.accountId === member.userId &&
    !!data.driveKeyBinding &&
    (await verifyDriveKeyBinding(account, data.accountAuthorityPublicKey, data.driveHpkePublicKey, data.driveSigningPublicKey, data.driveKeyBinding))
  if (!bound || (await incarnationIdOfAuthority(data.accountAuthorityPublicKey)) !== data.accountIncarnationId) {
    throw new MemberKeyUnproven(member.userId)
  }
  await confirmRecipient(trust.me, `${data.username}@${data.server}`, data, trust.confirmed)
  return { account, incarnationId: data.accountIncarnationId, hpkePublicKey: data.driveHpkePublicKey }
}

/** Who signs a shared mailbox's key lists: its owners and managers. */
export function signs(role: GroupRole): boolean {
  return role === 'owner' || role === 'manager'
}

/** A shared mailbox's key-list chain as its server serves it. */
interface GroupChainAnswer {
  groupId: string
  firstSigner: string
  keyLists: { data: string; signature: string }[]
  signerHandovers?: string[]
}

/** The shared mailbox's key-list chain, verified (`mail_group::verify_group_key_chain`). */
export async function groupChain(group: { id: string; address: string }): Promise<GroupKeyChainView> {
  const { data } = await api.get<GroupChainAnswer>('/mail/keys', { params: { email: group.address } })
  if (data.groupId !== group.id) throw new Error('the server answered for another group')
  const chain = await verifyMailGroupKeyChain(group.id, data.firstSigner, data.keyLists, data.signerHandovers ?? [])
  // The chain must be this mailbox's: its newest list names the address asked.
  const asked = await foldAddress(group.address)
  if (!asked || asked !== (await foldAddress(chain.newest.address))) throw new Error('the key lists are for another address')
  return chain
}

/**
 * How the next key list is signed:
 * - `first`: a new group's first signer, shared with `holders`;
 * - `current`: the signer in force, held by the caller;
 * - `handover`: a new signer for `holders`, handed over by the signer in force the caller holds (an owner or manager left);
 * - `restart`: a new chain for `holders` (an administrator who holds no share; senders see a change).
 */
export type GroupSigning =
  | { kind: 'first'; holders: { userId: string }[] }
  | { kind: 'current'; holder: GroupSignerHolder; chain: GroupKeyChainView }
  | { kind: 'handover'; holder: GroupSignerHolder; chain: GroupKeyChainView; holders: { userId: string }[] }
  | { kind: 'restart'; holders: { userId: string }[]; chain: GroupKeyChainView | null }

function sortedKeys(keys: MailKeyListInput['keys']): MailKeyListInput['keys'] {
  return [...keys].sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : a.fingerprint > b.fingerprint ? 1 : 0))
}

/** The list after `chain` naming `added` primary: the keys before stay to open older mail, no longer to encrypt to. */
function nextList(address: string, chain: GroupKeyChainView | null, added: { fingerprint: string; sha256Fingerprint: string }, restart: boolean): MailKeyListInput {
  const before = (chain?.newest.keys ?? []).map((key) => ({ ...key, primary: false, flags: key.flags & ~MAIL_KEY_FLAGS.notObsolete }))
  const keys = sortedKeys([...before, { ...added, primary: true, flags: DEFAULT_MAIL_KEY_FLAGS }])
  const issuedAt = new Date().toISOString()
  if (!chain || restart) return { address, sequence: 1, issuedAt, keys }
  return { address, sequence: chain.sequence + 1, previousHash: chain.digests[chain.digests.length - 1], issuedAt, keys }
}

/**
 * A new key for the shared mailbox `groupId` at `groupAddress`, with a share
 * for each of `members`, and the next key list naming it, signed as
 * `signing` says. Nothing is sealed to a member whose keys are in doubt.
 */
export async function newGroupKey(
  groupAddress: string,
  groupId: string,
  members: { userId: string }[],
  trust: MemberTrust,
  signing: GroupSigning,
): Promise<NewGroupKey> {
  const keys = await Promise.all(members.map((member) => memberKey(member, trust)))
  const made = await generateMailGroupKey(groupAddress, groupId, keys)
  const key = {
    publicKey: made.publicKey,
    shares: members.map((member, i) => ({ userId: member.userId, share: made.shares[i] })),
  }
  const added = { fingerprint: made.fingerprint, sha256Fingerprint: made.sha256Fingerprint }
  if (signing.kind === 'current') {
    const list: SignedMailKeyList = await signMailGroupKeyList(signing.holder, nextList(groupAddress, signing.chain, added, false))
    return { ...key, keyList: { data: list.data, signature: list.signature } }
  }
  const holderKeys = await Promise.all(signing.holders.map((holder) => memberKey(holder, trust)))
  const chain = signing.kind === 'first' ? null : signing.chain
  const signer = await newMailGroupSigner(
    groupId,
    holderKeys,
    nextList(groupAddress, chain, added, signing.kind === 'restart'),
    signing.kind === 'handover' ? { holder: signing.holder, previousListHash: signing.chain.digests[signing.chain.digests.length - 1] } : undefined,
  )
  return {
    ...key,
    keyList: { data: signer.keyList.data, signature: signer.keyList.signature },
    signer: {
      publicKey: signer.publicKey,
      shares: signing.holders.map((holder, i) => ({ userId: holder.userId, share: signer.shares[i] })),
      ...(signer.handover ? { handover: signer.handover } : {}),
    },
  }
}

export interface MemberInput {
  userId: string
  address: string
  role: GroupRole
  canSendAs: boolean
}

export interface MembershipBody {
  members: { userId: string; role: GroupRole; canSendAs: boolean }[]
  keyShares?: (ShareInput & { groupFingerprint: string })[]
  newKey?: NewGroupKey
  /** The signer in force's seed for owners and managers who lack it. */
  signerShares?: ShareInput[]
}

/**
 * The body of `PUT /mail/groups/{id}/members` for a change from `current` to
 * `next`, and whether joining members can read the mailbox's older mail. For
 * a shared mailbox: joining members get a share of every key the caller
 * holds; anyone leaving means a new key for all who stay. A caller without
 * every share (an administrator who is not a member) can only give the
 * mailbox a new key, so joining members read mail from then on.
 */
export async function membershipBody(
  group: MailGroup,
  current: MailGroupMember[],
  next: MemberInput[],
  me: GroupKeyHolderOf | null,
  trust: MemberTrust,
): Promise<{ body: MembershipBody; historyShared: boolean }> {
  const members = next.map(({ userId, role, canSendAs }) => ({ userId, role, canSendAs }))
  if (group.kind !== 'shared') return { body: { members }, historyShared: true }
  // Joining members, and members staying whose keys changed (an
  // administrator reset them): both get the mailbox's keys.
  const joining = next.filter((m) => !current.some((c) => c.userId === m.userId))
  const resealed = next.filter((m) => current.some((c) => c.userId === m.userId && c.needsKeys))
  const added = [...joining, ...resealed]
  const removed = current.filter((c) => !next.some((m) => m.userId === c.userId))
  const answer = await groupKeys(group.id).catch((): MailGroupKeys => ({ keys: [] }))
  const rows = answer.keys
  const held = me ? heldKeys(rows, group.id, me) : []
  const holdsAll = rows.length > 0 && held.length === rows.length
  const body: MembershipBody = { members }
  if (added.length > 0 && holdsAll) {
    const keys = await Promise.all(added.map((member) => memberKey(member, trust)))
    body.keyShares = []
    for (const key of held) {
      const shares = await reshareMailGroupKey(key, keys)
      added.forEach((member, i) => body.keyShares!.push({ groupFingerprint: key.fingerprint, userId: member.userId, share: shares[i] }))
    }
  }
  // A deactivated account gets no share; a manager seals the keys to it
  // again if it comes back.
  const active = (m: { userId: string }) => current.find((c) => c.userId === m.userId)?.active !== false
  // The signing key's holders: the active owners and managers. Losing one,
  // or one deleted or deactivated (`needsNewSigner`), means a new signer,
  // handed over by the one in force (the caller's, if they hold it; an
  // administrator without it starts a new chain). So does gaining one when
  // the caller has no share of the signer to give.
  const holdersBefore = current.filter((c) => signs(c.role) && c.active).map((c) => c.userId)
  const holdersAfter = next.filter((m) => signs(m.role) && active(m))
  const signer: GroupSignerHolder | null =
    me && answer.signer && answer.signingShare ? { ...me, groupId: group.id, signer: answer.signer, signingShare: answer.signingShare } : null
  const gained = holdersAfter.some((h) => !holdersBefore.includes(h.userId))
  const lost =
    holdersBefore.some((id) => !holdersAfter.some((h) => h.userId === id)) || group.needsNewSigner || (gained && !signer)
  if (removed.length > 0 || (joining.length > 0 && !holdsAll) || lost) {
    const chain = await groupChain(group)
    const signing: GroupSigning = lost
      ? signer
        ? { kind: 'handover', holder: signer, chain, holders: holdersAfter }
        : { kind: 'restart', holders: holdersAfter, chain }
      : signer
        ? { kind: 'current', holder: signer, chain }
        : { kind: 'restart', holders: holdersAfter, chain }
    body.newKey = await newGroupKey(group.address, group.id, next.filter(active), trust, signing)
  }
  if (!body.newKey?.signer && signer) {
    // Owners and managers joining, promoted, or reset since get the signer in force.
    const lacking = holdersAfter.filter(
      (h) => !holdersBefore.includes(h.userId) || current.some((c) => c.userId === h.userId && c.needsKeys),
    )
    if (lacking.length > 0) {
      const keys = await Promise.all(lacking.map((holder) => memberKey(holder, trust)))
      const shares = await reshareMailGroupSigner(signer, keys)
      body.signerShares = lacking.map((holder, i) => ({ userId: holder.userId, share: shares[i] }))
    }
  }
  return { body, historyShared: joining.length === 0 || holdsAll }
}

export async function setMembers(groupId: string, body: MembershipBody): Promise<MailGroupDetail> {
  return (await api.put<MailGroupDetail>(`/mail/groups/${groupId}/members`, body)).data
}

export async function updateGroup(
  groupId: string,
  change: { displayName?: string; description?: string; postPolicy?: PostPolicy },
): Promise<MailGroupDetail> {
  return (await api.patch<MailGroupDetail>(`/mail/groups/${groupId}`, change)).data
}

/** Groups the caller may write to whose address or name starts with `q`. */
export async function groupDirectory(q: string): Promise<{ address: string; displayName: string; kind: GroupKind }[]> {
  if (!q.trim()) return []
  return (await api.get<{ address: string; displayName: string; kind: GroupKind }[]>('/mail/groups/directory', { params: { q } })).data
}
