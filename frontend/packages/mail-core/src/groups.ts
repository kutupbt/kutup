import { useQuery } from '@tanstack/react-query'
import { generateMailGroupKey, reshareMailGroupKey, type GroupKeyMember, type GroupMailKey } from '@kutup/crypto'
import { incarnationIdOfAuthority, verifyDriveKeyBinding } from '@kutup/crypto/identityPins'
import api from '@kutup/session/client'
import type { GroupKeyHolderOf } from './api'

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
}

export interface MailGroupMember {
  userId: string
  username: string
  address: string
  role: GroupRole
  canSendAs: boolean
  active: boolean
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

export interface NewGroupKey {
  publicKey: string
  shares: ShareInput[]
}

export const groupsKey = ['mail', 'groups'] as const

/** The groups the signed-in account belongs to. */
export function useMyGroups() {
  return useQuery({
    queryKey: groupsKey,
    queryFn: async () => (await api.get<MailGroup[]>('/mail/groups')).data,
  })
}

export async function groupDetail(id: string): Promise<MailGroupDetail> {
  return (await api.get<MailGroupDetail>(`/mail/groups/${id}`)).data
}

export function useGroupDetail(id: string | undefined) {
  return useQuery({ queryKey: ['mail', 'groups', id, 'detail'], enabled: !!id, queryFn: () => groupDetail(id!) })
}

/** A shared mailbox's keys with the caller's shares. */
export async function groupKeys(id: string): Promise<MailGroupKeyRow[]> {
  return (await api.get<MailGroupKeyRow[]>(`/mail/groups/${id}/keys`)).data
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

/**
 * A member's account key (docs/plans/account-ids.md): looked up by their
 * account id and kept only when their account authority's Drive key binding
 * vouches for it, for that account.
 */
async function memberKey(userId: string): Promise<GroupKeyMember> {
  const { data } = await api.get<MemberIdentity>(`/users/by-id/${encodeURIComponent(userId)}`)
  const account = { server: data.server, accountId: data.accountId }
  const bound =
    data.accountId === userId &&
    !!data.driveKeyBinding &&
    (await verifyDriveKeyBinding(account, data.accountAuthorityPublicKey, data.driveHpkePublicKey, data.driveSigningPublicKey, data.driveKeyBinding))
  if (!bound || (await incarnationIdOfAuthority(data.accountAuthorityPublicKey)) !== data.accountIncarnationId) {
    throw new MemberKeyUnproven(userId)
  }
  return { account, incarnationId: data.accountIncarnationId, hpkePublicKey: data.driveHpkePublicKey }
}

/** A new key for the shared mailbox `groupId` at `groupAddress`, with a share for each of `members`. */
export async function newGroupKey(groupAddress: string, groupId: string, members: { userId: string }[]): Promise<NewGroupKey> {
  const keys = await Promise.all(members.map((member) => memberKey(member.userId)))
  const made = await generateMailGroupKey(groupAddress, groupId, keys)
  return {
    publicKey: made.publicKey,
    shares: members.map((member, i) => ({ userId: member.userId, share: made.shares[i] })),
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
): Promise<{ body: MembershipBody; historyShared: boolean }> {
  const members = next.map(({ userId, role, canSendAs }) => ({ userId, role, canSendAs }))
  if (group.kind !== 'shared') return { body: { members }, historyShared: true }
  const added = next.filter((m) => !current.some((c) => c.userId === m.userId))
  const removed = current.filter((c) => !next.some((m) => m.userId === c.userId))
  const rows = await groupKeys(group.id).catch(() => [] as MailGroupKeyRow[])
  const held = me ? heldKeys(rows, group.id, me) : []
  const holdsAll = rows.length > 0 && held.length === rows.length
  const body: MembershipBody = { members }
  if (added.length > 0 && holdsAll) {
    const keys = await Promise.all(added.map((member) => memberKey(member.userId)))
    body.keyShares = []
    for (const key of held) {
      const shares = await reshareMailGroupKey(key, keys)
      added.forEach((member, i) => body.keyShares!.push({ groupFingerprint: key.fingerprint, userId: member.userId, share: shares[i] }))
    }
  }
  if (removed.length > 0 || (added.length > 0 && !holdsAll)) {
    body.newKey = await newGroupKey(group.address, group.id, next)
  }
  return { body, historyShared: added.length === 0 || holdsAll }
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
