import { Crown, DoorOpen, Loader2, RefreshCw, Shield, Trash2, UserMinus, UserPlus } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { accountKey, type AccountRef } from '@kutup/chat-core/identity'
import { resolveTyped } from '../../lib/resolveAddress'
import { accountName } from '../../state/accountNames'
import type {
  LocalMlsConversationRecord,
  MlsAuthorityPolicyInspection,
  MlsConversationMember,
  PendingMlsOwnerApprovalRequest,
} from '@kutup/chat-core/types'
import { useContactLookup } from '@kutup/contacts-core/api'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { refreshChat, useChat } from '../../app/chatStore'
import { Avatar } from '@kutup/ui/components/avatar'
import { chatErrorMessage } from '../../lib/errors'
import { personName } from '../../lib/names'
import { groupIdOf } from '../../state/views'
import type { ConversationModel } from '../thread/useConversationModel'
import { useSaveContact } from '../contacts/saveContactState'
import { Section } from './DetailsPanel'
import { GroupLinkSection } from '../groupLink/GroupLinkSection'
import { MlsGroupSecurityDetails } from './MlsGroupSecurityDetails'

/** Owner-governance proposal kinds (`proposal.actionType`). */
const ACTION = { policy: 5, cryptography: 6, close: 7, recovery: 9 } as const

/**
 * A group's members and its governance. Administrators add and remove
 * members and make other administrators; owners (a separate, signed role)
 * change owners, who may send, the message size limit, the ordering
 * authorities, and can close or recover the group — each of those may need
 * the other owners' approval, which is asked for here too.
 */
export function GroupDetails({ model, group }: { model: ConversationModel; group: LocalMlsConversationRecord }) {
  const { t } = useTranslation()
  const { service, snapshot, self, capabilities } = useChat()
  const selfKey = self!.key
  const contacts = useContactLookup()
  const saveContact = useSaveContact()
  const groupId = groupIdOf(group)
  const [busy, setBusy] = useState(false)
  const [adding, setAdding] = useState(false)
  const [confirm, setConfirm] = useState<'close' | 'recover' | null>(null)
  const [policies, setPolicies] = useState<MlsAuthorityPolicyInspection[]>([])
  const [policiesLoading, setPoliciesLoading] = useState(true)
  const [domains, setDomains] = useState('')
  const [maxBytes, setMaxBytes] = useState('')
  const profiles = new Map(snapshot.profiles.map((p) => [p.peer, p]))

  const me = group.currentRoster.find((m) => accountKey(m.account) === selfKey)
  const closed = group.status === 'closed'
  const left = group.left === true
  const canManage = me?.isAdmin === true && !closed && !left
  const isOwner = Boolean(me?.ownerId) && !closed && !left
  const [leaving, setLeaving] = useState(false)
  const departing = new Set(group.departingMembers ?? [])
  const adminCount = group.currentRoster.filter((m) => m.isAdmin).length
  const approval = snapshot.ownerApprovals.find((a) => a.request.proposal.conversationId === groupId)
  const feedback = snapshot.invitationFeedback.filter(
    (f) => f.conversationId === groupId && f.incarnation === group.request.genesis.incarnation,
  )
  const maximum = group.currentCryptographicPolicy.maximumApplicationPlaintextBytes

  useEffect(() => {
    setDomains(group.currentAuthoritySet.authorities.map((a) => a.domain).join(', '))
  }, [groupId, group.currentAuthoritySet])
  useEffect(() => {
    setMaxBytes(String(group.currentCryptographicPolicy.maximumApplicationPlaintextBytes))
  }, [groupId, group.currentCryptographicPolicy])
  useEffect(() => {
    let cancelled = false
    setPoliciesLoading(true)
    void service
      ?.groupAuthorityPolicyDetails(groupId)
      .then((value) => !cancelled && setPolicies(value))
      .catch(() => !cancelled && setPolicies([]))
      .finally(() => !cancelled && setPoliciesLoading(false))
    return () => {
      cancelled = true
    }
  }, [service, groupId, group.currentAuthoritySet.sequence])

  /** Run a group change; `finalized === false` means other owners must approve. */
  async function run(work: () => Promise<boolean | void>, done: string, pending?: string) {
    if (!service || busy) return
    setBusy(true)
    try {
      const finalized = await work()
      await refreshChat()
      toast.success(finalized === false && pending ? pending : done)
    } catch (error) {
      toast.error(chatErrorMessage(error, t))
    } finally {
      setBusy(false)
    }
  }

  const domainList = () => domains.split(/[\s,]+/u).map((d) => d.trim()).filter(Boolean)

  return (
    <>
      {approval ? <ApprovalCard approval={approval} busy={busy} onRespond={(approve) =>
        void run(
          () => (approve ? service!.approveGroupOwnerGovernance(groupId) : service!.rejectGroupOwnerGovernance(groupId)),
          approve ? t('chat.group.approval.approved') : t('chat.group.approval.rejected'),
        )} /> : null}

      {!closed && !left ? <GroupLinkSection group={group} canManage={canManage} /> : null}

      <Section title={t('chat.group.membersTitle', { count: group.currentRoster.length })}>
        <p className="mb-3 text-xs text-muted-foreground">{t('chat.group.rolesExplanation')}</p>
        {canManage ? (
          <Button variant="outline" className="mb-2 w-full justify-start" onClick={() => setAdding(true)} disabled={busy} data-testid="chat-group-add-member">
            <UserPlus />
            {t('chat.group.addMember')}
          </Button>
        ) : null}
        <ul className="space-y-1">
          {group.currentRoster.map((member) => (
            <MemberRow
              key={accountKey(member.account)}
              member={member}
              name={personName(accountKey(member.account), profiles, selfKey, t)}
              self={accountKey(member.account) === selfKey}
              feedback={feedback.find((f) => accountKey(f.member) === accountKey(member.account))?.decision}
              leaving={departing.has(accountKey(member.account))}
              canManage={canManage}
              canOwn={isOwner}
              canDemote={member.isAdmin && !member.ownerId && adminCount > 1}
              busy={busy}
              onToggleAdmin={() =>
                void run(
                  () => service!.setGroupAdministrator(groupId, member.account, !member.isAdmin),
                  member.isAdmin ? t('chat.group.adminRemoved') : t('chat.group.adminAdded'),
                )}
              onToggleOwner={() =>
                void run(
                  () => service!.setGroupOwner(groupId, member.account, !member.ownerId),
                  t('chat.group.ownerUpdated'),
                  t('chat.group.approvalRequested'),
                )}
              onRemove={() => void run(() => service!.removeGroupMember(groupId, member.account), t('chat.group.memberRemoved'))}
              onSaveContact={
                contacts.ready && memberAddress(member) && accountKey(member.account) !== selfKey && !contacts.find(memberAddress(member))
                  ? () => {
                      const address = memberAddress(member)!
                      const name = profiles.get(accountKey(member.account))?.displayName
                      saveContact({ address, name })
                    }
                  : undefined
              }
            />
          ))}
        </ul>
      </Section>

      <Section title={t('chat.group.policyTitle')} testId="chat-group-policies">
        <p className="mb-2 text-sm">{t('chat.group.whoSends')}</p>
        <div className="flex gap-2">
          {(['members', 'administrators'] as const).map((who) => {
            const active = group.currentAuthorizationPolicy.applicationSenders === (who === 'members' ? 1 : 2)
            return (
              <Button
                key={who}
                size="sm"
                variant={active ? 'default' : 'outline'}
                disabled={busy || !isOwner || active}
                onClick={() =>
                  void run(
                    () => service!.setGroupApplicationSenders(groupId, who),
                    t('chat.group.policyUpdated'),
                    t('chat.group.approvalRequested'),
                  )}
                data-testid={`chat-group-senders-${who}`}
              >
                {t(`chat.group.senders.${who}`)}
              </Button>
            )
          })}
        </div>
        <p className="mb-2 mt-4 text-sm">{t('chat.group.whoEdits')}</p>
        <div className="flex gap-2">
          {(['members', 'administrators'] as const).map((who) => {
            const active = group.currentAuthorizationPolicy.groupInfoEditors === (who === 'members' ? 1 : 2)
            return (
              <Button
                key={who}
                size="sm"
                variant={active ? 'default' : 'outline'}
                disabled={busy || !isOwner || active}
                onClick={() =>
                  void run(
                    () => service!.setGroupInfoEditors(groupId, who),
                    t('chat.group.policyUpdated'),
                    t('chat.group.approvalRequested'),
                  )}
                data-testid={`chat-group-editors-${who}`}
              >
                {t(`chat.group.senders.${who}`)}
              </Button>
            )
          })}
        </div>
        <form
          className="mt-4 flex items-end gap-2"
          onSubmit={(event: FormEvent) => {
            event.preventDefault()
            void run(
              () => service!.tightenGroupMaximumPlaintext(groupId, Number(maxBytes)),
              t('chat.group.policyUpdated'),
              t('chat.group.approvalRequested'),
            )
          }}
        >
          <Field label={t('chat.group.maxBytes')} className="flex-1" description={t('chat.group.maxBytesHint')}>
            {(props) => (
              <Input
                {...props}
                type="number"
                min={1024}
                max={maximum - 1}
                value={maxBytes}
                onChange={(e) => setMaxBytes(e.target.value)}
                disabled={!isOwner || busy}
                data-testid="chat-group-maximum-plaintext"
              />
            )}
          </Field>
          <Button
            type="submit"
            size="sm"
            className="mb-6"
            disabled={!isOwner || busy || !Number.isSafeInteger(Number(maxBytes)) || Number(maxBytes) < 1024 || Number(maxBytes) >= maximum}
            data-testid="chat-group-tighten-plaintext"
          >
            {t('chat.group.tighten')}
          </Button>
        </form>
      </Section>

      <Section title={t('chat.group.securityTitle')}>
        <MlsGroupSecurityDetails group={group} authorityPolicies={policies} loading={policiesLoading} />
        {isOwner ? (
          <form
            className="mt-3 flex items-end gap-2"
            onSubmit={(event: FormEvent) => {
              event.preventDefault()
              void run(() => service!.setGroupAuthorities(groupId, domainList()), t('chat.group.authoritiesUpdated'))
            }}
          >
            <Field label={t('chat.group.authorities')} className="flex-1">
              {(props) => (
                <Input
                  {...props}
                  value={domains}
                  onChange={(e) => setDomains(e.target.value)}
                  placeholder={capabilities?.serverName ?? 'example.org'}
                  autoCapitalize="none"
                  autoCorrect="off"
                  data-testid="chat-group-authority-domains"
                />
              )}
            </Field>
            <Button type="submit" size="sm" disabled={busy || domainList().length === 0} data-testid="chat-group-save-authorities">
              {t('chat.group.update')}
            </Button>
          </form>
        ) : null}
      </Section>

      {!closed && !left && me ? (
        <section className="border-t border-border px-4 py-3">
          <Button
            variant="ghost"
            className="w-full justify-start text-destructive hover:bg-destructive/10 hover:text-destructive"
            disabled={busy}
            onClick={() => setLeaving(true)}
            data-testid="chat-group-leave"
          >
            <DoorOpen />
            {t('chat.group.leave.action')}
          </Button>
        </section>
      ) : null}
      <LeaveGroupDialog
        open={leaving}
        onOpenChange={setLeaving}
        group={group}
        selfKey={selfKey}
        nameOf={(address) => personName(address, profiles, selfKey, t)}
        busy={busy}
        onLeave={(successor) => {
          setLeaving(false)
          void run(async () => {
            if (successor) await service!.setGroupAdministrator(groupId, successor, true)
            await service!.leaveGroup(groupId)
          }, t('chat.group.leave.done'))
        }}
      />

      {closed ? (
        <p className="mx-6 mt-4 rounded-lg border border-destructive/40 p-3 text-sm" data-testid="chat-group-closed">
          {t('chat.group.closedNotice')}
        </p>
      ) : isOwner ? (
        <section className="space-y-1 border-t border-border px-4 py-3">
          <Button variant="ghost" className="w-full justify-start" disabled={busy || domainList().length === 0} onClick={() => setConfirm('recover')} data-testid="chat-group-recover">
            <RefreshCw />
            {t('chat.group.recover')}
          </Button>
          <Button
            variant="ghost"
            className="w-full justify-start text-destructive hover:bg-destructive/10 hover:text-destructive"
            disabled={busy}
            onClick={() => setConfirm('close')}
            data-testid="chat-group-close"
          >
            <Trash2 />
            {t('chat.group.close')}
          </Button>
        </section>
      ) : null}

      <AddMemberDialog
        open={adding}
        onOpenChange={setAdding}
        busy={busy}
        onAdd={(account) =>
          run(async () => {
            await service!.addGroupMember(groupId, account)
            setAdding(false)
          }, t('chat.group.memberInvited'))
        }
        homeServer={capabilities?.serverName}
      />
      <ConfirmDestructive
        open={confirm !== null}
        onOpenChange={(open) => !open && setConfirm(null)}
        title={confirm === 'close' ? t('chat.group.closeTitle') : t('chat.group.recoverTitle')}
        description={confirm === 'close' ? t('chat.group.closeDescription') : t('chat.group.recoverDescription')}
        submit={confirm === 'close' ? t('chat.group.close') : t('chat.group.recover')}
        errorFallback={t('chat.errors.unavailable')}
        onConfirm={() => {
          const action = confirm
          setConfirm(null)
          if (action === 'close') {
            void run(() => service!.closeGroup(groupId), t('chat.group.closed'), t('chat.group.approvalRequested'))
          } else {
            void run(() => service!.recoverGroup(groupId, domainList()), t('chat.group.recovered'), t('chat.group.approvalRequested'))
          }
        }}
      />
      {model.readiness.pending.length > 0 || model.readiness.refused.length > 0 ? (
        <p className="mx-6 mt-4 text-xs text-muted-foreground" data-testid="chat-group-delivery-readiness">
          {t('chat.group.readiness', { pending: model.readiness.pending.length, refused: model.readiness.refused.length })}
        </p>
      ) : null}
    </>
  )
}

function MemberRow({
  member,
  name,
  self,
  feedback,
  leaving,
  canManage,
  canOwn,
  canDemote,
  busy,
  onToggleAdmin,
  onToggleOwner,
  onRemove,
  onSaveContact,
}: {
  member: MlsConversationMember
  name: string
  self: boolean
  feedback?: string
  /** Asked to leave; an administrator's client removes them. */
  leaving: boolean
  canManage: boolean
  canOwn: boolean
  canDemote: boolean
  busy: boolean
  onToggleAdmin: () => void
  onToggleOwner: () => void
  onRemove: () => void
  /** Present for a member who is not in the address book. */
  onSaveContact?: () => void
}) {
  const { t } = useTranslation()
  const address = accountKey(member.account)
  return (
    <li className="flex items-center gap-3 rounded-lg px-2 py-2 hover:bg-muted" data-testid={`chat-group-member-${address}`}>
      <Avatar name={self ? address : name} size={32} />
      <span className="min-w-0 flex-1">
        <span className="block truncate text-sm font-medium">{name}</span>
        <span className="flex flex-wrap gap-x-2 text-xs text-muted-foreground">
          {name !== address && !self ? <span className="truncate">{address}</span> : null}
          {member.ownerId ? <span data-testid={`chat-group-member-owner-${address}`}>{t('chat.group.owner')}</span> : null}
          {member.isAdmin ? <span>{t('chat.group.admin')}</span> : null}
          {leaving ? <span className="text-status-warn">{t('chat.group.leave.leaving')}</span> : null}
        </span>
        {feedback ? (
          <span
            className={feedback === 'accepted' ? 'block text-xs text-status-ok' : 'block text-xs text-status-warn'}
            data-testid={`chat-group-invitation-feedback-${address}`}
          >
            {t(`chat.group.feedback.${feedback === 'accepted' || feedback === 'rejected' ? feedback : 'expired'}`)}
          </span>
        ) : null}
      </span>
      {onSaveContact ? (
        <Button size="icon" variant="ghost" onClick={onSaveContact} aria-label={t('chat.contacts.saveNamed', { name })} data-testid={`chat-group-save-contact-${address}`}>
          <UserPlus />
        </Button>
      ) : null}
      {canManage && !self ? (
        <span className="flex shrink-0 items-center">
          {canOwn ? (
            <Button
              size="icon"
              variant="ghost"
              disabled={busy}
              onClick={onToggleOwner}
              aria-label={member.ownerId ? t('chat.group.removeOwner', { name }) : t('chat.group.makeOwner', { name })}
              aria-pressed={Boolean(member.ownerId)}
              data-testid={`chat-group-owner-${address}`}
            >
              <Crown className={member.ownerId ? 'text-primary' : undefined} />
            </Button>
          ) : null}
          <Button
            size="icon"
            variant="ghost"
            disabled={busy || (member.isAdmin && !canDemote)}
            onClick={onToggleAdmin}
            aria-label={member.isAdmin ? t('chat.group.removeAdmin', { name }) : t('chat.group.makeAdmin', { name })}
            aria-pressed={member.isAdmin}
          >
            <Shield className={member.isAdmin ? 'text-primary' : undefined} />
          </Button>
          <Button size="icon" variant="ghost" disabled={busy || Boolean(member.ownerId)} onClick={onRemove} aria-label={t('chat.group.remove', { name })}>
            <UserMinus />
          </Button>
        </span>
      ) : null}
    </li>
  )
}

function ApprovalCard({
  approval,
  busy,
  onRespond,
}: {
  approval: PendingMlsOwnerApprovalRequest
  busy: boolean
  onRespond: (approve: boolean) => void
}) {
  const { t } = useTranslation()
  const shown = (account: AccountRef) => accountName(accountKey(account)) ?? t('chat.someone')
  const requester = shown(approval.requester)
  const kind = approval.request.proposal.actionType
  const key =
    kind === ACTION.close ? 'close' : kind === ACTION.recovery ? 'recovery' : kind === ACTION.policy ? 'policy' : kind === ACTION.cryptography ? 'cryptography' : 'owners'
  const detail =
    key === 'policy'
      ? t(`chat.group.senders.${approval.request.nextAuthorizationPolicy?.applicationSenders === 2 ? 'administrators' : 'members'}`)
      : key === 'cryptography'
        ? String(approval.request.nextCryptographicPolicy?.maximumApplicationPlaintextBytes ?? 0)
        : key === 'owners'
          ? approval.request.nextRoster.filter((m) => m.ownerId).map((m) => shown(m.account)).join(', ')
          : ''
  return (
    <div className="mx-6 mb-4 rounded-lg border border-primary/40 bg-accent/50 p-3" data-testid="chat-group-owner-approval">
      <p className="text-sm font-medium">{t(`chat.group.approval.${key}.title`)}</p>
      <p className="mt-1 text-xs text-muted-foreground">{t(`chat.group.approval.${key}.description`, { requester, detail })}</p>
      <div className="mt-3 flex justify-end gap-2">
        <Button size="sm" variant="outline" disabled={busy} onClick={() => onRespond(false)} data-testid="chat-group-owner-reject">
          {t('chat.group.approval.reject')}
        </Button>
        <Button size="sm" disabled={busy} onClick={() => onRespond(true)} data-testid="chat-group-owner-approve">
          {busy ? <Loader2 className="animate-spin" /> : null}
          {t('chat.group.approval.approve')}
        </Button>
      </div>
    </div>
  )
}

function AddMemberDialog({
  open,
  onOpenChange,
  busy,
  onAdd,
  homeServer,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  busy: boolean
  onAdd: (account: AccountRef) => Promise<void>
  homeServer?: string
}) {
  const { t } = useTranslation()
  const [value, setValue] = useState('')
  const [error, setError] = useState<string | undefined>()
  const [looking, setLooking] = useState(false)
  return (
    <Dialog open={open} onOpenChange={(next) => { onOpenChange(next); if (!next) { setValue(''); setError(undefined) } }}>
      <DialogContent className="sm:max-w-md">
        <form
          className="space-y-4"
          onSubmit={(event) => {
            event.preventDefault()
            if (looking) return
            setLooking(true)
            void resolveTyped(value, homeServer, t)
              .then(async (member) => {
                if ('error' in member) {
                  setError(member.error)
                  return
                }
                await onAdd(member.account)
                setValue('')
              })
              .finally(() => setLooking(false))
          }}
        >
          <DialogHeader>
            <DialogTitle>{t('chat.group.addMember')}</DialogTitle>
            <DialogDescription>{t('chat.group.addMemberDescription')}</DialogDescription>
          </DialogHeader>
          <Field label={t('chat.group.memberAddress')} error={error}>
            {(props) => (
              <Input {...props} autoFocus value={value} onChange={(e) => { setValue(e.target.value); setError(undefined) }} placeholder={t('chat.username')} autoCapitalize="none" autoCorrect="off" />
            )}
          </Field>
          <DialogFooter>
            <Button type="submit" disabled={!value.trim() || busy || looking}>
              {busy || looking ? <Loader2 className="animate-spin" /> : null}
              {t('chat.group.invite')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

/**
 * Signal's "Leave group": a confirmation, and for the last administrator a
 * choice of who takes over. An owner must hand ownership over first, and
 * the only member closes the group instead; both are said here rather than
 * failing after the click.
 */
function LeaveGroupDialog({
  open,
  onOpenChange,
  group,
  selfKey,
  nameOf,
  busy,
  onLeave,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  group: LocalMlsConversationRecord
  selfKey: string
  nameOf: (address: string) => string
  busy: boolean
  onLeave: (successor: MlsConversationMember['account'] | null) => void
}) {
  const { t } = useTranslation()
  const me = group.currentRoster.find((m) => accountKey(m.account) === selfKey)
  const others = group.currentRoster.filter((m) => accountKey(m.account) !== selfKey)
  const lastAdmin = me?.isAdmin === true && group.currentRoster.filter((m) => m.isAdmin).length === 1
  const [successor, setSuccessor] = useState('')
  useEffect(() => {
    if (open) setSuccessor('')
  }, [open])
  const blocked = others.length === 0
    ? t('chat.group.leave.onlyMember')
    : me?.ownerId
      ? t('chat.group.leave.owner')
      : null
  const needsSuccessor = !blocked && lastAdmin
  const chosen = others.find((m) => accountKey(m.account) === successor)
  return (
    <Dialog open={open} onOpenChange={(next) => !busy && onOpenChange(next)}>
      <DialogContent className="sm:max-w-md" data-testid="chat-group-leave-dialog">
        <DialogHeader>
          <DialogTitle>{t('chat.group.leave.title')}</DialogTitle>
          <DialogDescription>{blocked ?? t('chat.group.leave.description')}</DialogDescription>
        </DialogHeader>
        {needsSuccessor ? (
          <div className="space-y-2">
            <p className="text-sm">{t('chat.group.leave.chooseAdmin')}</p>
            <ul className="max-h-56 space-y-1 overflow-y-auto" role="radiogroup" aria-label={t('chat.group.leave.chooseAdmin')}>
              {others.map((member) => {
                const address = accountKey(member.account)
                return (
                  <li key={address}>
                    <label className="flex cursor-pointer items-center gap-3 rounded-lg px-2 py-2 hover:bg-muted">
                      <input
                        type="radio"
                        name="successor"
                        value={address}
                        checked={successor === address}
                        onChange={() => setSuccessor(address)}
                        data-testid={`chat-group-leave-successor-${address}`}
                      />
                      <span className="truncate text-sm">{nameOf(address)}</span>
                    </label>
                  </li>
                )
              })}
            </ul>
          </div>
        ) : null}
        <DialogFooter>
          <Button type="button" variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
            {t('common.cancel')}
          </Button>
          {!blocked ? (
            <Button
              variant="destructive"
              disabled={busy || (needsSuccessor && !chosen)}
              onClick={() => onLeave(needsSuccessor && chosen ? chosen.account : null)}
              data-testid="chat-group-leave-confirm"
            >
              {t('chat.group.leave.action')}
            </Button>
          ) : null}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** An address to save a member under in the address book, once known. */
function memberAddress(member: MlsConversationMember): string | null {
  return accountName(accountKey(member.account))
}
