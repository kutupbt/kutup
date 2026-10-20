import { Ban, DoorOpen, Pencil, Shield, ShieldAlert, UserMinus, UserPlus } from 'lucide-react'
import { useEffect, useId, useMemo, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import type { ChatGroupAccessRequired, ChatGroupDetails as Details, ChatGroupMember, ChatGroupSummary } from '@kutup/chat-core/types'
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@kutup/ui/components/alert-dialog'
import { Avatar } from '@kutup/ui/components/avatar'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { refreshChat, useChat } from '../../app/chatStore'
import { chatErrorMessage } from '../../lib/errors'
import { personName } from '../../lib/names'
import { accountName } from '../../state/accountNames'
import {
  BanDialog,
  GroupAboutSection,
  GroupBansSection,
  GroupEndSection,
  GroupLinkSection,
  GroupPermissionsSection,
  GroupRequestsSection,
  GroupTimerSection,
} from './ChatGroupSettings'
import { Section } from './DetailsPanel'

/** A title's longest (Signal's group name limit). */
const TITLE_MAX = 32

/** Whether this member may do what `required` guards (the home checks it too). */
function allowed(required: ChatGroupAccessRequired | undefined, isAdmin: boolean): boolean {
  return required === 'any' || required === 'member' || (required === 'administrator' && isAdmin)
}

/**
 * A pairwise group's members and what a member can do there
 * (docs/plans/pairwise-groups.md §3): Signal's two roles, administrators
 * adding, removing and promoting members; anyone renaming it or inviting
 * contacts as the group's access allows (the home refuses otherwise); and
 * leaving, with Signal's rule that the last administrator names another
 * first.
 */
export function ChatGroupDetails({ group }: { group: ChatGroupSummary }) {
  const { t } = useTranslation()
  const { service, snapshot, self } = useChat()
  const selfKey = self!.key
  const [members, setMembers] = useState<ChatGroupMember[] | null>(null)
  const [membersFailed, setMembersFailed] = useState(false)
  const [details, setDetails] = useState<Details | null>(null)
  const [banning, setBanning] = useState<{ member: ChatGroupMember; name: string } | null>(null)
  // A removal or a demotion, asked before it is done.
  const [confirming, setConfirming] = useState<{ kind: 'remove' | 'demote'; member: ChatGroupMember; name: string } | null>(null)
  const [busy, setBusy] = useState(false)
  const [adding, setAdding] = useState(false)
  const [renaming, setRenaming] = useState(false)
  const [leaving, setLeaving] = useState(false)
  const profiles = useMemo(() => new Map(snapshot.profiles.map((p) => [p.peer, p])), [snapshot.profiles])
  const nameOf = (account: string) => personName(account, profiles, selfKey, t)
  const member = group.status === 'member'

  // The members, checked again whenever the group moves on.
  useEffect(() => {
    if (!service || !member) return
    let current = true
    service
      .chatGroupMembers(group.groupId)
      .then((list) => {
        if (!current) return
        setMembers(list)
        setMembersFailed(false)
      })
      .catch((error: unknown) => {
        console.warn('chat: the group members could not be read', error)
        // Unknown members stay unknown: nothing that depends on them (who
        // is the last admin before leaving) is offered meanwhile.
        if (current) setMembersFailed(true)
      })
    return () => {
      current = false
    }
  }, [service, group.groupId, group.revision, member])

  // The settings, requests and bans, from the same verified state.
  useEffect(() => {
    if (!service || !member) return
    let current = true
    service
      .chatGroupDetails(group.groupId)
      .then((next) => current && setDetails(next))
      .catch((error: unknown) => console.warn('chat: the group settings could not be read', error))
    return () => {
      current = false
    }
  }, [service, group.groupId, group.revision, member])

  const me = members?.find((m) => m.account === selfKey) ?? null
  const ended = details?.terminated === true
  const isAdmin = me?.administrator === true && !ended
  const canRename = members !== null && !ended && allowed(group.access?.attributes, isAdmin)
  const canAdd = members !== null && !ended && allowed(group.access?.members, isAdmin)
  const banned = new Set(details?.bannedMembers ?? [])
  const removable = (members ?? []).filter((m) => m.account !== selfKey && !m.administrator && (!m.account || banned.has(m.pseudonym)))

  async function run(work: () => Promise<unknown>, done: string) {
    if (!service) return
    setBusy(true)
    try {
      await work()
      toast.success(done)
      await refreshChat()
      setMembers(await service.chatGroupMembers(group.groupId).catch(() => members))
      setDetails(await service.chatGroupDetails(group.groupId).catch(() => details))
    } catch (error) {
      toast.error(chatErrorMessage(error, t))
    } finally {
      setBusy(false)
    }
  }

  if (!member) return null
  const sorted = [...(members ?? [])].sort(
    (a, b) => Number(b.account === selfKey) - Number(a.account === selfKey) || Number(b.administrator) - Number(a.administrator),
  )
  const id = group.groupId
  return (
    <>
      {ended ? (
        <p className="mx-6 mb-2 rounded-md bg-muted px-3 py-2 text-center text-sm" role="status" data-testid="chat-group-ended">
          {t('chat.chatGroup.endedNotice')}
        </p>
      ) : null}
      {canRename ? (
        <section className="flex justify-center px-6 pb-2">
          <Button variant="outline" size="sm" onClick={() => setRenaming(true)} disabled={busy} data-testid="chat-group-rename">
            <Pencil />
            {t('chat.chatGroup.rename')}
          </Button>
        </section>
      ) : null}
      {details ? (
        <>
          <GroupAboutSection details={details} canEdit={canRename} busy={busy} run={run} onSave={(text) => service!.setChatGroupDescription(id, text)} />
          <GroupTimerSection details={details} canEdit={canRename} busy={busy} run={run} onChoose={(seconds) => service!.setChatGroupTimer(id, seconds)} />
        </>
      ) : null}
      {details && isAdmin ? (
        <GroupRequestsSection
          details={details}
          nameOf={nameOf}
          busy={busy}
          run={run}
          onApprove={(pseudonym) => service!.approveChatGroupRequest(id, pseudonym)}
          onDeny={(pseudonym) => service!.denyChatGroupRequest(id, pseudonym)}
        />
      ) : null}
      <Section title={t('chat.group.membersTitle', { count: members?.length ?? group.memberCount })} testId="chat-group-members">
        {canAdd ? (
          <Button
            variant="ghost"
            className="mb-1 w-full justify-start"
            onClick={() => setAdding(true)}
            disabled={busy}
            data-testid="chat-group-add-members"
          >
            <UserPlus />
            {t('chat.chatGroup.addMembers')}
          </Button>
        ) : null}
        {members === null ? (
          <p className="px-2 py-2 text-sm text-muted-foreground" role={membersFailed ? 'alert' : undefined}>
            {membersFailed ? t('chat.chatGroup.membersFailed') : t('chat.chatGroup.loadingMembers')}
          </p>
        ) : (
          <ul className="space-y-1">
            {sorted.map((m) => (
              <MemberRow
                key={m.pseudonym}
                member={m}
                name={m.account ? nameOf(m.account) : t('chat.chatGroup.unverifiedMember')}
                self={m.account === selfKey}
                canManage={isAdmin && m.account !== selfKey}
                banned={banned.has(m.pseudonym)}
                busy={busy}
                onBan={(name) => setBanning({ member: m, name })}
                onToggleAdmin={(name) =>
                  m.administrator
                    ? setConfirming({ kind: 'demote', member: m, name })
                    : void run(() => service!.setChatGroupAdmin(group.groupId, m.pseudonym, true), t('chat.group.adminAdded'))}
                onRemove={(name) => setConfirming({ kind: 'remove', member: m, name })}
              />
            ))}
          </ul>
        )}
        {isAdmin && removable.length > 0 ? (
          <Button
            variant="outline"
            size="sm"
            className="mt-2"
            disabled={busy}
            onClick={() => void run(() => service!.removeUnverifiedChatGroupMembers(id), t('chat.chatGroup.unverifiedRemoved', { count: removable.length }))}
            data-testid="chat-group-remove-unverified"
          >
            <ShieldAlert />
            {t('chat.chatGroup.removeUnverified', { count: removable.length })}
          </Button>
        ) : null}
      </Section>

      {details && isAdmin ? (
        <>
          <GroupLinkSection
            details={details}
            busy={busy}
            run={run}
            onMode={(mode) => service!.setChatGroupLink(id, mode)}
            onReset={() => service!.resetChatGroupLink(id)}
          />
          <GroupPermissionsSection
            details={details}
            busy={busy}
            run={run}
            onAccess={(attributes, adders) => service!.setChatGroupAccess(id, attributes, adders)}
            onAnnouncements={(on) => service!.setChatGroupAnnouncementsOnly(id, on)}
          />
          <GroupBansSection details={details} nameOf={nameOf} busy={busy} run={run} onUnban={(ban) => service!.unbanChatGroup(id, ban)} />
        </>
      ) : null}

      <section className="border-t border-border px-4 py-3">
        <Button
          variant="ghost"
          className="w-full justify-start text-destructive hover:bg-destructive/10 hover:text-destructive"
          disabled={busy || members === null}
          onClick={() => setLeaving(true)}
          data-testid="chat-group-leave"
        >
          <DoorOpen />
          {t('chat.group.leave.action')}
        </Button>
        {isAdmin ? <GroupEndSection busy={busy} run={run} onEnd={() => service!.endChatGroup(id)} /> : null}
      </section>
      <BanDialog
        name={banning?.name ?? null}
        linkOn={details?.link.mode !== undefined && details.link.mode !== 'off'}
        busy={busy}
        onOpenChange={(open) => !open && setBanning(null)}
        onBan={(resetLink) => {
          const target = banning
          setBanning(null)
          if (target) void run(() => service!.banChatGroupMember(id, target.member.pseudonym, resetLink), t('chat.chatGroup.banned'))
        }}
      />

      <AlertDialog open={confirming !== null} onOpenChange={(open) => !open && setConfirming(null)}>
        <AlertDialogContent data-testid="chat-group-member-confirm">
          <AlertDialogHeader>
            <AlertDialogTitle>
              {confirming?.kind === 'remove'
                ? t('chat.chatGroup.removeTitle', { name: confirming.name })
                : t('chat.chatGroup.demoteTitle', { name: confirming?.name ?? '' })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {confirming?.kind === 'remove' ? t('chat.chatGroup.removeBody') : t('chat.chatGroup.demoteBody')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <Button
              variant="destructive"
              data-testid="chat-group-member-confirm-action"
              onClick={() => {
                const target = confirming
                setConfirming(null)
                if (!target) return
                if (target.kind === 'remove') {
                  void run(() => service!.removeChatGroupMember(group.groupId, target.member.pseudonym), t('chat.group.memberRemoved'))
                } else {
                  void run(() => service!.setChatGroupAdmin(group.groupId, target.member.pseudonym, false), t('chat.group.adminRemoved'))
                }
              }}
            >
              {confirming?.kind === 'remove' ? t('chat.chatGroup.removeConfirm') : t('chat.chatGroup.demoteConfirm')}
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      <RenameDialog
        open={renaming}
        onOpenChange={setRenaming}
        current={group.title ?? ''}
        busy={busy}
        onSave={(title) => {
          setRenaming(false)
          void run(() => service!.renameChatGroup(group.groupId, title), t('chat.chatGroup.renamed'))
        }}
      />
      <AddMembersDialog
        open={adding}
        onOpenChange={setAdding}
        candidates={snapshot.contacts
          .filter((c) => c.state === 'accepted' && c.peer !== selfKey && !members?.some((m) => m.account === c.peer))
          .map((c) => c.peer)}
        nameOf={nameOf}
        busy={busy}
        onAdd={(accounts) => {
          setAdding(false)
          void run(async () => {
            const sent = await service!.inviteToChatGroup(group.groupId, accounts)
            if (sent < accounts.length) toast.error(t('chat.chatGroup.someNotInvited', { count: accounts.length - sent }))
          }, t('chat.chatGroup.invitedSent', { count: accounts.length }))
        }}
      />
      <LeaveDialog
        open={leaving}
        onOpenChange={setLeaving}
        members={members ?? []}
        selfKey={selfKey}
        nameOf={nameOf}
        busy={busy}
        onLeave={(successor) => {
          setLeaving(false)
          void run(async () => {
            if (successor) await service!.setChatGroupAdmin(group.groupId, successor, true)
            await service!.leaveChatGroup(group.groupId)
          }, t('chat.group.leave.done'))
        }}
      />
    </>
  )
}

function MemberRow({
  member,
  name,
  self,
  canManage,
  banned,
  busy,
  onToggleAdmin,
  onRemove,
  onBan,
}: {
  member: ChatGroupMember
  name: string
  self: boolean
  canManage: boolean
  banned: boolean
  busy: boolean
  onToggleAdmin: (name: string) => void
  onRemove: (name: string) => void
  onBan: (name: string) => void
}) {
  const { t } = useTranslation()
  const address = member.account ? accountName(member.account) : null
  return (
    <li className="flex items-center gap-3 rounded-lg px-2 py-2 hover:bg-muted" data-testid={`chat-group-member-${member.account ?? member.pseudonym}`}>
      <Avatar name={name} size={32} />
      <span className="min-w-0 flex-1">
        <span className="block truncate text-sm font-medium" dir="auto">{self ? t('chat.you') : name}</span>
        <span className="flex flex-wrap gap-x-2 text-xs text-muted-foreground">
          {address && name !== address && !self ? <span className="truncate">{address}</span> : null}
          {member.administrator ? <span>{t('chat.group.admin')}</span> : null}
          {!member.account ? <span className="text-status-warn">{t('chat.chatGroup.unverifiedHint')}</span> : null}
          {banned ? <span className="text-status-warn" data-testid="chat-group-member-banned">{t('chat.chatGroup.bannedAccount')}</span> : null}
        </span>
      </span>
      {canManage ? (
        <span className="flex shrink-0 items-center">
          <Button
            size="icon"
            variant="ghost"
            disabled={busy}
            onClick={() => onToggleAdmin(name)}
            aria-label={member.administrator ? t('chat.group.removeAdmin', { name }) : t('chat.group.makeAdmin', { name })}
            aria-pressed={member.administrator}
          >
            <Shield className={member.administrator ? 'text-primary' : undefined} />
          </Button>
          <Button
            size="icon"
            variant="ghost"
            disabled={busy}
            onClick={() => onRemove(name)}
            aria-label={t('chat.group.remove', { name })}
            data-testid="chat-group-member-remove"
          >
            <UserMinus />
          </Button>
          <Button
            size="icon"
            variant="ghost"
            disabled={busy}
            onClick={() => onBan(name)}
            aria-label={t('chat.chatGroup.banName', { name })}
            data-testid="chat-group-member-ban"
          >
            <Ban />
          </Button>
        </span>
      ) : null}
    </li>
  )
}

function RenameDialog({
  open,
  onOpenChange,
  current,
  busy,
  onSave,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  current: string
  busy: boolean
  onSave: (title: string) => void
}) {
  const { t } = useTranslation()
  const [title, setTitle] = useState(current)
  useEffect(() => {
    if (open) setTitle(current)
  }, [open, current])
  const tooLong = [...title.trim()].length > TITLE_MAX
  return (
    <Dialog open={open} onOpenChange={(next) => !busy && onOpenChange(next)}>
      <DialogContent className="sm:max-w-md">
        <form
          onSubmit={(event: FormEvent) => {
            event.preventDefault()
            if (!tooLong) onSave(title.trim())
          }}
        >
          <DialogHeader>
            <DialogTitle>{t('chat.chatGroup.rename')}</DialogTitle>
            <DialogDescription>{t('chat.chatGroup.renameDescription')}</DialogDescription>
          </DialogHeader>
          <Field
            label={t('chat.group.info.name')}
            className="my-4"
            error={tooLong ? t('chat.group.info.nameTooLong', { count: TITLE_MAX }) : undefined}
          >
            {(props) => <Input {...props} value={title} onChange={(e) => setTitle(e.target.value)} autoFocus data-testid="chat-group-title-input" />}
          </Field>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" disabled={busy || tooLong || title.trim() === current.trim()} data-testid="chat-group-title-save">
              {t('common.save')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

/** Contacts to invite; only contacts can be (their profile key carries the invitation). */
export function AddMembersDialog({
  open,
  onOpenChange,
  candidates,
  nameOf,
  busy,
  onAdd,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  candidates: string[]
  nameOf: (account: string) => string
  busy: boolean
  onAdd: (accounts: string[]) => void
}) {
  const { t } = useTranslation()
  const [chosen, setChosen] = useState<string[]>([])
  useEffect(() => {
    if (open) setChosen([])
  }, [open])
  return (
    <Dialog open={open} onOpenChange={(next) => !busy && onOpenChange(next)}>
      <DialogContent className="sm:max-w-md" data-testid="chat-group-add-members-dialog">
        <DialogHeader>
          <DialogTitle>{t('chat.chatGroup.addMembers')}</DialogTitle>
          <DialogDescription>{t('chat.chatGroup.addMembersDescription')}</DialogDescription>
        </DialogHeader>
        <ContactPicker candidates={candidates} chosen={chosen} onChange={setChosen} nameOf={nameOf} />
        <DialogFooter>
          <Button type="button" variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button disabled={busy || chosen.length === 0} onClick={() => onAdd(chosen)} data-testid="chat-group-add-members-confirm">
            {t('chat.chatGroup.invite', { count: chosen.length })}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** A checklist of contacts. */
export function ContactPicker({
  candidates,
  chosen,
  onChange,
  nameOf,
}: {
  candidates: string[]
  chosen: string[]
  onChange: (chosen: string[]) => void
  nameOf: (account: string) => string
}) {
  const { t } = useTranslation()
  const pickerId = useId()
  if (candidates.length === 0) {
    return <p className="py-2 text-sm text-muted-foreground">{t('chat.chatGroup.noContacts')}</p>
  }
  const sorted = [...candidates].sort((a, b) => nameOf(a).localeCompare(nameOf(b)))
  return (
    <ul className="max-h-64 space-y-1 overflow-y-auto" aria-label={t('chat.chatGroup.contacts')}>
      {sorted.map((account) => {
        const name = nameOf(account)
        const checked = chosen.includes(account)
        return (
          <li key={account}>
            <div className="flex items-center gap-3 rounded-lg px-2 py-2 hover:bg-muted">
              <Checkbox
                id={`${pickerId}-${account}`}
                checked={checked}
                onCheckedChange={() => onChange(checked ? chosen.filter((a) => a !== account) : [...chosen, account])}
                data-testid={`chat-group-pick-${account}`}
              />
              <label htmlFor={`${pickerId}-${account}`} className="flex min-w-0 flex-1 cursor-pointer items-center gap-3">
                <Avatar name={name} size={28} />
                <span className="truncate text-sm" dir="auto">{name}</span>
              </label>
            </div>
          </li>
        )
      })}
    </ul>
  )
}

function LeaveDialog({
  open,
  onOpenChange,
  members,
  selfKey,
  nameOf,
  busy,
  onLeave,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  members: ChatGroupMember[]
  selfKey: string
  nameOf: (account: string) => string
  busy: boolean
  onLeave: (successor: string | null) => void
}) {
  const { t } = useTranslation()
  const me = members.find((m) => m.account === selfKey)
  const others = members.filter((m) => m.account !== selfKey)
  // Signal's rule: the last administrator names another before leaving,
  // someone whose membership this device verified.
  const needsSuccessor = me?.administrator === true && others.length > 0 && !others.some((m) => m.administrator)
  const candidates = others.filter((m) => m.account)
  const [successor, setSuccessor] = useState('')
  useEffect(() => {
    if (open) setSuccessor('')
  }, [open])
  const chosen = candidates.find((m) => m.pseudonym === successor)
  return (
    <Dialog open={open} onOpenChange={(next) => !busy && onOpenChange(next)}>
      <DialogContent className="sm:max-w-md" data-testid="chat-group-leave-dialog">
        <DialogHeader>
          <DialogTitle>{t('chat.group.leave.title')}</DialogTitle>
          <DialogDescription>{t('chat.group.leave.description')}</DialogDescription>
        </DialogHeader>
        {needsSuccessor && candidates.length === 0 ? (
          <p className="text-sm text-muted-foreground" role="alert">{t('chat.chatGroup.noVerifiedSuccessor')}</p>
        ) : null}
        {needsSuccessor && candidates.length > 0 ? (
          <div className="space-y-2">
            <p className="text-sm">{t('chat.group.leave.chooseAdmin')}</p>
            <ul className="max-h-56 space-y-1 overflow-y-auto" role="radiogroup" aria-label={t('chat.group.leave.chooseAdmin')}>
              {candidates.map((m) => (
                <li key={m.pseudonym}>
                  <label className="flex cursor-pointer items-center gap-3 rounded-lg px-2 py-2 hover:bg-muted">
                    <input
                      type="radio"
                      name="successor"
                      value={m.pseudonym}
                      checked={successor === m.pseudonym}
                      onChange={() => setSuccessor(m.pseudonym)}
                    />
                    <span className="truncate text-sm" dir="auto">{nameOf(m.account!)}</span>
                  </label>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        <DialogFooter>
          <Button type="button" variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button
            variant="destructive"
            disabled={busy || (needsSuccessor && !chosen)}
            onClick={() => onLeave(needsSuccessor && chosen ? chosen.pseudonym : null)}
            data-testid="chat-group-leave-confirm"
          >
            {t('chat.group.leave.action')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
