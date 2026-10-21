import { Ban, Check, Copy, Link2, Megaphone, RotateCcw, Timer, UserCheck, UserX, XCircle } from 'lucide-react'
import { QRCodeSVG } from 'qrcode.react'
import { useEffect, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import type { ChatGroupBan, ChatGroupDetails, ChatGroupLinkMode } from '@kutup/chat-core/types'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Label } from '@kutup/ui/components/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { Textarea } from '@kutup/ui/components/textarea'
import { cn } from '@kutup/ui/lib/cn'
import { chatGroupLinkUrl } from '../../lib/chatGroupLink'
import { DISAPPEARING_PRESETS } from '../../lib/disappearing'
import { Section } from './DetailsPanel'

/** Signal-Desktop's description limit, in characters (the core checks it too). */
const DESCRIPTION_MAX = 480

/** Runs an action, saying how it went; the panel reloads after. */
export type GroupRun = (work: () => Promise<unknown>, done: string) => Promise<void>

/** The description, shown to every member; editable as the title is. */
export function GroupAboutSection({
  details,
  canEdit,
  busy,
  run,
  onSave,
}: {
  details: ChatGroupDetails
  canEdit: boolean
  busy: boolean
  run: GroupRun
  onSave: (description: string) => Promise<void>
}) {
  const { t } = useTranslation()
  const [editing, setEditing] = useState(false)
  if (!details.description && !canEdit) return null
  return (
    <Section title={t('chat.chatGroup.about')} testId="chat-group-about">
      {details.description ? (
        <p className="whitespace-pre-line break-words text-sm" dir="auto" data-testid="chat-group-description">
          {details.description}
        </p>
      ) : (
        <p className="text-sm text-muted-foreground">{t('chat.chatGroup.noDescription')}</p>
      )}
      {canEdit ? (
        <Button variant="ghost" size="sm" className="mt-2" disabled={busy} onClick={() => setEditing(true)} data-testid="chat-group-description-edit">
          {details.description ? t('chat.chatGroup.editDescription') : t('chat.chatGroup.addDescription')}
        </Button>
      ) : null}
      <DescriptionDialog
        open={editing}
        onOpenChange={setEditing}
        current={details.description ?? ''}
        busy={busy}
        onSave={(description) => {
          setEditing(false)
          void run(() => onSave(description), t('chat.chatGroup.descriptionSaved'))
        }}
      />
    </Section>
  )
}

function DescriptionDialog({
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
  onSave: (description: string) => void
}) {
  const { t } = useTranslation()
  const [text, setText] = useState(current)
  useEffect(() => {
    if (open) setText(current)
  }, [open, current])
  const tooLong = [...text.trim()].length > DESCRIPTION_MAX
  return (
    <Dialog open={open} onOpenChange={(next) => !busy && onOpenChange(next)}>
      <DialogContent className="sm:max-w-md">
        <form
          onSubmit={(event: FormEvent) => {
            event.preventDefault()
            if (!tooLong) onSave(text.trim())
          }}
        >
          <DialogHeader>
            <DialogTitle>{t('chat.chatGroup.editDescription')}</DialogTitle>
            <DialogDescription>{t('chat.chatGroup.descriptionHint')}</DialogDescription>
          </DialogHeader>
          <Field
            label={t('chat.chatGroup.description')}
            className="my-4"
            error={tooLong ? t('chat.chatGroup.descriptionTooLong', { count: DESCRIPTION_MAX }) : undefined}
          >
            {(props) => (
              <Textarea {...props} rows={5} value={text} onChange={(e) => setText(e.target.value)} autoFocus data-testid="chat-group-description-input" />
            )}
          </Field>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" disabled={busy || tooLong || text.trim() === current.trim()} data-testid="chat-group-description-save">
              {t('common.save')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

/** The group's disappearing-messages timer: every member's messages carry it. */
export function GroupTimerSection({
  details,
  canEdit,
  busy,
  run,
  onChoose,
}: {
  details: ChatGroupDetails
  canEdit: boolean
  busy: boolean
  run: GroupRun
  onChoose: (seconds: number) => Promise<void>
}) {
  const { t } = useTranslation()
  const current = details.timerSeconds === 0 ? undefined : details.timerSeconds
  return (
    <Section title={t('chat.disappearing.setting')} testId="chat-group-timer">
      <p className="mb-3 flex items-start gap-2 text-sm text-muted-foreground">
        <Timer className="mt-0.5 size-4 shrink-0" aria-hidden />
        {t('chat.chatGroup.timerExplanation')}
      </p>
      <div role="radiogroup" aria-label={t('chat.disappearing.setting')} className="grid grid-cols-2 gap-1.5">
        {DISAPPEARING_PRESETS.map((option) => {
          const active = current === option.seconds
          return (
            <button
              key={option.id}
              type="button"
              role="radio"
              aria-checked={active}
              disabled={busy || !canEdit}
              onClick={() => !active && void run(() => onChoose(option.seconds ?? 0), t('chat.chatGroup.timerSaved'))}
              data-testid={`chat-group-timer-${option.id}`}
              className={cn(
                'flex items-center justify-between rounded-lg border px-3 py-2 text-sm transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-60',
                active ? 'border-primary bg-accent font-medium' : 'border-border hover:bg-muted',
              )}
            >
              {t(`chat.disappearing.presets.${option.id}`)}
              {active ? <Check className="size-4 text-primary" aria-hidden /> : null}
            </button>
          )
        })}
      </div>
    </Section>
  )
}

/** The invite link (administrators): on with or without approval, shared, reset. */
export function GroupLinkSection({
  details,
  busy,
  run,
  onMode,
  onReset,
}: {
  details: ChatGroupDetails
  busy: boolean
  run: GroupRun
  onMode: (mode: ChatGroupLinkMode) => Promise<void>
  onReset: () => Promise<void>
}) {
  const { t } = useTranslation()
  const [resetting, setResetting] = useState(false)
  const url = details.link.fragment ? chatGroupLinkUrl(details.link.fragment) : null
  async function copy() {
    if (!url) return
    try {
      await navigator.clipboard.writeText(url)
      toast.success(t('chat.chatGroup.linkCopied'))
    } catch {
      toast.error(t('chat.chatGroup.linkCopyFailed'))
    }
  }
  return (
    <Section title={t('chat.chatGroup.link')} testId="chat-group-link">
      <p className="mb-3 flex items-start gap-2 text-sm text-muted-foreground">
        <Link2 className="mt-0.5 size-4 shrink-0" aria-hidden />
        {t('chat.chatGroup.linkExplanation')}
      </p>
      <Label className="mb-1 block text-sm">{t('chat.chatGroup.linkMode')}</Label>
      <Select
        value={details.link.mode}
        disabled={busy}
        onValueChange={(mode) => void run(() => onMode(mode as ChatGroupLinkMode), t('chat.chatGroup.linkSaved'))}
      >
        <SelectTrigger data-testid="chat-group-link-mode">
          <SelectValue placeholder={t('chat.chatGroup.linkModes.off')} />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="off">{t('chat.chatGroup.linkModes.off')}</SelectItem>
          <SelectItem value="join" data-testid="chat-group-link-mode-join">{t('chat.chatGroup.linkModes.join')}</SelectItem>
          <SelectItem value="approve" data-testid="chat-group-link-mode-approve">{t('chat.chatGroup.linkModes.approve')}</SelectItem>
        </SelectContent>
      </Select>
      {url ? (
        <div className="mt-3 space-y-2">
          <div className="flex justify-center rounded-lg bg-white p-3">
            <QRCodeSVG value={url} size={160} aria-label={t('chat.chatGroup.linkQr')} />
          </div>
          <p className="break-all rounded-md bg-muted px-2 py-1 font-mono text-xs" data-testid="chat-group-link-url">{url}</p>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => void copy()} data-testid="chat-group-link-copy">
              <Copy />
              {t('chat.chatGroup.linkCopy')}
            </Button>
            <Button variant="ghost" size="sm" disabled={busy} onClick={() => setResetting(true)} data-testid="chat-group-link-reset">
              <RotateCcw />
              {t('chat.chatGroup.linkReset')}
            </Button>
          </div>
        </div>
      ) : null}
      <ConfirmDestructive
        open={resetting}
        onOpenChange={setResetting}
        title={t('chat.chatGroup.linkResetTitle')}
        description={t('chat.chatGroup.linkResetBody')}
        submit={t('chat.chatGroup.linkReset')}
        errorFallback={t('chat.chatGroup.actionFailed')}
        onConfirm={() => {
          setResetting(false)
          void run(onReset, t('chat.chatGroup.linkResetDone'))
        }}
      />
    </Section>
  )
}

/** Requests to join (administrators), seen at this device's last sync. */
export function GroupRequestsSection({
  details,
  nameOf,
  busy,
  run,
  onApprove,
  onDeny,
}: {
  details: ChatGroupDetails
  nameOf: (account: string) => string
  busy: boolean
  run: GroupRun
  onApprove: (pseudonym: string) => Promise<void>
  onDeny: (pseudonym: string) => Promise<void>
}) {
  const { t } = useTranslation()
  if (details.requests.length === 0) return null
  return (
    <Section title={t('chat.chatGroup.requests', { count: details.requests.length })} testId="chat-group-requests">
      <p className="mb-2 text-xs text-muted-foreground">{t('chat.chatGroup.requestsHint')}</p>
      <ul className="space-y-1">
        {details.requests.map((request) => {
          const name = request.account
            ? nameOf(request.account)
            : request.claimed
              ? t('chat.chatGroup.claimsToBe', { name: nameOf(request.claimed) })
              : t('chat.chatGroup.unverifiedRequester')
          return (
            <li key={request.pseudonym} className="flex items-center gap-3 rounded-lg px-2 py-2 hover:bg-muted" data-testid={`chat-group-request-${request.account ?? request.pseudonym}`}>
              <span className="min-w-0 flex-1">
                <span className="block truncate text-sm font-medium" dir="auto">{name}</span>
                {request.banned ? <span className="text-xs text-status-warn">{t('chat.chatGroup.bannedAccount')}</span> : null}
                {request.unconfirmed ? (
                  <span className="block text-xs text-muted-foreground">{t('chat.chatGroup.requestUnconfirmed')}</span>
                ) : !request.account ? (
                  <span className="text-xs text-status-warn">{t('chat.chatGroup.unverifiedHint')}</span>
                ) : null}
              </span>
              <Button
                size="icon"
                variant="ghost"
                disabled={busy || request.banned || request.unconfirmed || !request.claimed}
                aria-label={t('chat.chatGroup.approve', { name })}
                onClick={() => void run(() => onApprove(request.pseudonym), t('chat.chatGroup.approved'))}
                data-testid="chat-group-request-approve"
              >
                <UserCheck />
              </Button>
              <Button
                size="icon"
                variant="ghost"
                disabled={busy}
                aria-label={t('chat.chatGroup.deny', { name })}
                onClick={() => void run(() => onDeny(request.pseudonym), t('chat.chatGroup.denied'))}
                data-testid="chat-group-request-deny"
              >
                <UserX />
              </Button>
            </li>
          )
        })}
      </ul>
    </Section>
  )
}

/** Who may edit the details and add members, and who may send (administrators). */
export function GroupPermissionsSection({
  details,
  busy,
  run,
  onAccess,
  onAnnouncements,
}: {
  details: ChatGroupDetails
  busy: boolean
  run: GroupRun
  onAccess: (attributes: 'member' | 'administrator', members: 'member' | 'administrator') => Promise<void>
  onAnnouncements: (on: boolean) => Promise<void>
}) {
  const { t } = useTranslation()
  const level = (value: string): 'member' | 'administrator' => (value === 'administrator' ? 'administrator' : 'member')
  const attributes = level(details.access.attributes)
  const members = level(details.access.members)
  const saved = t('chat.chatGroup.permissionsSaved')
  return (
    <Section title={t('chat.chatGroup.permissions')} testId="chat-group-permissions">
      <div className="space-y-3">
        <PermissionSelect
          label={t('chat.chatGroup.whoEdits')}
          value={attributes}
          busy={busy}
          testId="chat-group-who-edits"
          onChange={(value) => void run(() => onAccess(value, members), saved)}
        />
        <PermissionSelect
          label={t('chat.chatGroup.whoAdds')}
          value={members}
          busy={busy}
          testId="chat-group-who-adds"
          onChange={(value) => void run(() => onAccess(attributes, value), saved)}
        />
        <div className="flex items-start gap-3">
          <Checkbox
            id="chat-group-announcements"
            checked={details.announcementsOnly}
            disabled={busy}
            onCheckedChange={(on) => void run(() => onAnnouncements(on === true), saved)}
            data-testid="chat-group-announcements"
          />
          <label htmlFor="chat-group-announcements" className="text-sm">
            <span className="flex items-center gap-1 font-medium">
              <Megaphone className="size-4" aria-hidden />
              {t('chat.chatGroup.announcementsOnly')}
            </span>
            <span className="text-muted-foreground">{t('chat.chatGroup.announcementsOnlyHint')}</span>
          </label>
        </div>
      </div>
    </Section>
  )
}

function PermissionSelect({
  label,
  value,
  busy,
  testId,
  onChange,
}: {
  label: string
  value: 'member' | 'administrator'
  busy: boolean
  testId: string
  onChange: (value: 'member' | 'administrator') => void
}) {
  const { t } = useTranslation()
  return (
    <div>
      <Label className="mb-1 block text-sm">{label}</Label>
      <Select value={value} disabled={busy} onValueChange={(next) => next !== value && onChange(next === 'administrator' ? 'administrator' : 'member')}>
        <SelectTrigger data-testid={testId}>
          <SelectValue placeholder={t('chat.groupUpdates.allMembers')} />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="member">{t('chat.chatGroup.everyMember')}</SelectItem>
          <SelectItem value="administrator">{t('chat.chatGroup.onlyAdministrators')}</SelectItem>
        </SelectContent>
      </Select>
    </div>
  )
}

/** The bans (administrators): accounts, and pseudonyms nobody verified. */
export function GroupBansSection({
  details,
  nameOf,
  busy,
  run,
  onUnban,
}: {
  details: ChatGroupDetails
  nameOf: (account: string) => string
  busy: boolean
  run: GroupRun
  onUnban: (ban: ChatGroupBan) => Promise<void>
}) {
  const { t } = useTranslation()
  if (details.banListUnreadable) {
    return (
      <Section title={t('chat.chatGroup.bans', { count: 0 })} testId="chat-group-bans">
        <p className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive" role="alert" data-testid="chat-group-ban-list-unreadable">
          {t('chat.chatGroup.banListUnreadable')}
        </p>
      </Section>
    )
  }
  if (details.bans.length === 0) return null
  return (
    <Section title={t('chat.chatGroup.bans', { count: details.bans.length })} testId="chat-group-bans">
      {details.banListFull ? (
        <p className="mb-2 rounded-md bg-status-warn/10 px-3 py-2 text-sm text-status-warn" role="status" data-testid="chat-group-ban-list-full">
          {t('chat.chatGroup.banListFull')}
        </p>
      ) : null}
      <ul className="space-y-1">
        {details.bans.map((ban) => {
          const name = ban.account ? nameOf(ban.account) : t('chat.chatGroup.unverifiedRequester')
          return (
            <li key={ban.account ?? ban.pseudonyms[0]} className="flex items-center gap-3 rounded-lg px-2 py-2 hover:bg-muted" data-testid={`chat-group-ban-${ban.account ?? ban.pseudonyms[0]}`}>
              <Ban className="size-4 shrink-0 text-muted-foreground" aria-hidden />
              <span className="min-w-0 flex-1 truncate text-sm" dir="auto">{name}</span>
              <Button
                variant="ghost"
                size="sm"
                disabled={busy}
                onClick={() => void run(() => onUnban(ban), t('chat.chatGroup.unbanned'))}
                data-testid="chat-group-unban"
              >
                {t('chat.chatGroup.unban')}
              </Button>
            </li>
          )
        })}
      </ul>
    </Section>
  )
}

/** Ending the group for everyone (administrators), confirmed first. */
export function GroupEndSection({ busy, run, onEnd }: { busy: boolean; run: GroupRun; onEnd: () => Promise<void> }) {
  const { t } = useTranslation()
  const [confirming, setConfirming] = useState(false)
  return (
    <>
      <Button
        variant="ghost"
        className="w-full justify-start text-destructive hover:bg-destructive/10 hover:text-destructive"
        disabled={busy}
        onClick={() => setConfirming(true)}
        data-testid="chat-group-end"
      >
        <XCircle />
        {t('chat.chatGroup.end')}
      </Button>
      <ConfirmDestructive
        open={confirming}
        onOpenChange={setConfirming}
        title={t('chat.chatGroup.endTitle')}
        description={t('chat.chatGroup.endBody')}
        warning={t('chat.chatGroup.endWarning')}
        submit={t('chat.chatGroup.end')}
        errorFallback={t('chat.chatGroup.actionFailed')}
        onConfirm={() => {
          setConfirming(false)
          void run(onEnd, t('chat.chatGroup.ended'))
        }}
      />
    </>
  )
}

/** Banning a member: their pseudonym and account, and by default a new link. */
export function BanDialog({
  name,
  linkOn,
  listFull,
  busy,
  onOpenChange,
  onBan,
}: {
  name: string | null
  linkOn: boolean
  listFull: boolean
  busy: boolean
  onOpenChange: (open: boolean) => void
  onBan: (resetLink: boolean) => void
}) {
  const { t } = useTranslation()
  const [resetLink, setResetLink] = useState(true)
  useEffect(() => {
    if (name !== null) setResetLink(true)
  }, [name])
  return (
    <Dialog open={name !== null} onOpenChange={(next) => !busy && onOpenChange(next)}>
      <DialogContent className="sm:max-w-md" data-testid="chat-group-ban-dialog">
        <DialogHeader>
          <DialogTitle>{t('chat.chatGroup.banTitle', { name: name ?? '' })}</DialogTitle>
          <DialogDescription>{t('chat.chatGroup.banBody')}</DialogDescription>
        </DialogHeader>
        {listFull ? (
          <p className="rounded-md bg-status-warn/10 px-3 py-2 text-sm text-status-warn" role="status">{t('chat.chatGroup.banListFull')}</p>
        ) : null}
        {linkOn ? (
          <div className="flex items-start gap-3">
            <Checkbox id="chat-group-ban-reset" checked={resetLink} onCheckedChange={(on) => setResetLink(on === true)} data-testid="chat-group-ban-reset" />
            <label htmlFor="chat-group-ban-reset" className="text-sm">
              {t('chat.chatGroup.banResetLink')}
            </label>
          </div>
        ) : null}
        <DialogFooter>
          <Button type="button" variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button variant="destructive" disabled={busy} onClick={() => onBan(linkOn && resetLink)} data-testid="chat-group-ban-confirm">
            {t('chat.chatGroup.ban')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
