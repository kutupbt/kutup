import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CalendarDays } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { loadCalendars, type Calendar } from '@kutup/calendar-core/api'
import { defaultCalendar, invitationLimits, loadInviteSettings, sendLanguage } from '@kutup/calendar-core/invitations'
import {
  addParticipant,
  addPublished,
  answerInvitation,
  applyOnView,
  calendarParts,
  readPart,
  widgetState,
  type CarryingMessage,
  type WidgetState,
} from '@kutup/calendar-core/invitationWidget'
import type { Partstat } from '@kutup/crypto/calendar'
import type { Invitation } from '@kutup/crypto/calendarIcs'
import { usePinnedKeys, type MailAccount, type MailMessage } from '@kutup/mail-core/api'
import type { ParsedMessage } from '@kutup/mail-core/mime'
import { appUrl } from '@kutup/session/apps'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Input } from '@kutup/ui/components/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'

/**
 * Proton's `ExtraEvents` (docs/plans/calendar-e4.md §5): one widget per
 * calendar part of a received message, above its body. The calendar
 * runtimes load only here, for a message that has one (Q-4).
 */
export function InvitationWidgets({ account, message, parsed }: { account: MailAccount; message: MailMessage; parsed: ParsedMessage }) {
  const limits = useQuery({ queryKey: ['calendar', 'invitation-limits'], queryFn: invitationLimits, staleTime: Infinity })
  const parts = limits.data ? calendarParts(parsed.attachments, limits.data.invitationIcsMaxBytes) : []
  if (message.direction !== 'inbound' || message.folder === 'drafts' || message.folder === 'spam' || parts.length === 0) return null
  // The sender a reply must come from: the address the message was
  // delivered from, and the one it says inside, when they are the same.
  const sender = message.from?.address && parsed.from?.address && message.from.address.toLowerCase() === parsed.from.address.toLowerCase() ? parsed.from.address : null
  const carrying: CarryingMessage = {
    from: sender,
    date: parsed.date ? parsed.date.toISOString() : message.receivedAt,
    subject: parsed.subject || message.subject,
    messageId: parsed.messageId,
  }
  return (
    <div className="space-y-2">
      {parts.map((text, index) => (
        <InvitationWidget key={index} account={account} text={text} message={carrying} messageId={message.id} />
      ))}
    </div>
  )
}

function when(invitation: Invitation, lng: string): string {
  const start = invitation.fields.start
  if ('date' in start) return new Intl.DateTimeFormat(lng, { dateStyle: 'full', timeZone: 'UTC' }).format(new Date(`${start.date}T00:00:00Z`))
  if ('utc' in start) return new Intl.DateTimeFormat(lng, { dateStyle: 'full', timeStyle: 'short' }).format(new Date(start.utc))
  const shown = new Intl.DateTimeFormat(lng, { dateStyle: 'full', timeStyle: 'short', timeZone: 'UTC' }).format(new Date(`${start.zoned.local}Z`))
  return `${shown} (${start.zoned.tzid.replaceAll('_', ' ')})`
}

function InvitationWidget({ account, text, message, messageId }: { account: MailAccount; text: string; message: CarryingMessage; messageId: string }) {
  const { t, i18n } = useTranslation()
  const session = useRequiredSession()
  const pinned = usePinnedKeys()
  const queryClient = useQueryClient()
  const [note, setNote] = useState('')
  const [calendarId, setCalendarId] = useState<string | null>(null)
  const calendars = useQuery({
    queryKey: ['mail', 'invitation-calendars', session.sessionId],
    queryFn: () => loadCalendars(session, account),
    structuralSharing: false,
    staleTime: 60_000,
  })
  const settings = useQuery({ queryKey: ['calendar', 'invite-settings'], queryFn: loadInviteSettings, staleTime: 60_000 })
  const key = ['mail', 'invitation', messageId, text.length, text.slice(0, 64)]
  const state = useQuery({
    queryKey: key,
    enabled: !!calendars.data && !!settings.data,
    structuralSharing: false,
    queryFn: async (): Promise<WidgetState> => {
      const outcome = await readPart(text, message)
      const list = calendars.data!.calendars
      const first = await widgetState({ account, calendars: list, outcome, message })
      // What Proton's widget does on its own: an update or cancellation
      // applied, an outside reply written, a new one added as pending.
      const changed = await applyOnView({ session, account, calendars: list, state: first, autoAdd: settings.data!.autoAdd }).catch(() => false)
      return changed ? widgetState({ account, calendars: list, outcome, message }) : first
    },
  })
  const lng = sendLanguage(settings.data, i18n.language)
  const owned: Calendar[] = (calendars.data?.calendars ?? []).filter((c) => c.owned)
  const answer = useMutation({
    mutationFn: async (partstat: Exclude<Partstat, 'needs-action'>) => {
      const current = state.data
      if (current?.kind !== 'attendee') throw new Error('not an invitation')
      const target = owned.find((c) => c.id === calendarId) ?? defaultCalendar(owned)
      return answerInvitation({ session, account, pinned: pinned ?? (() => undefined), calendars: owned, calendar: target, state: current, partstat, note: note.trim() || null, lng, message })
    },
    onSuccess: async (failures) => {
      if (failures.length) toast.error(t('invitation.widget.sendFailed'))
      else toast.success(t('invitation.widget.sent'))
      await queryClient.invalidateQueries({ queryKey: key })
    },
  })
  const add = useMutation({
    mutationFn: async () => {
      const current = state.data
      if (current?.kind !== 'publish') return
      const target = owned.find((c) => c.id === calendarId) ?? defaultCalendar(owned)
      if (!target) throw new Error('no calendar')
      await addPublished(session, account, target, current.invitation)
    },
    onSuccess: async () => {
      toast.success(t('invitation.widget.added'))
      await queryClient.invalidateQueries({ queryKey: key })
    },
  })
  const invite = useMutation({
    mutationFn: async () => {
      const current = state.data
      if (current?.kind !== 'organizer') return []
      return addParticipant({ session, account, pinned: pinned ?? (() => undefined), state: current, lng })
    },
    onSuccess: async () => {
      toast.success(t('invitation.widget.participantAdded'))
      await queryClient.invalidateQueries({ queryKey: key })
    },
  })

  const frame = (children: React.ReactNode) => (
    <section className="space-y-2 rounded-lg border border-border bg-muted/30 p-3 text-sm" data-testid="invitation-widget" aria-label={t('invitation.widget.title')}>
      {children}
    </section>
  )
  if (state.isPending || calendars.isPending) return frame(<p className="text-muted-foreground">{t('invitation.widget.loading')}</p>)
  if (state.isError || calendars.isError || !state.data) {
    return frame(
      <div className="flex items-center gap-2">
        <Alert variant="error" className="flex-1">
          {t('invitation.widget.error.fetching')}
        </Alert>
        <Button size="sm" variant="outline" onClick={() => void state.refetch()}>
          {t('invitation.widget.tryAgain')}
        </Button>
      </div>,
    )
  }
  const s = state.data
  if (s.kind === 'error') return frame(<Alert variant="error" data-testid="invitation-error">{t(s.key)}</Alert>)
  if (s.kind === 'unsupported') return frame(<p data-testid="invitation-unsupported">{t('invitation.widget.unsupported')}</p>)

  const invitation = s.invitation
  const header = (
    <div className="flex gap-2">
      <CalendarDays className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
      <div className="min-w-0 space-y-0.5">
        <p className="font-medium" data-testid="invitation-title">
          {invitation.fields.summary || t('invitation.body.untitled')}
        </p>
        <p className="text-muted-foreground" data-testid="invitation-when">
          {when(invitation, i18n.language)}
        </p>
        {invitation.fields.location ? <p className="text-muted-foreground">{invitation.fields.location}</p> : null}
        {invitation.organizer ? (
          <p className="text-xs text-muted-foreground">
            {t('invitation.widget.organizer')}: {invitation.organizer.name || invitation.organizer.email}
          </p>
        ) : null}
      </div>
    </div>
  )
  const calendarChoice =
    owned.length > 1 ? (
      <div className="flex items-center gap-2 text-xs">
        {t('invitation.widget.calendar')}
        <Select value={calendarId ?? defaultCalendar(owned)?.id ?? ''} onValueChange={setCalendarId}>
          <SelectTrigger className="h-7 w-48 text-xs" data-testid="invitation-calendar">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {owned.map((c) => (
              <SelectItem key={c.id} value={c.id}>
                {c.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
    ) : null
  const openLink = (
    <a className="text-xs underline" href={appUrl('calendar', `/?date=${'date' in invitation.fields.start ? invitation.fields.start.date : ('utc' in invitation.fields.start ? invitation.fields.start.utc : invitation.fields.start.zoned.local).slice(0, 10)}`)} target="_blank" rel="noreferrer" data-testid="invitation-open">
      {t('invitation.widget.open')}
    </a>
  )

  if (s.kind === 'publish') {
    return frame(
      <>
        {header}
        <p className="text-muted-foreground">{t('invitation.widget.publish')}</p>
        {s.stored ? (
          <p data-testid="invitation-added">{t('invitation.widget.added')}</p>
        ) : owned.length === 0 ? (
          <p>{t('invitation.widget.noCalendar')}</p>
        ) : (
          <div className="flex flex-wrap items-center gap-2">
            {calendarChoice}
            <Button size="sm" loading={add.isPending} onClick={() => add.mutate()} data-testid="invitation-add">
              {t('invitation.widget.addToCalendar')}
            </Button>
          </div>
        )}
        {add.error ? <p className="text-xs text-destructive">{apiErrorMessage(add.error, t('invitation.widget.error.unexpected'))}</p> : null}
      </>,
    )
  }

  if (s.kind === 'organizer') {
    const name = s.attendee.name || s.attendee.email
    const replied =
      s.attendee.partstat === 'accepted'
        ? t('invitation.widget.repliedAccepted', { name })
        : s.attendee.partstat === 'tentative'
          ? t('invitation.widget.repliedTentative', { name })
          : s.attendee.partstat === 'declined'
            ? t('invitation.widget.repliedDeclined', { name })
            : null
    const status: Record<typeof s.status, string | null> = {
      applied: replied,
      kutupReply: replied,
      outdated: t('invitation.widget.replyOutdated'),
      noEvent: t('invitation.widget.replyNoEvent'),
      partyCrasher: t('invitation.widget.partyCrasherOrganizer', { email: s.attendee.email }),
      notFromAttendee: t('invitation.widget.replyNotFromAttendee'),
      occurrence: `${t('invitation.widget.repliedOccurrence', { name })} ${t('invitation.widget.occurrenceNotApplied')}`,
      counter: t('invitation.widget.counter', { name }),
    }
    return frame(
      <>
        {header}
        <p data-testid="invitation-reply" data-status={s.status}>
          {status[s.status]}
        </p>
        {s.invitation.note ? <p className="whitespace-pre-wrap text-muted-foreground">{s.invitation.note}</p> : null}
        {s.status === 'partyCrasher' ? (
          <Button size="sm" variant="outline" loading={invite.isPending} onClick={() => invite.mutate()} data-testid="invitation-add-participant">
            {t('invitation.widget.addParticipant')}
          </Button>
        ) : null}
        {s.stored ? openLink : null}
      </>,
    )
  }

  // The attendee's side.
  const statusText =
    s.status === 'cancelled'
      ? invitation.fields.recurrenceId
        ? t('invitation.widget.cancelledOccurrence')
        : t('invitation.widget.cancelled')
      : s.status === 'outdated'
        ? t('invitation.widget.outdated')
        : s.status === 'updated'
          ? t('invitation.widget.updated')
          : s.answer && s.answer !== 'needs-action'
            ? t(`invitation.widget.answered.${s.answer}`)
            : t('invitation.widget.new')
  // A Kutup invitation (or anyone's) to an address this account doesn't
  // hold: Proton lets outside ones be answered, Kutup ones not.
  const crasher = !s.me
  // A party crasher doesn't answer here (Proton lets an outside one add themselves; not yet).
  const canAnswer = s.status !== 'cancelled' && s.status !== 'outdated' && !crasher
  return frame(
    <>
      {header}
      <p data-testid="invitation-status" data-status={s.status} data-answer={s.answer ?? ''}>
        {statusText}
      </p>
      {s.timing !== 'upcoming' ? <p className="text-xs text-muted-foreground">{s.timing === 'ended' ? t('invitation.widget.ended') : t('invitation.widget.inProgress')}</p> : null}
      {crasher ? <Alert variant="warn">{s.kutup ? t('invitation.widget.partyCrasherKutup') : t('invitation.widget.partyCrasher')}</Alert> : null}
      {canAnswer ? (
        owned.length === 0 ? (
          <p>{t('invitation.widget.noCalendar')}</p>
        ) : (
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-medium">{s.answer ? t('invitation.widget.change') : t('invitation.widget.attending')}</span>
              {(['accepted', 'tentative', 'declined'] as const).map((partstat) => (
                <Button
                  key={partstat}
                  size="sm"
                  variant={s.answer === partstat ? 'default' : 'outline'}
                  loading={answer.isPending && answer.variables === partstat}
                  onClick={() => answer.mutate(partstat)}
                  data-testid={`invitation-rsvp-${partstat}`}
                >
                  {t(`invitation.widget.${partstat === 'accepted' ? 'yes' : partstat === 'tentative' ? 'maybe' : 'no'}`)}
                </Button>
              ))}
            </div>
            {!s.stored && !s.kutup?.row.copies.length ? calendarChoice : null}
            <Input value={note} onChange={(e) => setNote(e.target.value)} maxLength={500} placeholder={t('invitation.widget.note')} className="h-8 text-xs" data-testid="invitation-note" />
          </div>
        )
      ) : null}
      {answer.error ? (
        <p className="text-xs text-destructive" role="alert">
          {apiErrorMessage(answer.error, t('invitation.widget.sendFailed'))}
        </p>
      ) : null}
      {s.stored || s.kutup?.row.copies.length ? openLink : null}
    </>,
  )
}
