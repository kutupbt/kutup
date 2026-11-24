import { useQuery } from '@tanstack/react-query'
import { AlignLeft, Bell, CalendarDays, Copy, MapPin, Pencil, Trash2, UserRound, X } from 'lucide-react'
import { useMemo, useRef, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { EventRefusedError, PERMISSION, saveEvent, useCalendarMutation, useCalendars, type Calendar } from '@kutup/calendar-core/api'
import { addDays } from '@kutup/calendar-core/time'
import { useMailAccount } from '@kutup/mail-core/api'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Input } from '@kutup/ui/components/input'
import { Label } from '@kutup/ui/components/label'
import { Popover, PopoverAnchor, PopoverContent } from '@kutup/ui/components/popover'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { notificationStatus, requestNotifications } from '@kutup/ui/lib/desktopNotifications'
import { Choice } from './Choice'
import { openEditor } from './editorState'
import { requestDelete, useDeleteRequest } from './deleteState'
import { EventChip } from './EventChip'
import { draftOf, fieldsOf, formOf, remindersOf, type Draft } from './eventDraft'
import { formatLongDate, formatTime } from './format'
import { localAt } from './gridInteraction'
import { Linkified } from './linkify'
import { covers, eventZone, type Placed } from './placement'
import { closePopover, currentPopover, handOver, openPopover, usePopover, type NewTarget, type OpenPopover } from './popoverState'
import { useCalendarPrefs } from './prefs'
import { dayOf } from './recurrence/actions'
import { modelOf, onceModel } from './recurrence/frequency'
import { ruleText } from './recurrence/frequencyText'
import { refreshPush } from './reminders/push'
import { reminderText } from './reminders/reminderText'

/** Kutup-crypto's title limit (`calendar_event`), as the editor's. */
const MAX_TITLE = 255

function writableOf(calendars: Calendar[] | undefined): Calendar[] {
  return (calendars ?? []).filter((calendar) => (calendar.permissions & PERMISSION.write) !== 0)
}

/** "Tuesday, 24 November 2026, 09:00 – 10:00", or the days of an all-day event (Proton's `CalendarEventDateHeader`). */
function whenText(placed: Pick<Placed, 'allDay' | 'start' | 'end' | 'firstDay' | 'afterLastDay'>, locale: string, hour12: boolean | null): string {
  if (placed.allDay) {
    const last = addDays(placed.afterLastDay, -1)
    return last === placed.firstDay ? formatLongDate(placed.firstDay, locale) : `${formatLongDate(placed.firstDay, locale)} – ${formatLongDate(last, locale)}`
  }
  const startDay = placed.start.slice(0, 10)
  const endsMidnight = placed.end === `${addDays(startDay, 1)}T00:00:00`
  if (placed.end.slice(0, 10) === startDay || endsMidnight) {
    return `${formatLongDate(startDay, locale)}, ${formatTime(placed.start, locale, hour12)} – ${formatTime(placed.end, locale, hour12)}`
  }
  return `${formatLongDate(startDay, locale)}, ${formatTime(placed.start, locale, hour12)} – ${formatLongDate(placed.end.slice(0, 10), locale)}, ${formatTime(placed.end, locale, hour12)}`
}

/** One labelled row of the event's details (Proton's `IconRow`). */
function Row({ icon, label, children, testId }: { icon: ReactNode; label: string; children: ReactNode; testId?: string }) {
  return (
    <div className="flex gap-3 text-sm">
      <span className="mt-0.5 shrink-0 text-muted-foreground" title={label}>
        {icon}
        <span className="sr-only">{label}</span>
      </span>
      <div className="min-w-0 flex-1 break-words" data-testid={testId}>
        {children}
      </div>
    </div>
  )
}

function IconAction({ label, onClick, children, testId, loading }: { label: string; onClick: () => void; children: ReactNode; testId: string; loading?: boolean }) {
  return (
    <Button type="button" variant="ghost" size="icon" className="size-8" aria-label={label} title={label} onClick={onClick} loading={loading} data-testid={testId}>
      {children}
    </Button>
  )
}

/** Proton's `EventPopover`: an event's details, with Edit, Duplicate and Delete. */
function EventPeek({ placed, calendars }: { placed: Placed; calendars: Calendar[] }) {
  const { t, i18n } = useTranslation()
  const prefs = useCalendarPrefs()
  const deleting = useDeleteRequest()
  const { event } = placed
  const fields = event.fields
  const calendar = calendars.find((c) => c.id === event.calendarId)
  const canWrite = !!calendar && (calendar.permissions & PERMISSION.write) !== 0
  const canDuplicate = writableOf(calendars).length > 0
  const title = fields.summary ?? t('events.untitled')
  const zone = placed.allDay ? null : eventZone(event)
  // The event's own clock when it keeps another zone than the view's.
  const own = placed.instance ?? { start: fields.start, end: fields.end }
  const ownLocal = (time: typeof fields.start | null) => (time && 'zoned' in time ? time.zoned.local : null)
  const ownStart = ownLocal(own.start)
  const ownEnd = ownLocal(own.end) ?? ownStart
  const repeat = useQuery({
    queryKey: ['calendar', 'popover-rule', event.id, fields.rrule, prefs.zone, prefs.weekStart, i18n.language],
    enabled: !!fields.rrule,
    queryFn: async () => {
      const model = await modelOf(fields.rrule, fields.start, dayOf(fields.start))
      return ruleText(t, { model, start: dayOf(fields.start), weekStart: prefs.weekStart, locale: i18n.language, zone, viewZone: prefs.zone })
    },
  })
  const reminders = event.reminders ?? (calendar ? (placed.allDay ? calendar.defaultReminders.allDay : calendar.defaultReminders.timed) : [])
  const organizer = fields.organizer?.replace(/^mailto:/i, '')

  return (
    <div className="space-y-3" data-testid="event-popover">
      <div className="-mr-2 -mt-2 flex items-center justify-end gap-0.5">
        {canWrite ? (
          <IconAction label={t('popover.edit')} testId="event-popover-edit" onClick={() => handOver(() => openEditor({ kind: 'edit', event, instance: placed.instance }))}>
            <Pencil />
          </IconAction>
        ) : null}
        {canDuplicate ? (
          <IconAction
            label={t('popover.duplicate')}
            testId="event-popover-duplicate"
            onClick={() => handOver(() => openEditor({ kind: 'duplicate', event, instance: placed.instance, writable: canWrite }))}
          >
            <Copy />
          </IconAction>
        ) : null}
        {canWrite ? (
          <IconAction label={t('events.delete')} testId="event-popover-delete" loading={deleting?.event === event} onClick={() => handOver(() => requestDelete(event, placed.instance))}>
            <Trash2 />
          </IconAction>
        ) : null}
        <IconAction label={t('popover.close')} testId="event-popover-close" onClick={() => closePopover(true)}>
          <X />
        </IconAction>
      </div>
      <div className="flex gap-3">
        <span className="mt-1 w-1 shrink-0 self-stretch rounded-full" style={{ background: placed.color }} aria-hidden />
        <div className="min-w-0 space-y-0.5">
          <h2 className="break-words font-display text-lg font-semibold leading-snug" data-testid="event-popover-title">
            {title}
          </h2>
          <p className="text-sm" data-testid="event-popover-when">
            {whenText(placed, i18n.language, prefs.hour12)}
          </p>
          {zone ? (
            <p className="text-xs text-muted-foreground" data-testid="event-popover-zone">
              {zone !== prefs.zone && ownStart && ownEnd
                ? t('popover.ownZone', {
                    start: formatTime(ownStart, i18n.language, prefs.hour12),
                    end: formatTime(ownEnd, i18n.language, prefs.hour12),
                    zone: zone.replaceAll('_', ' '),
                  })
                : prefs.zone.replaceAll('_', ' ')}
            </p>
          ) : null}
          {repeat.data ? (
            <p className="text-sm text-muted-foreground" data-testid="event-popover-repeat">
              {repeat.data}
            </p>
          ) : null}
        </div>
      </div>
      {!event.verified ? (
        <Alert variant="warn" className="text-xs">
          {t('events.unverified')}
        </Alert>
      ) : null}
      <div className="max-h-[50vh] space-y-2.5 overflow-y-auto">
        {fields.location ? (
          <Row icon={<MapPin className="size-4" />} label={t('events.location')} testId="event-popover-location">
            <Linkified text={fields.location} />
          </Row>
        ) : null}
        {organizer ? (
          <Row icon={<UserRound className="size-4" />} label={t('popover.participants')} testId="event-popover-organizer">
            {t('popover.organizer', { address: organizer })}
          </Row>
        ) : null}
        <Row icon={<CalendarDays className="size-4" />} label={t('events.calendar')} testId="event-popover-calendar">
          {calendar?.name ?? ''}
        </Row>
        {reminders.length ? (
          <Row icon={<Bell className="size-4" />} label={t('reminders.field')} testId="event-popover-reminders">
            <ul>
              {reminders.map((reminder, index) => (
                <li key={index}>{reminderText(t, reminder, placed.allDay, i18n.language, prefs.hour12)}</li>
              ))}
            </ul>
          </Row>
        ) : null}
        {fields.description ? (
          <Row icon={<AlignLeft className="size-4" />} label={t('events.description')} testId="event-popover-description">
            <div className="whitespace-pre-wrap">
              <Linkified text={fields.description} />
            </div>
          </Row>
        ) : null}
      </div>
    </div>
  )
}

/** The new event's span in words. */
function newWhen(target: NewTarget, locale: string, hour12: boolean | null): string {
  if (target.allDay) {
    const last = target.lastDate ?? target.date
    return last === target.date ? formatLongDate(target.date, locale) : `${formatLongDate(target.date, locale)} – ${formatLongDate(last, locale)}`
  }
  const start = localAt(target.date, target.minutes ?? 0)
  const endDay = target.endDate ?? target.date
  const end = localAt(endDay, target.endMinutes ?? 0)
  return whenText({ allDay: false, start, end, firstDay: target.date, afterLastDay: endDay }, locale, hour12)
}

/** Proton's `CreateEventPopover`: a title, Save, or "More options" for the whole editor. */
function QuickCreate({ target, calendars }: { target: NewTarget; calendars: Calendar[] }) {
  const { t, i18n } = useTranslation()
  const prefs = useCalendarPrefs()
  const session = useRequiredSession()
  const account = useMailAccount()
  const writable = useMemo(() => writableOf(calendars), [calendars])
  const [title, setTitle] = useState('')
  const [calendarId, setCalendarId] = useState(writable[0]?.id ?? '')
  const save = useCalendarMutation(async () => {
    const calendar = writable.find((c) => c.id === calendarId)
    if (!account.data || !calendar) throw new Error('no calendar')
    const base = draftOf({ ...target, title, calendarId }, prefs.zone, calendarId)
    // The calendar's default notifications (Proton's popover shows none and saves them).
    const draft: Draft = { ...base, reminders: remindersOf(calendar, null, base.allDay), frequency: onceModel(base.startDate) }
    const form = await formOf(draft, prefs.weekStart, null)
    await saveEvent(session, account.data, calendar, fieldsOf(form, account.data.serverDomain), undefined, undefined)
  })
  const calendar = writable.find((c) => c.id === calendarId)
  const defaults = calendar ? (target.allDay ? calendar.defaultReminders.allDay : calendar.defaultReminders.timed) : []
  const error = save.error
    ? save.error instanceof EventRefusedError
      ? t(save.error.code === 'eventLimit' ? 'events.limit' : 'events.refused')
      : apiErrorMessage(save.error, t('events.saveFailed'))
    : null
  return (
    <form
      className="space-y-3"
      data-testid="create-popover"
      noValidate
      onSubmit={(e) => {
        e.preventDefault()
        if (!calendar) return
        // As the editor: the browser's permission asked in the click that saves a device reminder.
        if (defaults.some((r) => r.type === 'device') && notificationStatus() === 'default') void requestNotifications().then(refreshPush)
        save.mutate(undefined, {
          onSuccess: () => {
            toast.success(t('events.created'))
            closePopover(true)
          },
        })
      }}
    >
      <div className="-mr-2 -mt-2 flex justify-end">
        <IconAction label={t('popover.close')} testId="create-popover-close" onClick={() => closePopover(true)}>
          <X />
        </IconAction>
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="create-popover-title">{t('events.title')}</Label>
        <Input
          id="create-popover-title"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          maxLength={MAX_TITLE}
          placeholder={t('popover.addTitle')}
          autoFocus
          data-testid="create-popover-title"
        />
      </div>
      <p className="text-sm text-muted-foreground" data-testid="create-popover-when">
        {newWhen(target, i18n.language, prefs.hour12)}
      </p>
      {writable.length > 1 ? (
        <div className="space-y-1.5">
          <Label htmlFor="create-popover-calendar">{t('events.calendar')}</Label>
          <Choice
            id="create-popover-calendar"
            value={calendarId}
            options={writable.map((c) => ({ value: c.id, label: c.name }))}
            onChange={setCalendarId}
            testId="create-popover-calendar"
          />
        </div>
      ) : null}
      {error ? <Alert variant="error">{error}</Alert> : null}
      <div className="flex justify-end gap-2">
        <Button
          type="button"
          variant="outline"
          disabled={save.isPending}
          onClick={() => handOver(() => openEditor({ ...target, title, calendarId }))}
          data-testid="create-popover-more"
        >
          {t('popover.moreOptions')}
        </Button>
        <Button type="submit" loading={save.isPending} disabled={!calendar} data-testid="create-popover-save">
          {t('common.save')}
        </Button>
      </div>
    </form>
  )
}

/** Proton's `MorePopoverEvent`: every event of a month's day. */
function DayEvents({ open, placed }: { open: OpenPopover & { kind: 'more' }; placed: Placed[] }) {
  const { t, i18n } = useTranslation()
  const here = placed
    .filter((p) => covers(p, open.day))
    .sort((a, b) => Number(b.allDay) - Number(a.allDay) || a.start.localeCompare(b.start))
  return (
    <div className="space-y-2" data-testid="more-popover">
      <div className="-mr-2 -mt-2 flex items-center gap-2">
        <h2 className="min-w-0 flex-1 truncate font-display text-base font-semibold">{formatLongDate(open.day, i18n.language)}</h2>
        <IconAction label={t('popover.close')} testId="more-popover-close" onClick={() => closePopover(true)}>
          <X />
        </IconAction>
      </div>
      <ul className="max-h-[50vh] space-y-0.5 overflow-y-auto">
        {here.map((p) => (
          <li key={p.key}>
            <EventChip placed={p} showTime onOpen={() => openPopover({ kind: 'event', placed: p }, open.anchor, open.returnFocus)} />
          </li>
        ))}
      </ul>
    </div>
  )
}

/** The calendar's popover, at what it points to; Escape closes it and focus goes back. */
export function CalendarPopovers({ placed }: { placed: Placed[] }) {
  const { t } = useTranslation()
  const open = usePopover()
  const calendars = useCalendars().data?.calendars ?? []
  const last = useRef<DOMRect | null>(null)
  // Measured on each move: a new event's draft on the grid, else what it opened at
  // (where it last was, should a refresh have replaced the element).
  const anchor = useRef({
    getBoundingClientRect: (): DOMRect => {
      const now = currentPopover()
      const draft = now?.kind === 'create' ? document.querySelector('[data-calendar-draft]') : null
      const element = draft ?? (now?.anchor.isConnected ? now.anchor : null)
      if (element) last.current = element.getBoundingClientRect()
      return last.current ?? new DOMRect()
    },
  })
  // The event shown, as the grid has it now (a sync may have changed or removed it).
  const shown = open?.kind === 'event' ? (placed.find((p) => p.key === open.placed.key) ?? open.placed) : null
  return (
    <Popover open={open !== null} onOpenChange={(isOpen) => !isOpen && closePopover(false)}>
      <PopoverAnchor virtualRef={anchor} />
      {open ? (
        <PopoverContent
          key={open.id}
          side="right"
          align="start"
          className="w-96"
          aria-label={open.kind === 'event' ? t('popover.eventLabel') : open.kind === 'create' ? t('popover.createLabel') : t('popover.dayLabel')}
          onEscapeKeyDown={(e) => {
            e.preventDefault()
            closePopover(true)
          }}
          // Focus goes back by `closePopover`, not by the panel (it has no trigger).
          onCloseAutoFocus={(e) => e.preventDefault()}
          // The press that opened it may focus what it opened from (a touch's late mouse events).
          onFocusOutside={(e) => {
            if (e.target === open.returnFocus) e.preventDefault()
          }}
        >
          {open.kind === 'event' && shown ? (
            <EventPeek placed={shown} calendars={calendars} />
          ) : open.kind === 'create' ? (
            <QuickCreate target={open.target} calendars={calendars} />
          ) : open.kind === 'more' ? (
            <DayEvents open={open} placed={placed} />
          ) : null}
        </PopoverContent>
      ) : null}
    </Popover>
  )
}
