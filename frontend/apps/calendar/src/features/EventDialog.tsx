import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { EventRefusedError, PERMISSION, loadSeries, saveEvent, useCalendarMutation, useCalendars, type Reminder } from '@kutup/calendar-core/api'
import { occurrences, timeZones } from '@kutup/crypto/calendar'
import { useMailAccount } from '@kutup/mail-core/api'
import { loadServerSettings } from '@kutup/session/apps'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Input } from '@kutup/ui/components/input'
import { Label } from '@kutup/ui/components/label'
import { Textarea } from '@kutup/ui/components/textarea'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { notificationStatus, requestNotifications } from '@kutup/ui/lib/desktopNotifications'
import { cn } from '@kutup/ui/lib/cn'
import { Choice } from './Choice'
import { zoneOptions } from './format'
import { openEditor, useEditorTarget } from './editorState'
import { isRecurring, requestDelete, useDeleteRequest } from './deleteState'
import { draftOf, endsAfterStart, fieldsOf, formOf, remindersOf, startOf, type Draft } from './eventDraft'
import { useCalendarPrefs } from './prefs'
import { refreshPush } from './reminders/push'
import { ReminderList } from './reminders/ReminderList'
import { hasRepeats } from './reminders/triggers'
import { choicesFor, planSave, saveWarnings, seriesContext, type FormValues, type RecurringType, type SaveWarnings, type SeriesContext } from './recurrence/actions'
import { DEFAULT_MAX_COUNT, followStart, modelOf, onceModel } from './recurrence/frequency'
import { RecurringDialog } from './recurrence/RecurringDialog'
import { RepeatField } from './recurrence/RepeatField'
import { planOf, runPlan, type Plan } from './recurrence/run'

/** Kutup-crypto's limits (`calendar_event`), as Proton's. */
const MAX_TITLE = 255
const MAX_LOCATION = 255
const MAX_DESCRIPTION = 3000
/** Proton's reminders per event (`MAX_NOTIFICATIONS`); the server holds its own limit (`calendarRemindersPerEvent`). */
const MAX_REMINDERS = 10


/** A recurring change waiting for its choice. */
interface Pending {
  types: RecurringType[]
  context: SeriesContext
  form: FormValues
  reminders?: Reminder[] | null
}

/** Creates an event (maybe a duplicate), or changes or deletes one. */
export function EventDialog() {
  const { t } = useTranslation()
  const target = useEditorTarget()
  const prefs = useCalendarPrefs()
  const session = useRequiredSession()
  const account = useMailAccount()
  const calendars = useCalendars()
  const queryClient = useQueryClient()
  const writable = useMemo(
    () => (calendars.data?.calendars ?? []).filter((calendar) => (calendar.permissions & PERMISSION.write) !== 0),
    [calendars.data],
  )
  const zones = useQuery({ queryKey: ['calendar', 'zones'], queryFn: timeZones, staleTime: Infinity })
  // The server's largest COUNT (`calendarMaxCount`, Proton's 49).
  const maxCount = useQuery({
    queryKey: ['calendar', 'server-settings'],
    queryFn: () => loadServerSettings<{ calendar?: { maxCount?: number } }>(),
    staleTime: Infinity,
  }).data?.calendar?.maxCount ?? DEFAULT_MAX_COUNT
  const [draft, setDraft] = useState<Draft | null>(null)
  const [pending, setPending] = useState<Pending | null>(null)
  const [warnings, setWarnings] = useState<SaveWarnings | null>(null)
  // A planned series change, kept so Save again sends only what hasn't landed.
  const plan = useRef<{ type: RecurringType; plan: Plan } | null>(null)
  const existing = target?.kind === 'edit' ? target.event : undefined
  const recurring = isRecurring(existing)
  // A duplicate keeps its source's repeat (Proton's), not a changed occurrence's.
  const duplicated = target?.kind === 'duplicate' ? target.event : undefined
  const duplicateRule = duplicated && !duplicated.fields.recurrenceId ? duplicated.fields.rrule : null
  const deleting = useDeleteRequest()
  const existingCalendar = writable.find((c) => c.id === existing?.calendarId)
  // A changed occurrence's series, for the rule it shows (Proton's: a single edit shows its series' repeat).
  const series = useQuery({
    queryKey: ['calendar', 'series', existing?.calendarId, existing?.fields.uid],
    enabled: !!existing?.fields.recurrenceId && !!account.data && !!existingCalendar,
    queryFn: () => loadSeries(account.data!, existingCalendar!, existing!.fields.uid),
  })
  const seriesRule = existing?.fields.recurrenceId
    ? (series.data?.find((event) => !event.fields.recurrenceId && event.fields.rrule)?.fields.rrule ?? null)
    : (existing?.fields.rrule ?? duplicateRule)

  useEffect(() => {
    if (!target) return
    const base = draftOf(target, prefs.zone, writable[0]?.id ?? '')
    const calendar = writable.find((c) => c.id === base.calendarId)
    const source = target.kind === 'new' ? undefined : target.event
    // A duplicate into another calendar takes that one's defaults.
    const own = source && source.calendarId === base.calendarId ? source.reminders : null
    const repeats = target.kind === 'edit' ? isRecurring(source) : target.kind === 'duplicate' && !!source?.fields.rrule && !source.fields.recurrenceId
    setDraft({ ...base, reminders: remindersOf(calendar, own, base.allDay), frequency: repeats ? null : onceModel(base.startDate) })
    setPending(null)
    plan.current = null
    save.reset()
    // eslint-disable-next-line react-hooks/exhaustive-deps -- once per opening
  }, [target])
  // The stored rule read into the repeat choice, at the start the form shows.
  useEffect(() => {
    if (!target || !(recurring || duplicateRule) || !draft || draft.frequency) return
    if (existing?.fields.recurrenceId && !series.data) return
    let cancelled = false
    void modelOf(seriesRule, startOf(draft), draft.startDate).then((frequency) => {
      if (!cancelled) setDraft((d) => (d && !d.frequency ? { ...d, frequency } : d))
    })
    return () => {
      cancelled = true
    }
  }, [target, recurring, duplicateRule, draft, existing, series.data, seriesRule])

  /** This member's reminders as the save sends them: own when edited, back to the defaults when they were own, else as they are. */
  const remindersFor = (next: Draft) => (next.reminders.custom ? (next.allDay ? next.reminders.allDay : next.reminders.timed) : existing?.reminders ? null : undefined)

  const save = useCalendarMutation(async (next: Draft): Promise<'created' | 'createdMany' | 'saved' | 'asked'> => {
    const calendar = writable.find((c) => c.id === next.calendarId)
    if (!account.data || !calendar) throw new Error('no calendar')
    const form = await formOf(next, prefs.weekStart, seriesRule).catch(() => {
      throw new RuleRefused()
    })
    const reminders = remindersFor(next)
    if (existing && recurring) {
      // Proton's: every event of the series read first, then the choice.
      const context = await seriesContext(await loadSeries(account.data, calendar, existing.fields.uid), existing, target?.kind === 'edit' ? target.instance : null)
      if (context) {
        const types = await choicesFor(context)
        setPending({ types, context, form, reminders })
        return 'asked'
      }
    }
    const fields = fieldsOf(form, account.data.serverDomain, existing)
    await saveEvent(session, account.data, calendar, fields, existing, reminders)
    if (existing) return 'saved'
    // Proton's "Events created" for a series of more than one.
    const many = fields.rrule ? (await occurrences(fields, '1970-01-01T00:00:00Z', '2038-01-01T00:00:00Z', 2).catch(() => [])).length > 1 : false
    return many ? 'createdMany' : 'created'
  })
  const recurringRun = useCalendarMutation(async (type: RecurringType) => {
    const calendar = writable.find((c) => c.id === existing?.calendarId)
    if (!account.data || !calendar || !pending) throw new Error('no calendar')
    if (!plan.current || plan.current.type !== type) {
      const steps = await planSave(type, pending.context, pending.form, pending.reminders)
      plan.current = { type, plan: planOf(steps) }
    }
    await runPlan(plan.current.plan, session, account.data, calendar)
    return type
  })

  const close = () => openEditor(null)
  const set = (change: Partial<Draft>) =>
    setDraft((d) => {
      if (!d) return d
      const next = { ...d, ...change }
      // Another calendar's defaults, until the person sets the event's own.
      if (change.calendarId !== undefined && !d.reminders.custom) next.reminders = remindersOf(writable.find((c) => c.id === change.calendarId), null, next.allDay)
      // The repeat follows the start (Proton's `getFrequencyModelChange`).
      if (change.startDate !== undefined && d.frequency) next.frequency = followStart(d.frequency, d.startDate, change.startDate)
      return next
    })
  const shownReminders = draft ? (draft.allDay ? draft.reminders.allDay : draft.reminders.timed) : []
  const repeated = hasRepeats(shownReminders)
  const valid = draft !== null && draft.calendarId !== '' && endsAfterStart(draft) && !repeated && draft.frequency !== null
  const errorText = (error: unknown, fallback: string) =>
    error instanceof RuleRefused
      ? t('recurrence.invalid')
      : error instanceof EventRefusedError
        ? t(
            error.code === 'eventLimit'
              ? 'events.limit'
              : error.code === 'revisionConflict'
                ? 'events.changedElsewhere'
                : error.code === 'countTooLarge'
                  ? 'recurrence.countTooLarge'
                  : 'events.refused',
          )
        : error
          ? apiErrorMessage(error, fallback)
          : null
  const saveError = errorText(save.error, t('events.saveFailed'))
  const doneText: Record<RecurringType, string> = { single: t('events.saved'), future: t('recurrence.futureUpdated'), all: t('recurrence.allUpdated') }

  return (
    <>
      <Dialog open={target !== null && draft !== null} onOpenChange={(open) => !open && close()}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>{existing ? t('events.editTitle') : t('events.newTitle')}</DialogTitle>
          </DialogHeader>
          {draft ? (
            <form
              className="mt-2 space-y-4"
              noValidate
              onSubmit={(e) => {
                e.preventDefault()
                if (!valid) return
                // Proton asks for the browser's permission with the first device
                // reminder: here, in the click itself (a browser asks only then).
                const applied = draft.allDay ? draft.reminders.allDay : draft.reminders.timed
                if (applied.some((r) => r.type === 'device') && notificationStatus() === 'default') void requestNotifications().then(refreshPush)
                save.mutate(draft, {
                  onSuccess: (result) => {
                    if (result === 'asked') return
                    toast.success(result === 'saved' ? t('events.saved') : result === 'createdMany' ? t('recurrence.created') : t('events.created'))
                    close()
                  },
                })
              }}
            >
              {existing && !existing.verified ? <Alert variant="warn">{t('events.unverified')}</Alert> : null}
              <div className="space-y-1.5">
                <Label htmlFor="event-title">{t('events.title')}</Label>
                <Input
                  id="event-title"
                  value={draft.title}
                  onChange={(e) => set({ title: e.target.value })}
                  maxLength={MAX_TITLE}
                  placeholder={t('events.untitled')}
                  autoFocus
                  data-testid="event-title"
                />
              </div>
              <div className="flex items-center gap-2">
                <Checkbox id="event-all-day" checked={draft.allDay} onCheckedChange={(v) => set({ allDay: v === true })} data-testid="event-all-day" />
                <Label htmlFor="event-all-day">{t('events.allDay')}</Label>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <Label htmlFor="event-start-date">{t('events.start')}</Label>
                  <Input id="event-start-date" type="date" value={draft.startDate} onChange={(e) => e.target.value && set({ startDate: e.target.value })} data-testid="event-start-date" />
                </div>
                <div className={cn('space-y-1.5', draft.allDay && 'invisible')}>
                  <Label htmlFor="event-start-time">{t('events.startTime')}</Label>
                  <Input id="event-start-time" type="time" value={draft.startTime} onChange={(e) => e.target.value && set({ startTime: e.target.value })} data-testid="event-start-time" />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="event-end-date">{t('events.end')}</Label>
                  <Input id="event-end-date" type="date" value={draft.endDate} onChange={(e) => e.target.value && set({ endDate: e.target.value })} data-testid="event-end-date" />
                </div>
                <div className={cn('space-y-1.5', draft.allDay && 'invisible')}>
                  <Label htmlFor="event-end-time">{t('events.endTime')}</Label>
                  <Input id="event-end-time" type="time" value={draft.endTime} onChange={(e) => e.target.value && set({ endTime: e.target.value })} data-testid="event-end-time" />
                </div>
              </div>
              {!endsAfterStart(draft) ? (
                <p className="text-xs text-destructive" role="alert">
                  {t('events.endBeforeStart')}
                </p>
              ) : null}
              {!draft.allDay ? (
                <div className="space-y-1.5">
                  <Label htmlFor="event-zone">{t('events.timeZone')}</Label>
                  <Choice
                    id="event-zone"
                    value={draft.tzid}
                    options={zoneOptions(zones.data, draft.tzid)}
                    onChange={(tzid) => set({ tzid })}
                    testId="event-zone"
                  />
                </div>
              ) : null}
              <div className="space-y-1.5">
                <Label htmlFor="event-repeat">{t('recurrence.field')}</Label>
                {draft.frequency ? (
                  <RepeatField
                    model={draft.frequency}
                    start={draft.startDate}
                    weekStart={prefs.weekStart}
                    maxCount={maxCount}
                    onChange={(frequency) => set({ frequency })}
                  />
                ) : (
                  <p className="text-sm text-muted-foreground">{t('common.loading')}</p>
                )}
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="event-calendar">{t('events.calendar')}</Label>
                <Choice
                  id="event-calendar"
                  value={draft.calendarId}
                  options={writable.map((calendar) => ({ value: calendar.id, label: calendar.name }))}
                  disabled={existing !== undefined}
                  onChange={(calendarId) => set({ calendarId })}
                />
              </div>
              <div className="space-y-1.5">
                <Label>{t('reminders.field')}</Label>
                <ReminderList
                  id="event"
                  allDay={draft.allDay}
                  reminders={shownReminders}
                  max={MAX_REMINDERS}
                  onChange={(list) => set({ reminders: { ...draft.reminders, custom: true, [draft.allDay ? 'allDay' : 'timed']: list } })}
                />
                {repeated ? (
                  <p className="text-xs text-destructive" role="alert">
                    {t('reminders.picker.repeats')}
                  </p>
                ) : null}
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="event-location">{t('events.location')}</Label>
                <Input id="event-location" value={draft.location} onChange={(e) => set({ location: e.target.value })} maxLength={MAX_LOCATION} />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="event-description">{t('events.description')}</Label>
                <Textarea id="event-description" value={draft.description} onChange={(e) => set({ description: e.target.value })} maxLength={MAX_DESCRIPTION} rows={3} />
              </div>
              {saveError ? <Alert variant="error">{saveError}</Alert> : null}
              <DialogFooter className="sm:justify-between">
                {existing ? (
                  <Button
                    type="button"
                    variant="ghost"
                    loading={deleting?.event === existing}
                    onClick={() => requestDelete(existing, target?.kind === 'edit' ? target.instance : null, close)}
                    data-testid="event-delete"
                  >
                    {t('events.delete')}
                  </Button>
                ) : (
                  <span />
                )}
                <div className="flex gap-2">
                  <Button type="button" variant="ghost" onClick={close}>
                    {t('common.cancel')}
                  </Button>
                  <Button type="submit" loading={save.isPending} disabled={!valid} data-testid="event-save">
                    {t('common.save')}
                  </Button>
                </div>
              </DialogFooter>
            </form>
          ) : null}
        </DialogContent>
      </Dialog>
      <RecurringDialog
        mode="save"
        types={pending?.types ?? null}
        warnings={warnings}
        pending={recurringRun.isPending}
        error={errorText(recurringRun.error, t('events.saveFailed'))}
        onWarnings={(type) => {
          setWarnings(null)
          if (pending) void saveWarnings(type, pending.context, pending.form).then(setWarnings)
        }}
        onConfirm={(type) =>
          recurringRun.mutate(type, {
            onSuccess: (done) => {
              setPending(null)
              plan.current = null
              void queryClient.invalidateQueries({ queryKey: ['calendar'] })
              toast.success(doneText[done])
              close()
            },
          })
        }
        onClose={() => {
          setPending(null)
          plan.current = null
          recurringRun.reset()
        }}
      />
    </>
  )
}

/** The repeat choice doesn't make a rule the Rust core takes for this start. */
class RuleRefused extends Error {
  constructor() {
    super('the repeat rule is refused for this start')
    this.name = 'RuleRefused'
  }
}
