import { Plus, X } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { Reminder } from '@kutup/calendar-core/api'
import { Button } from '@kutup/ui/components/button'
import { Input } from '@kutup/ui/components/input'
import { Choice } from '../Choice'
import { newRow, reminderOf, rowOf, UNIT_MAX, type ReminderRow, type ReminderUnit } from './triggers'

/** "HH:MM" from minutes after midnight, and back. */
const clock = (minutes: number) => `${String(Math.floor(minutes / 60)).padStart(2, '0')}:${String(minutes % 60).padStart(2, '0')}`
const minutesOfClock = (value: string) => {
  const [h, m] = value.split(':').map(Number)
  return (h ?? 0) * 60 + (m ?? 0)
}

/**
 * Proton's `Notifications`: one row per reminder (`NotificationInput`):
 * Notification or Email; for a timed event "at time of event" or a number of
 * minutes, hours, days or weeks before; for an all-day event "on the same
 * day" or a number of days or weeks before, at a time of day. "Add
 * notification" up to `max`.
 */
export function ReminderList({
  id,
  reminders,
  allDay,
  max,
  onChange,
}: {
  id: string
  reminders: Reminder[]
  allDay: boolean
  max: number
  onChange: (reminders: Reminder[]) => void
}) {
  const { t } = useTranslation()
  // A reminder this picker can't show (another client's) keeps its place, unchanged.
  const rows = reminders.map((reminder) => ({ reminder, row: rowOf(reminder, allDay) }))
  const set = (index: number, row: ReminderRow) => onChange(reminders.map((r, i) => (i === index ? reminderOf(row, allDay) : r)))
  const whenOptions = allDay
    ? [
        { value: 'same', label: t('reminders.picker.sameDay') },
        { value: 'day', label: t('reminders.picker.daysBefore') },
        { value: 'week', label: t('reminders.picker.weeksBefore') },
      ]
    : [
        { value: 'same', label: t('reminders.picker.atTime') },
        { value: 'minute', label: t('reminders.picker.minutesBefore') },
        { value: 'hour', label: t('reminders.picker.hoursBefore') },
        { value: 'day', label: t('reminders.picker.daysBefore') },
        { value: 'week', label: t('reminders.picker.weeksBefore') },
      ]
  return (
    <div className="space-y-2" data-testid={`${id}-reminders`}>
      {rows.map(({ reminder, row }, index) => {
        if (!row) {
          return (
            <div key={index} className="flex items-center gap-2 text-sm text-muted-foreground">
              <span className="flex-1">{t('reminders.picker.other', { trigger: reminder.trigger })}</span>
              <Button variant="ghost" size="icon" className="size-8" aria-label={t('reminders.picker.remove')} onClick={() => onChange(reminders.filter((_, i) => i !== index))}>
                <X className="size-4" />
              </Button>
            </div>
          )
        }
        const same = row.value === 0
        const when = same ? 'same' : row.unit
        return (
          <div key={index} className="flex flex-wrap items-center gap-2" data-testid="reminder-row">
            <div className="w-36">
              <Choice
                id={`${id}-type-${index}`}
                label={t('reminders.picker.type')}
                value={row.type}
                options={[
                  { value: 'device', label: t('reminders.picker.device') },
                  { value: 'email', label: t('reminders.picker.email') },
                ]}
                onChange={(type) => set(index, { ...row, type: type as Reminder['type'] })}
              />
            </div>
            {!same ? (
              <Input
                type="number"
                aria-label={t('reminders.picker.amount')}
                className="w-20"
                min={1}
                max={UNIT_MAX[row.unit]}
                value={row.value}
                // Proton's IntegerInput: whole numbers in the unit's bounds; empty or 0 is 1.
                onChange={(e) => set(index, { ...row, value: Math.min(Math.max(Math.trunc(Number(e.target.value)) || 1, 1), UNIT_MAX[row.unit]) })}
              />
            ) : null}
            <div className="w-48">
              <Choice
                id={`${id}-when-${index}`}
                label={t('reminders.picker.when')}
                value={when}
                options={whenOptions}
                onChange={(value) =>
                  set(
                    index,
                    value === 'same'
                      ? { ...row, value: 0, unit: allDay ? 'day' : 'minute' }
                      : { ...row, value: Math.min(Math.max(row.value, 1), UNIT_MAX[value as ReminderUnit]), unit: value as ReminderUnit },
                  )
                }
              />
            </div>
            {allDay ? (
              <>
                <span className="text-sm text-muted-foreground">{t('reminders.picker.at')}</span>
                <Input
                  type="time"
                  aria-label={t('reminders.picker.timeOfDay')}
                  className="w-28"
                  value={clock(row.at)}
                  onChange={(e) => e.target.value && set(index, { ...row, at: minutesOfClock(e.target.value) })}
                />
              </>
            ) : null}
            <Button variant="ghost" size="icon" className="size-8" aria-label={t('reminders.picker.remove')} onClick={() => onChange(reminders.filter((_, i) => i !== index))}>
              <X className="size-4" />
            </Button>
          </div>
        )
      })}
      {reminders.length < max ? (
        <Button type="button" variant="ghost" size="sm" onClick={() => onChange([...reminders, reminderOf(newRow(allDay), allDay)])} data-testid={`${id}-add-reminder`}>
          <Plus className="size-4" />
          {t('reminders.picker.add')}
        </Button>
      ) : null}
    </div>
  )
}
