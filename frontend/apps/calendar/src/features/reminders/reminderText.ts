import type { TFunction } from 'i18next'
import type { Reminder } from '@kutup/calendar-core/api'
import { formatTime } from '../format'
import { rowOf } from './triggers'

/**
 * A reminder in words, as Proton's popover lists it (`getNotificationString`,
 * `PopoverNotification`): "15 minutes before", "At time of event", "1 day
 * before at 09:00", "On the same day at 09:00", with "by email" for an email
 * one; a trigger the picker can't read is shown as written.
 */
export function reminderText(t: TFunction, reminder: Reminder, allDay: boolean, locale: string, hour12: boolean | null): string {
  const row = rowOf(reminder, allDay)
  let text: string
  if (!row) text = t('reminders.picker.other', { trigger: reminder.trigger })
  else if (!allDay) text = row.value === 0 ? t('reminders.text.atTime') : t(`reminders.text.${row.unit}Before`, { count: row.value })
  else {
    const time = formatTime(`2000-01-01T${String(Math.floor(row.at / 60)).padStart(2, '0')}:${String(row.at % 60).padStart(2, '0')}:00`, locale, hour12)
    text = row.value === 0 ? t('reminders.text.sameDayAt', { time }) : t(`reminders.text.${row.unit}BeforeAt`, { count: row.value, time })
  }
  return reminder.type === 'email' ? t('reminders.text.byEmail', { text }) : text
}
