import type { Reminder } from '@kutup/calendar-core/api'

// Proton's notification picker (`NotificationInput`, `getValarmTrigger`):
// what a row shows, and the RFC 5545 trigger it stands for. A timed event's:
// "at time of event" or a number of minutes, hours, days or weeks before.
// An all-day event's: "on the same day" or a number of days or weeks before,
// at a time of day.

export type ReminderUnit = 'minute' | 'hour' | 'day' | 'week'

/** One row of the picker. */
export interface ReminderRow {
  type: Reminder['type']
  /** 0 with `unit` minute (timed) or day (all-day): at the event's time, or on its day. */
  value: number
  unit: ReminderUnit
  /** All-day only: the time of day, minutes after midnight. */
  at: number
}

const MINUTES: Record<ReminderUnit, number> = { minute: 1, hour: 60, day: 1440, week: 10080 }

/** Proton's bounds per unit (`NOTIFICATION_UNITS_MAX`). */
export const UNIT_MAX: Record<ReminderUnit, number> = { week: 999, day: 6999, hour: 999, minute: 9999 }

/** A trigger's minutes from the start (negative: before), or null for one this picker doesn't read. */
export function triggerMinutes(trigger: string): number | null {
  const match = /^([+-]?)P(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$/.exec(trigger)
  if (!match || trigger === 'P' || trigger.endsWith('T')) return null
  const [, sign, weeks, days, hours, minutes] = match
  const total = Number(weeks ?? 0) * 10080 + Number(days ?? 0) * 1440 + Number(hours ?? 0) * 60 + Number(minutes ?? 0)
  return sign === '-' ? -total : total
}

/** Minutes as a trigger, Proton's way: `-PT15M`, `-P1D`, `-PT15H`, `PT9H`, `PT0S`. */
export function minutesTrigger(minutes: number): string {
  if (minutes === 0) return 'PT0S'
  const sign = minutes < 0 ? '-' : ''
  let rest = Math.abs(minutes)
  // A whole number of weeks or days before reads as Proton writes it.
  if (rest % 10080 === 0) return `${sign}P${rest / 10080}W`
  const days = Math.floor(rest / 1440)
  rest -= days * 1440
  const hours = Math.floor(rest / 60)
  const mins = rest - hours * 60
  const time = `${hours ? `${hours}H` : ''}${mins ? `${mins}M` : ''}`
  return `${sign}P${days ? `${days}D` : ''}${time ? `T${time}` : ''}`
}

/** A reminder as the picker shows it. */
export function rowOf(reminder: Reminder, allDay: boolean): ReminderRow | null {
  const minutes = triggerMinutes(reminder.trigger)
  if (minutes === null) return null
  if (!allDay) {
    if (minutes > 0) return null
    const before = -minutes
    if (before === 0) return { type: reminder.type, value: 0, unit: 'minute', at: 0 }
    const unit: ReminderUnit = before % 10080 === 0 ? 'week' : before % 1440 === 0 ? 'day' : before % 60 === 0 ? 'hour' : 'minute'
    return { type: reminder.type, value: before / MINUTES[unit], unit, at: 0 }
  }
  // All-day: days before (0: the same day) and the time of day.
  if (minutes >= 1440) return null
  const days = minutes >= 0 ? 0 : Math.ceil(-minutes / 1440)
  const at = minutes + days * 1440
  if (days > 0 && days % 7 === 0) return { type: reminder.type, value: days / 7, unit: 'week', at }
  return { type: reminder.type, value: days, unit: 'day', at }
}

/** The reminder a row stands for. */
export function reminderOf(row: ReminderRow, allDay: boolean): Reminder {
  if (!allDay) return { type: row.type, trigger: minutesTrigger(-row.value * MINUTES[row.unit]) }
  const days = row.unit === 'week' ? row.value * 7 : row.value
  return { type: row.type, trigger: minutesTrigger(-days * 1440 + row.at) }
}

/** A new row (Proton's): a device reminder 15 minutes before, or the day before at 09:00. */
export function newRow(allDay: boolean): ReminderRow {
  return allDay ? { type: 'device', value: 1, unit: 'day', at: 9 * 60 } : { type: 'device', value: 15, unit: 'minute', at: 0 }
}

/** The same reminder twice (type and time) is refused by the server: the rows say so first. */
export function hasRepeats(reminders: Reminder[]): boolean {
  const seen = new Set(reminders.map((r) => `${r.type}:${triggerMinutes(r.trigger)}`))
  return seen.size !== reminders.length
}
