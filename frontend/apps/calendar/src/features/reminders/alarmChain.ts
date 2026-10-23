import type { Alarm } from '@kutup/calendar-core/api'

// Proton's AlarmWatcher: the open app fires its own reminders. One timer at a
// time, for the next alarm not yet fired; each once (a set kept by the
// caller); one more than a minute late is skipped, never shown.

const MINUTE = 60_000
/** The window fetched ahead (Proton's lookAhead). */
export const LOOK_AHEAD_MS = 2 * 24 * 60 * MINUTE
/** Fetched again this long before the window ends (Proton's PADDING). */
export const PADDING_MS = 2 * MINUTE
/** Later than this, a reminder is skipped (Proton's MIN_CUTOFF). */
export const LATE_MS = MINUTE

/**
 * One alarm's name for a notification (its tag) and for the fired set:
 * its event, occurrence and fire time (Proton tags per alarm: two
 * reminders for one occurrence are two notifications), as the service
 * worker's push names it too, so the two never show one reminder twice.
 */
export function alarmTag(alarm: Pick<Alarm, 'eventId' | 'occurrenceStart' | 'fireAt'>): string {
  return `kutup-calendar:${alarm.eventId}:${Date.parse(alarm.occurrenceStart)}:${Date.parse(alarm.fireAt)}`
}

/**
 * Fires `alarms` (sorted by fire time) in turn, each once (`fired` is the
 * caller's, kept across refetches), `fire` called for one at most a minute
 * late. Returns the chain's end.
 */
export function runAlarms(alarms: Alarm[], fired: Set<string>, fire: (alarm: Alarm) => Promise<void>, now: () => number = Date.now): () => void {
  let timer: ReturnType<typeof setTimeout> | undefined
  let stopped = false
  const run = () => {
    if (stopped) return
    const next = alarms.find((alarm) => !fired.has(alarmTag(alarm)))
    if (!next) return
    const at = Date.parse(next.fireAt)
    timer = setTimeout(
      () => {
        if (stopped) return
        // A timer can come early (throttled, clamped): wait out the rest.
        if (now() < at - 1_000) {
          run()
          return
        }
        fired.add(alarmTag(next))
        if (now() - at > LATE_MS) {
          run()
          return
        }
        void fire(next)
          .catch(() => undefined)
          .finally(run)
      },
      Math.max(at - now(), 0),
    )
  }
  run()
  return () => {
    stopped = true
    if (timer !== undefined) clearTimeout(timer)
  }
}
