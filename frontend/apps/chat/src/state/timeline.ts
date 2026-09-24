import { isSameDay } from '../lib/time'
import type { MessageView } from './views'

// How the timeline is laid out, as in Signal Desktop: a heading when the day
// changes, an "unread messages" marker before the first unread one, notices
// (timer changes) on their own row, and consecutive messages from one
// author within three minutes drawn as one group — name on the first,
// picture and time on the last, tighter corners in between.

export const GROUP_WINDOW_MS = 3 * 60_000
const UNREAD_ROW_KEY = 'unread'

export type TimelineRow =
  | { kind: 'day'; key: string; at: number }
  | { kind: 'unread'; key: string; count: number }
  | { kind: 'notice'; key: string; view: MessageView }
  | {
      kind: 'message'
      key: string
      view: MessageView
      /** Joined to the message above / below (same group). */
      joinedAbove: boolean
      joinedBelow: boolean
    }

function joins(older: MessageView, newer: MessageView): boolean {
  return (
    !older.timerChange &&
    !newer.timerChange &&
    older.author === newer.author &&
    newer.entry.timestampMs - older.entry.timestampMs < GROUP_WINDOW_MS &&
    isSameDay(older.entry.timestampMs, newer.entry.timestampMs) &&
    older.reactions.length === 0
  )
}

/**
 * The rows of a timeline. The marker covers what was unread when the
 * conversation was opened: incoming messages after `unread.after` (the read
 * mark then) up to `unread.openedAt`. What arrives while it is open is read
 * as it comes and gets no marker.
 */
export function timelineRows(
  views: readonly MessageView[],
  unread: { after: number; openedAt: number } | null,
): TimelineRow[] {
  const rows: TimelineRow[] = []
  const isUnread = (v: MessageView) =>
    unread !== null && !v.outgoing && !v.timerChange && v.entry.timestampMs > unread.after && v.entry.timestampMs <= unread.openedAt
  const firstUnread = views.findIndex(isUnread)
  const unreadCount = views.filter(isUnread).length
  views.forEach((view, index) => {
    const previous = views[index - 1]
    const next = views[index + 1]
    if (!previous || !isSameDay(previous.entry.timestampMs, view.entry.timestampMs)) {
      rows.push({ kind: 'day', key: `day:${view.entry.timestampMs}:${view.id}`, at: view.entry.timestampMs })
    }
    const markerHere = index === firstUnread && unreadCount > 0
    if (markerHere) rows.push({ kind: 'unread', key: UNREAD_ROW_KEY, count: unreadCount })
    if (view.timerChange) {
      rows.push({ kind: 'notice', key: `notice:${view.entry.id}`, view })
      return
    }
    const nextHasMarker = index + 1 === firstUnread && unreadCount > 0
    rows.push({
      kind: 'message',
      key: `${view.entry.direction}:${view.entry.id}`,
      view,
      joinedAbove: Boolean(previous && !markerHere && joins(previous, view)),
      joinedBelow: Boolean(next && !nextHasMarker && joins(view, next)),
    })
  })
  return rows
}
