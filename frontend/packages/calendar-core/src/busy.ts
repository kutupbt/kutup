// Busy times (docs/plans/calendar-e3.md §4, E3e): when someone is busy,
// nothing more. The server answers from the calendars whose member chose to
// show their busy times, its recurrences expanded, and only to those the
// rule allows (Proton's: the person's organization; Q-3). Where they're shown
// (the participant row) comes with E4; this is the client for it.

import { loadServerSettings } from '@kutup/session/apps'
import api from '@kutup/session/client'

/** One busy block, in UTC (all-day blocks run midnight to midnight UTC of their dates). */
export interface BusyBlock {
  startUtc: string
  endUtc: string
  fullDay: boolean
}

/** The window the server answers at most (admin setting `calendar.busyWindowDays`). */
export async function busyWindowDays(): Promise<number> {
  const data = await loadServerSettings<{ calendar?: { busyWindowDays?: number } }>()
  return data.calendar?.busyWindowDays ?? 31
}

const DAY_MS = 24 * 60 * 60 * 1000

/** Asked for a window longer than the server answers. */
export class BusyWindowTooLong extends Error {
  constructor(readonly days: number) {
    super(`busy times are answered for at most ${days} days at once`)
    this.name = 'BusyWindowTooLong'
  }
}

/**
 * When the person at `address` is busy in [start, end), merged and in order.
 * The server may answer nothing (they share no busy times, or not with this
 * account), which is no error.
 */
export async function loadBusy(address: string, start: string, end: string): Promise<BusyBlock[]> {
  const from = Date.parse(start)
  const to = Date.parse(end)
  if (!(to > from)) throw new Error('the window ends before it starts')
  const days = await busyWindowDays()
  if (to - from > days * DAY_MS) throw new BusyWindowTooLong(days)
  const { data } = await api.get<{ busy: BusyBlock[] }>('/calendar/busy', { params: { address: address.trim(), start, end } })
  // Only what falls in the window, in order, overlaps merged: the server's
  // answer is a list of times, held to the shape asked for.
  const blocks = data.busy
    .filter((b) => Date.parse(b.endUtc) > from && Date.parse(b.startUtc) < to && Date.parse(b.endUtc) > Date.parse(b.startUtc))
    .sort((a, b) => a.startUtc.localeCompare(b.startUtc))
  const merged: BusyBlock[] = []
  for (const block of blocks) {
    const last = merged.at(-1)
    if (last && last.fullDay === block.fullDay && Date.parse(block.startUtc) <= Date.parse(last.endUtc)) {
      if (Date.parse(block.endUtc) > Date.parse(last.endUtc)) last.endUtc = block.endUtc
    } else {
      merged.push({ ...block })
    }
  }
  return merged
}
