// The timeline's shape (docs/plans/photos.md): newest first, by day under
// month headings, cut into rows for the virtualized grid. Pure, so the
// ordering and the day a photo falls on are tested on their own.

export interface Dated {
  /** Stable and unique: the file id. */
  id: string
  /** When it was taken (UTC ms), or, until that is known, uploaded. */
  takenAt: number
  /** The time zone where it was taken, minutes east of UTC, when known. */
  takenOffset?: number
}

/**
 * The wall-clock parts of when a photo was taken: in the time zone it was
 * taken in when the photo says (a photo from Tokyo at 23:30 stays on that
 * day), else in this device's.
 */
export function takenParts(item: Pick<Dated, 'takenAt' | 'takenOffset'>): {
  year: number
  month: number
  day: number
  hour: number
  minute: number
} {
  if (item.takenOffset !== undefined) {
    const d = new Date(item.takenAt + item.takenOffset * 60_000)
    return {
      year: d.getUTCFullYear(),
      month: d.getUTCMonth() + 1,
      day: d.getUTCDate(),
      hour: d.getUTCHours(),
      minute: d.getUTCMinutes(),
    }
  }
  const d = new Date(item.takenAt)
  return { year: d.getFullYear(), month: d.getMonth() + 1, day: d.getDate(), hour: d.getHours(), minute: d.getMinutes() }
}

const pad = (n: number) => String(n).padStart(2, '0')

/** "2024-07-01". */
export function dayKey(item: Pick<Dated, 'takenAt' | 'takenOffset'>): string {
  const p = takenParts(item)
  return `${p.year}-${pad(p.month)}-${pad(p.day)}`
}

/** Newest first; the same instant falls back to the id, so the order is stable. */
export function newestFirst<T extends Dated>(items: readonly T[]): T[] {
  return [...items].sort((a, b) => b.takenAt - a.takenAt || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
}

export interface Day<T> {
  /** "2024-07-01". */
  day: string
  /** "2024-07". */
  month: string
  items: T[]
}

/** Consecutive photos of one day, from a newest-first list. */
export function daysOf<T extends Dated>(sorted: readonly T[]): Day<T>[] {
  const days: Day<T>[] = []
  for (const item of sorted) {
    const day = dayKey(item)
    const last = days[days.length - 1]
    if (last && last.day === day) last.items.push(item)
    else days.push({ day, month: day.slice(0, 7), items: [item] })
  }
  return days
}

export type TimelineRow<T> =
  | { kind: 'month'; key: string; month: string }
  | { kind: 'day'; key: string; day: string; items: T[] }
  | { kind: 'photos'; key: string; day: string; items: T[] }

/**
 * The rows the grid draws: a heading at each new month, a day heading, then
 * that day's photos `columns` to a row.
 */
export function timelineRows<T extends Dated>(days: readonly Day<T>[], columns: number): TimelineRow<T>[] {
  const cols = Math.max(1, Math.floor(columns))
  const rows: TimelineRow<T>[] = []
  let month: string | null = null
  for (const day of days) {
    if (day.month !== month) {
      month = day.month
      rows.push({ kind: 'month', key: `m:${month}`, month })
    }
    rows.push({ kind: 'day', key: `d:${day.day}`, day: day.day, items: day.items })
    for (let i = 0; i < day.items.length; i += cols) {
      rows.push({ kind: 'photos', key: `p:${day.day}:${i}`, day: day.day, items: day.items.slice(i, i + cols) })
    }
  }
  return rows
}

/** How many tiles fit: at least `min`, each at least `minTile` wide with `gap` between. */
export function columnsFor(width: number, minTile: number, gap: number, min = 3): number {
  return Math.max(min, Math.floor((width + gap) / (minTile + gap)))
}
