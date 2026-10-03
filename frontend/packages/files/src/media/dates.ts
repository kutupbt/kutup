// Dates as cameras and phones write them (docs/plans/photos.md), turned into
// an instant (`takenAt`, UTC ms) and, when the source says, the time zone it
// was taken in (`takenOffset`, minutes east of UTC).

export interface TakenDate {
  takenAt: number
  takenOffset?: number
}

/** 1800 and 2200, as in the Rust format's limits. */
const MIN_MS = Date.UTC(1800, 0, 1)
const MAX_MS = Date.UTC(2200, 0, 1)

/** "+03:00", "+0300", "-0530", "Z" → minutes; undefined when unreadable. */
export function parseOffset(value: string | undefined): number | undefined {
  if (!value) return undefined
  const text = value.trim()
  if (text === 'Z') return 0
  const m = /^([+-])(\d{2}):?(\d{2})$/.exec(text)
  if (!m) return undefined
  const minutes = Number(m[2]) * 60 + Number(m[3])
  if (minutes > 14 * 60) return undefined
  return m[1] === '-' ? -minutes : minutes
}

/**
 * "2024:07:01 14:03:22" (EXIF), "2024-07-01T14:03:22.123+03:00" (XMP, ISO),
 * with optional sub-seconds and offset. Without an offset the wall-clock time
 * is read in this device's time zone (as Ente does) and no offset is kept.
 */
export function parseCameraDate(value: string, subSeconds?: string, offset?: string): TakenDate | undefined {
  const m = /^(\d{4})[:-](\d{2})[:-](\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?(?:\.(\d+))?)?\s*(Z|[+-]\d{2}:?\d{2})?$/.exec(value.trim())
  if (!m) return undefined
  const [year, month, day, hour, minute, second] = [m[1], m[2], m[3], m[4] ?? '0', m[5] ?? '0', m[6] ?? '0'].map(Number)
  const fraction = m[7] ?? subSeconds?.trim()
  const ms = fraction && /^\d+$/.test(fraction) ? Math.round(Number(`0.${fraction}`) * 1000) : 0
  // "0000:00:00 00:00:00" and Ente's 4501 placeholder mean "no date".
  if (year < 1800 || year >= 2200 || month < 1 || month > 12 || day < 1 || day > 31) return undefined
  if (hour > 23 || minute > 59 || second > 60) return undefined
  const zone = parseOffset(m[8] ?? offset)
  let takenAt: number
  if (zone === undefined) {
    const local = new Date(year, month - 1, day, hour, minute, second, ms)
    if (local.getDate() !== day) return undefined
    takenAt = local.getTime()
  } else {
    const utc = Date.UTC(year, month - 1, day, hour, minute, second, ms)
    if (new Date(utc).getUTCDate() !== day) return undefined
    takenAt = utc - zone * 60_000
  }
  if (!Number.isFinite(takenAt) || takenAt < MIN_MS || takenAt >= MAX_MS) return undefined
  return zone === undefined ? { takenAt } : { takenAt, takenOffset: zone }
}

/** Plausible for a photo: after 1990 (as Ente) and not in the future. */
function plausible(date: Date): boolean {
  const t = date.getTime()
  return Number.isFinite(t) && date.getFullYear() >= 1990 && t <= Date.now() + 86_400_000
}

function fromParts(year: number, month: number, day: number, hour?: number, minute?: number, second?: number): Date | undefined {
  const withTime = hour !== undefined && minute !== undefined
  let date = withTime ? new Date(year, month - 1, day, hour, minute, second ?? 0) : new Date(year, month - 1, day)
  if (withTime && (date.getHours() !== hour || date.getMinutes() !== minute)) date = new Date(year, month - 1, day)
  if (date.getFullYear() !== year || date.getMonth() !== month - 1 || date.getDate() !== day) return undefined
  return plausible(date) ? date : undefined
}

/** "20171218" + "143022" → a date. */
function fromFused(digits: string, time?: string): Date | undefined {
  if (!/^\d{8}$/.test(digits)) return undefined
  const t = time && /^\d{6}$/.test(time) ? time : undefined
  return fromParts(
    Number(digits.slice(0, 4)),
    Number(digits.slice(4, 6)),
    Number(digits.slice(6, 8)),
    t ? Number(t.slice(0, 2)) : undefined,
    t ? Number(t.slice(2, 4)) : undefined,
    t ? Number(t.slice(4, 6)) : undefined,
  )
}

/**
 * A date in a file name, as phones and apps write them (Ente's patterns):
 * `IMG-20171218-WA0028.jpg` (WhatsApp), `Screenshot_20240101-101500.png`,
 * `signal-2024-01-01-101500.jpg`, `PXL_20240101_101500123.jpg`,
 * `20240101_101500.jpg`, `2024-01-01 10.15.00.jpg`. Read in this device's
 * time zone; undefined when there is none.
 */
export function dateFromFileName(fileName: string): number | undefined {
  const name = fileName.trim().replace(/\.[^.]+$/, '')
  const groups = name.match(/\d+/g) ?? []
  let date: Date | undefined
  // Fused: 8 digits of date, then maybe 6 (or more: milliseconds) of time.
  const fusedIndex = groups.findIndex((g) => g.length === 8)
  if (fusedIndex >= 0) {
    const next = groups[fusedIndex + 1]
    date = fromFused(groups[fusedIndex]!, next && next.length >= 6 ? next.slice(0, 6) : undefined)
  }
  // Separate groups: 2024 01 01 [10 15 00].
  if (!date) {
    const start = groups.findIndex((g) => g.length === 4)
    if (start >= 0 && groups.length >= start + 3) {
      const [y, mo, d, h, mi, s] = groups.slice(start, start + 6).map(Number)
      if (groups[start + 1]!.length <= 2 && groups[start + 2]!.length <= 2) {
        const time = groups.length >= start + 5 && groups[start + 3]!.length <= 2 && groups[start + 4]!.length <= 2
        date = fromParts(y!, mo!, d!, time ? h : undefined, time ? mi : undefined, time ? s : undefined)
      }
    }
  }
  return date?.getTime()
}
