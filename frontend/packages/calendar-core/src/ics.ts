// `.ics` import and export in the browser (docs/plans/calendar.md, E2 §5–6,
// E2c: the reading and writing in the `.ics` runtime, loaded on first use),
// as Proton's (`applications/calendar` import and export modals,
// `packages/shared/lib/calendar/import`): the Rust core reads the file and
// rebuilds each event; here every event is sealed with the calendar's key
// and sent in batches of the events sync (series first, then their changed
// occurrences), overwriting an event of the same UID as Proton's
// `Overwrite`. The export opens every event of a calendar here and the Rust
// core writes the file: the server never sees one in the clear.

import { sealCalendarEvent, type EventFields } from '@kutup/crypto/calendar'
import { exportIcs, importIcs, type IcsError, type IcsFileError, type IcsImport, type IcsReminder } from '@kutup/crypto/calendarIcs'
import type { MailAccount } from '@kutup/mail-core/api'
import { loadServerSettings } from '@kutup/session/apps'
import api from '@kutup/session/client'
import { RELEASE } from '@kutup/session/release'
import type { Session } from '@kutup/session/store'
import { activeAddressId, beforeEventWrite, openEvent, type Calendar, type EventRow } from './api'

/** The file types Proton's import takes. */
export const ICS_EXTENSIONS = ['ics', 'ical', 'icalendar', 'ifb'] as const

/** The site's limits an import holds to (admin settings `calendar.*`, published by `/auth/settings`). */
export interface ImportLimits {
  maxBytes: number
  maxEvents: number
  syncBatch: number
  maxCount: number
  maxReminders: number
}

export async function loadImportLimits(): Promise<ImportLimits> {
  const data = await loadServerSettings<{
    calendar?: { importMaxBytes?: number; importMaxEvents?: number; syncBatch?: number; maxCount?: number; remindersPerEvent?: number }
  }>()
  const c = data.calendar ?? {}
  return {
    maxBytes: c.importMaxBytes ?? 10 * 1024 * 1024,
    maxEvents: c.importMaxEvents ?? 15_000,
    syncBatch: c.syncBatch ?? 10,
    maxCount: c.maxCount ?? 49,
    maxReminders: c.remindersPerEvent ?? 10,
  }
}

/** A whole file refused: Proton's reasons, and two of the picker's own. */
export class IcsFileRefused extends Error {
  constructor(
    readonly reason: IcsFileError | 'noFileSelected' | 'noIcsFile',
    readonly filename: string,
  ) {
    super(`the file ${filename} is refused: ${reason}`)
    this.name = 'IcsFileRefused'
  }
}

/** Checks a picked file before it is read (Proton's `handleFiles`): its type and size. */
export function checkIcsFile(file: File | undefined, limits: ImportLimits): File {
  if (!file) throw new IcsFileRefused('noFileSelected', '')
  const extension = file.name.includes('.') ? file.name.split('.').pop()!.toLowerCase() : ''
  if (!(ICS_EXTENSIONS as readonly string[]).includes(extension)) throw new IcsFileRefused('noIcsFile', file.name)
  if (file.size > limits.maxBytes) throw new IcsFileRefused('fileTooBig', file.name)
  return file
}

/** Reads a picked file: what the Rust core rebuilt from it, or why it is refused. */
export async function readIcsFile(file: File, zone: string, limits: ImportLimits): Promise<IcsImport> {
  let text: string
  try {
    text = await file.text()
  } catch {
    throw new IcsFileRefused('invalidCalendar', file.name)
  }
  const outcome = await importIcs(text, {
    primaryZone: zone,
    maxBytes: limits.maxBytes,
    maxEvents: limits.maxEvents,
    maxCount: limits.maxCount,
    maxReminders: limits.maxReminders,
    now: new Date().toISOString(),
  })
  if ('refused' in outcome) throw new IcsFileRefused(outcome.refused, file.name)
  return outcome.read
}

/** Why an event that was read wasn't imported after all: the server's refusal or the sealing. */
export type SubmitErrorKind = 'encryptionError' | 'parentEventMissing' | 'sequenceBehind' | 'eventLimit' | 'quota' | 'singleEditUnsupported' | 'externalError'

export interface SubmitError {
  id: string
  kind: SubmitErrorKind
}

export interface ImportProgress {
  /** Events sealed so far. */
  encrypted: number
  /** Events the server stored so far. */
  imported: number
  errors: SubmitError[]
}

interface SyncResult {
  status: number
  code: string | null
  error: string | null
}

/** A server's refusal of one change, as an import reports it. */
function refusal(result: SyncResult): SubmitErrorKind {
  switch (result.code) {
    case 'parentMissing':
      return 'parentEventMissing'
    case 'notAnOccurrence':
      return 'singleEditUnsupported'
    case 'sequenceBehind':
      return 'sequenceBehind'
    case 'eventLimit':
      return 'eventLimit'
    case 'quotaExceeded':
    case 'storageFull':
      return 'quota'
    default:
      return 'externalError'
  }
}

const sleep = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    const timer = setTimeout(resolve, ms)
    signal?.addEventListener('abort', () => {
      clearTimeout(timer)
      reject(new DOMException('aborted', 'AbortError'))
    })
  })

function status(error: unknown): number | undefined {
  return (error as { response?: { status?: number } })?.response?.status
}

/** One batch, sent again after the server's rate limit asks to wait (Proton's "jails"). */
async function sendBatch(calendar: Calendar, addressId: string, changes: unknown[], signal?: AbortSignal): Promise<SyncResult[]> {
  for (let attempt = 0; ; attempt++) {
    try {
      const { data } = await api.post<{ results: SyncResult[] }>(`/calendar/calendars/${calendar.id}/events/sync`, { addressId, changes }, { signal })
      return data.results
    } catch (error) {
      if (status(error) !== 429 || attempt >= 30) throw error
      const retry = Number((error as { response?: { headers?: Record<string, string> } }).response?.headers?.['retry-after'])
      await sleep(Number.isFinite(retry) && retry > 0 ? Math.min(retry, 60) * 1000 : 5000, signal)
    }
  }
}

/**
 * Seals and stores the events read from a file in `calendar`, in batches
 * of the site's sync, in the order read (every series before its changed
 * occurrences). Each event carries its own reminders (an imported event
 * takes no calendar defaults, as Proton's; an invitation's take them) and
 * overwrites an event of the same UID, unless that one's SEQUENCE is ahead.
 */
export async function importEvents(
  session: Session,
  account: MailAccount,
  calendar: Calendar,
  /** `reminders` null: the calendar's defaults (an invitation's, as Proton adds them). */
  events: { fields: EventFields; reminders: IcsReminder[] | null; id: string }[],
  limits: ImportLimits,
  onProgress: (progress: ImportProgress) => void,
  signal?: AbortSignal,
): Promise<ImportProgress> {
  await beforeEventWrite(session)
  const addressId = await activeAddressId(account)
  const progress: ImportProgress = { encrypted: 0, imported: 0, errors: [] }
  const batch = Math.max(1, limits.syncBatch)
  for (let at = 0; at < events.length; at += batch) {
    if (signal?.aborted) throw new DOMException('aborted', 'AbortError')
    const sealed: { id: string; change: unknown }[] = []
    for (const event of events.slice(at, at + batch)) {
      try {
        const data = sealCalendarEvent(calendar.unlocked, account.key, event.fields)
        sealed.push({
          id: event.id,
          change: { create: { id: crypto.randomUUID(), event: data, ...(event.reminders ? { reminders: event.reminders } : {}), overwrite: true } },
        })
        progress.encrypted++
      } catch {
        progress.errors.push({ id: event.id, kind: 'encryptionError' })
      }
    }
    onProgress({ ...progress })
    if (sealed.length === 0) continue
    const results = await sendBatch(
      calendar,
      addressId,
      sealed.map((s) => s.change),
      signal,
    )
    results.forEach((result, index) => {
      if (result.status === 200) progress.imported++
      else progress.errors.push({ id: sealed[index]?.id ?? '', kind: refusal(result) })
    })
    onProgress({ ...progress, errors: [...progress.errors] })
  }
  return progress
}

/** An event not exported: when it starts, and whether it repeats (Proton's export errors). */
export interface ExportError {
  startUtc: string
  fullDay: boolean
  repeats: boolean
}

/** Every event row of `calendar`, page by page (by id, whenever they are). */
async function allEventRows(calendar: Calendar, signal?: AbortSignal): Promise<EventRow[]> {
  const rows: EventRow[] = []
  let after: string | null = null
  for (let pages = 0; pages < 100_000; pages++) {
    const response: { data: { events: EventRow[]; next: string | null } } = await api.get(`/calendar/calendars/${encodeURIComponent(calendar.id)}/events/all`, {
      params: after ? { afterId: after } : {},
      signal,
    })
    rows.push(...response.data.events)
    const next = response.data.next
    if (!next) return rows
    if (after && next <= after) throw new Error('the server repeats a page')
    after = next
  }
  throw new Error('the server never ends this listing')
}

/**
 * The calendar as one `.ics` file, every event opened here (Proton's
 * export): each with this member's reminders (its own, else the calendar's
 * defaults). An event that doesn't open is left out and reported.
 */
export async function exportCalendar(
  account: MailAccount,
  calendar: Calendar,
  zone: string,
  untitled: string,
  onProgress?: (done: number, total: number) => void,
  signal?: AbortSignal,
): Promise<{ text: string; exported: number; errors: ExportError[] }> {
  const rows = await allEventRows(calendar, signal)
  const events: { fields: EventFields; reminders: IcsReminder[] }[] = []
  const errors: ExportError[] = []
  for (const [index, row] of rows.entries()) {
    try {
      const opened = await openEvent(account, calendar, row)
      const reminders = opened.reminders ?? (opened.fullDay ? calendar.defaultReminders.allDay : calendar.defaultReminders.timed)
      events.push({ fields: opened.fields, reminders })
    } catch {
      errors.push({ startUtc: row.startUtc, fullDay: row.fullDay, repeats: row.rangeEndUtc !== row.endUtc })
    }
    onProgress?.(index + 1, rows.length)
  }
  const text = await exportIcs({
    name: calendar.name,
    description: calendar.description || null,
    zone,
    release: RELEASE,
    untitled,
    email: account.address,
    events,
  })
  return { text, exported: events.length, errors }
}

/** Proton's file name: `<calendar name>-yyyy-MM-dd.ics`, today in the calendar's zone. */
export function exportFileName(name: string, today: string): string {
  const safe =
    [...name]
      .map((c) => (c.charCodeAt(0) < 0x20 || '\\/:*?"<>|'.includes(c) ? '_' : c))
      .join('')
      .trim() || 'calendar'
  return `${safe}-${today}.ics`
}

export type { IcsError, IcsImport }
