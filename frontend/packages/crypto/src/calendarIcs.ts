import type { EventFields } from './calendar'
import { freshUrl, retryLoad } from './retry'

// The `.ics` runtime (crates/kutup-calendar-ics-wasm, docs/plans/calendar.md
// E2c): the Rust core's import and export of `.ics` files, a runtime of its
// own loaded the first time a file is imported or exported, so the calendar
// runtimes don't carry it (and Mail's invitations, E4, load it the same way).
// From the page's own origin, in a directory named for its content hash
// (@kutup/config/vite), under the apps' `'wasm-unsafe-eval'` policy as the
// other runtimes. It holds no key: events are sealed and opened by
// crypto-calendar.

declare const __KUTUP_CALENDAR_ICS_WASM__: string | undefined
const BASE =
  typeof __KUTUP_CALENDAR_ICS_WASM__ === 'string' && __KUTUP_CALENDAR_ICS_WASM__ ? `/calendar-ics-wasm/${__KUTUP_CALENDAR_ICS_WASM__}` : '/calendar-ics-wasm'
const MODULE_URL = `${BASE}/kutup_calendar_ics_wasm.js`
const WASM_URL = `${BASE}/kutup_calendar_ics_wasm_bg.wasm`

/** A reminder as the server keeps it: on the device or by email, a trigger relative to the start. */
export interface IcsReminder {
  type: 'device' | 'email'
  trigger: string
}

/** What an `.ics` import may take (`ImportOptionsV1`): the site's limits, the person's zone, and now. */
export interface IcsImportOptions {
  primaryZone: string
  maxBytes: number
  maxEvents: number
  maxCount: number
  maxReminders: number
  now: string
}

/** Why a whole file is refused (Proton's `IMPORT_ERROR_TYPE`). */
export type IcsFileError = 'fileEmpty' | 'fileTooBig' | 'invalidCalendar' | 'invalidMethod' | 'noEvents' | 'tooManyEvents'

/** Why one component isn't imported (Proton's `IMPORT_EVENT_ERROR_TYPE`). */
export type IcsErrorKind =
  | 'wrongFormat'
  | 'nonGregorian'
  | 'todoFormat'
  | 'journalFormat'
  | 'freebusyFormat'
  | 'timezoneFormat'
  | 'unexpectedFloatingTime'
  | 'alldayInconsistency'
  | 'dtstartMissing'
  | 'dtstartMalformed'
  | 'dtstartOutOfBounds'
  | 'dtendMalformed'
  | 'dtendOutOfBounds'
  | 'xWrTimezoneUnsupported'
  | 'tzidUnsupported'
  | 'rruleMalformed'
  | 'rruleUnsupported'
  | 'singleEditUnsupported'
  | 'validationError'
  | 'externalError'

/** A component not imported: what it is (`vevent`, `vtodo`…), what names it, and why. */
export interface IcsError {
  component: string
  id: string
  kind: IcsErrorKind
}

export interface IcsImportedEvent {
  fields: EventFields
  reminders: IcsReminder[]
  id: string
}

/** A file read: its method, the events (series first), what isn't imported, and the events with no occurrence left. */
export interface IcsImport {
  method: string
  events: IcsImportedEvent[]
  errors: IcsError[]
  hidden: number
}

export type IcsImportOutcome = { read: IcsImport } | { refused: IcsFileError }

/** What an export writes (`ExportCalendarV1`). */
export interface IcsExport {
  name: string
  description: string | null
  zone: string
  release: string
  /** What an untitled event's alarms show. */
  untitled: string
  /** The member's address, for email alarms. */
  email: string | null
  events: { fields: EventFields; reminders: IcsReminder[] }[]
}

interface CalendarIcsModule {
  default(input?: unknown): Promise<unknown>
  calendarImportIcs(text: string, options: IcsImportOptions): IcsImportOutcome
  calendarExportIcs(calendar: IcsExport): string
}

let modulePromise: Promise<CalendarIcsModule> | null = null

/** The runtime, loaded once (a load cut off is tried again; a failed one is tried afresh next time). */
function runtime(): Promise<CalendarIcsModule> {
  if (!modulePromise) {
    modulePromise = retryLoad(async (n) => {
      const url = n === 0 ? MODULE_URL : freshUrl(MODULE_URL, n)
      const module = (await import(/* @vite-ignore */ url)) as CalendarIcsModule
      await module.default({ module_or_path: WASM_URL })
      return module
    })
    modulePromise.catch(() => {
      modulePromise = null
    })
  }
  return modulePromise
}

/** Reads an `.ics` file for import, every event rebuilt as Proton's import does (E2 §5). */
export async function importIcs(text: string, options: IcsImportOptions): Promise<IcsImportOutcome> {
  return (await runtime()).calendarImportIcs(text, options)
}

/** Writes a calendar's opened events as one `.ics` file (E2 §6). */
export async function exportIcs(calendar: IcsExport): Promise<string> {
  return (await runtime()).calendarExportIcs(calendar)
}
