import type { TFunction } from 'i18next'
import type { IcsFileRefused, ImportLimits, SubmitError, SubmitErrorKind } from '@kutup/calendar-core/ics'
import type { IcsErrorKind } from '@kutup/crypto/calendarIcs'

// Proton's texts for an import (`ImportFileError`, `getICSErrorMessage`).

/** Proton's display length of a file name (`MAX_FILENAME_CHARS_DISPLAY`). */
const MAX_FILENAME = 100

export function cut(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text
}

/** A size as Proton writes its limit: `10 MB`. */
export function sizeText(bytes: number): string {
  const mb = bytes / (1024 * 1024)
  return mb >= 1 ? `${Number.isInteger(mb) ? mb : mb.toFixed(1)} MB` : `${Math.round(bytes / 1024)} KB`
}

/** Why a whole file is refused, in Proton's words. */
export function fileErrorText(t: TFunction, error: IcsFileRefused, limits: ImportLimits): string {
  const filename = `"${cut(error.filename, MAX_FILENAME)}"`
  return t(`ics.file.${error.reason}`, { filename, size: sizeText(limits.maxBytes), count: limits.maxEvents })
}

/** One row of the details: what it is, what names it, and why it isn't imported. */
export interface ErrorRow {
  component: string
  id: string
  kind: IcsErrorKind | SubmitErrorKind
}

export function submitErrorRows(errors: SubmitError[]): ErrorRow[] {
  return errors.map((error) => ({ component: 'vevent', id: error.id, kind: error.kind }))
}

/** Proton's names for a component (`getComponentText`). */
export function componentText(t: TFunction, component: string): string {
  switch (component) {
    case 'vevent':
      return t('ics.component.event')
    case 'vcalendar':
      return t('ics.component.calendar')
    case 'vtimezone':
      return t('ics.component.timeZone')
    case 'vtodo':
    case 'vjournal':
    case 'vfreebusy':
      return t('ics.component.element')
    case '':
      return t('ics.component.unreadable')
    default:
      return t('ics.component.unknown')
  }
}
