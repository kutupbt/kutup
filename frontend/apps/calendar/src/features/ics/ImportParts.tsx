import { useTranslation } from 'react-i18next'
import { componentText, cut, type ErrorRow } from './importText'

// The pieces Proton's import and export modals show their texts in.

/** Proton's display length of an id (`MAX_UID_CHARS_DISPLAY`). */
const MAX_ID = 43

/** Proton's "click for details": every component not imported, and why. */
export function ErrorDetails({ rows, summary }: { rows: ErrorRow[]; summary: string }) {
  const { t } = useTranslation()
  if (rows.length === 0) return null
  return (
    <details className="rounded-md border text-sm" data-testid="import-errors">
      <summary className="cursor-pointer px-3 py-2">{summary}</summary>
      <ul className="max-h-56 space-y-1 overflow-y-auto border-t px-3 py-2">
        {rows.map((row, index) => (
          <li key={`${row.id}:${index}`} className="flex flex-col md:flex-row md:flex-wrap md:gap-1" data-testid="import-error">
            <span className="truncate">{`${componentText(t, row.component)} ${cut(row.id, MAX_ID)}`.trim()}:</span>
            <span className="text-destructive">{t(`ics.error.${row.kind}`)}</span>
          </li>
        ))}
      </ul>
    </details>
  )
}

/** Proton's `DynamicProgress`: a bar and what it counts. */
export function ProgressBar({ value, max, label }: { value: number; max: number; label: string }) {
  const share = max > 0 ? Math.min(100, Math.round((value / max) * 100)) : 100
  return (
    <div className="space-y-1.5">
      <div className="h-2 overflow-hidden rounded-full bg-muted" role="progressbar" aria-valuemin={0} aria-valuemax={max} aria-valuenow={value} aria-label={label}>
        <div className="h-full bg-primary transition-[width]" style={{ width: `${share}%` }} />
      </div>
      <p className="text-xs text-muted-foreground" data-testid="ics-progress">
        {label}
      </p>
    </div>
  )
}
