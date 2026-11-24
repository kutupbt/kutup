import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { Calendar } from '@kutup/calendar-core/api'
import { exportCalendar, exportFileName, type ExportError } from '@kutup/calendar-core/ics'
import { useMailAccount } from '@kutup/mail-core/api'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { useCalendarPrefs } from '../prefs'
import { useToday } from '../today'
import { ProgressBar } from './ImportParts'

// Proton's export modal (`ExportModal`): every event opened here, the file
// written by the Rust core, then a summary and "Save ICS file". Events that
// don't open are left out and listed, as Proton's.

type State = { step: 'exporting'; done: number; total: number } | { step: 'done'; text: string; exported: number; errors: ExportError[] } | { step: 'failed'; message: string }

export function ExportDialog({ calendar, onClose }: { calendar: Calendar; onClose: () => void }) {
  const { t, i18n } = useTranslation()
  const account = useMailAccount()
  const prefs = useCalendarPrefs()
  const today = useToday(prefs.zone)
  const [state, setState] = useState<State>({ step: 'exporting', done: 0, total: 0 })
  const [attempt, setAttempt] = useState(0)
  const abort = useRef<AbortController | null>(null)

  useEffect(() => {
    if (!account.data) return
    const controller = new AbortController()
    abort.current = controller
    setState({ step: 'exporting', done: 0, total: 0 })
    exportCalendar(account.data, calendar, prefs.zone, t('events.untitled'), (done, total) => !controller.signal.aborted && setState({ step: 'exporting', done, total }), controller.signal)
      .then((result) => !controller.signal.aborted && setState({ step: 'done', ...result }))
      .catch((error: unknown) => !controller.signal.aborted && setState({ step: 'failed', message: apiErrorMessage(error, t('ics.export.failed')) }))
    return () => controller.abort()
    // eslint-disable-next-line react-hooks/exhaustive-deps -- once per attempt
  }, [account.data, attempt])

  const save = (text: string) => {
    const url = URL.createObjectURL(new Blob([text], { type: 'text/calendar;charset=utf-8' }))
    const link = document.createElement('a')
    link.href = url
    link.download = exportFileName(calendar.name, today ?? new Date().toISOString().slice(0, 10))
    document.body.appendChild(link)
    link.click()
    link.remove()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
    onClose()
  }

  const when = (error: ExportError) =>
    new Intl.DateTimeFormat(i18n.language, error.fullDay ? { dateStyle: 'medium', timeZone: 'UTC' } : { dateStyle: 'medium', timeStyle: 'short', timeZone: prefs.zone }).format(new Date(error.startUtc))

  return (
    <Dialog open onOpenChange={(open) => !open && (abort.current?.abort(), onClose())}>
      <DialogContent className="sm:max-w-lg" data-testid="export-dialog">
        <DialogHeader>
          <DialogTitle>{t('ics.export.title')}</DialogTitle>
        </DialogHeader>
        {state.step === 'exporting' ? (
          <div className="space-y-4">
            <p className="text-sm">{t('ics.export.dontClose')}</p>
            <ProgressBar value={state.done} max={state.total} label={t('ics.export.progress', { done: state.done, count: state.total })} />
          </div>
        ) : null}
        {state.step === 'failed' ? <Alert variant="error">{state.message}</Alert> : null}
        {state.step === 'done' ? (
          <div className="space-y-4">
            {state.errors.length === 0 ? (
              <p className="text-sm" data-testid="export-summary">
                {t('ics.export.success', { count: state.exported })}
              </p>
            ) : (
              <>
                <Alert variant={state.exported > 0 ? 'warn' : 'error'} data-testid="export-summary">
                  {t('ics.export.partial', { exported: state.exported, count: state.exported + state.errors.length })}
                </Alert>
                <details className="rounded-md border text-sm">
                  <summary className="cursor-pointer px-3 py-2">{t('ics.import.details')}</summary>
                  <ul className="max-h-56 space-y-1 overflow-y-auto border-t px-3 py-2">
                    {state.errors.map((error, index) => (
                      <li key={index}>
                        {t(error.repeats ? 'ics.export.errorSeries' : 'ics.export.error', { when: when(error) })}: <span className="text-destructive">{t('ics.export.notOpened')}</span>
                      </li>
                    ))}
                  </ul>
                </details>
              </>
            )}
          </div>
        ) : null}
        <DialogFooter>
          <Button type="button" variant="ghost" onClick={() => (abort.current?.abort(), onClose())}>
            {t('common.cancel')}
          </Button>
          {state.step === 'failed' ? (
            <Button type="button" onClick={() => setAttempt((n) => n + 1)}>
              {t('ics.export.retry')}
            </Button>
          ) : (
            <Button type="button" disabled={state.step !== 'done' || (state.exported === 0 && state.errors.length > 0)} onClick={() => state.step === 'done' && save(state.text)} data-testid="export-save">
              {t('ics.export.save')}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
