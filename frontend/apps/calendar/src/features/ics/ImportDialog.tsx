import { useQuery, useQueryClient } from '@tanstack/react-query'
import { FileUp, X } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { PERMISSION, useCalendars, type Calendar } from '@kutup/calendar-core/api'
import { checkIcsFile, ICS_EXTENSIONS, IcsFileRefused, importEvents, loadImportLimits, readIcsFile, type ImportProgress } from '@kutup/calendar-core/ics'
import type { IcsImport } from '@kutup/crypto/calendar'
import { useMailAccount } from '@kutup/mail-core/api'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Label } from '@kutup/ui/components/label'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { Choice } from '../Choice'
import { useCalendarPrefs } from '../prefs'
import { ErrorDetails, ProgressBar } from './ImportParts'
import { fileErrorText, sizeText, submitErrorRows } from './importText'

// Proton's import modal (`ImportModal`): a file and a calendar, the file read
// and each event rebuilt in the browser, a warning for an invitation file
// and for what can't be imported, then every event sealed and sent, and a
// summary. Its steps and texts are Proton's.

type Step = 'attach' | 'invitation' | 'partial' | 'importing' | 'done'

/** Proton's totals (`extractTotals`): events with no occurrence left count as imported. */
function totals(read: IcsImport, progress: ImportProgress) {
  const toImport = read.events.length + read.hidden
  return {
    toImport,
    toProcess: 2 * toImport,
    imported: progress.imported + read.hidden,
    processed: progress.encrypted + progress.imported + 2 * read.hidden + progress.errors.length,
  }
}

export function ImportDialog({ open, onOpenChange, initialCalendarId }: { open: boolean; onOpenChange: (open: boolean) => void; initialCalendarId?: string }) {
  const { t } = useTranslation()
  const session = useRequiredSession()
  const account = useMailAccount()
  const calendars = useCalendars()
  const prefs = useCalendarPrefs()
  const queryClient = useQueryClient()
  const limits = useQuery({ queryKey: ['calendar', 'import-limits'], queryFn: loadImportLimits, staleTime: 5 * 60_000 })
  const writable = (calendars.data?.calendars ?? []).filter((calendar) => (calendar.permissions & PERMISSION.write) !== 0)
  const [step, setStep] = useState<Step>('attach')
  const [file, setFile] = useState<File | null>(null)
  const [calendarId, setCalendarId] = useState('')
  const [failure, setFailure] = useState<string | null>(null)
  const [reading, setReading] = useState(false)
  const [read, setRead] = useState<IcsImport | null>(null)
  const [progress, setProgress] = useState<ImportProgress>({ encrypted: 0, imported: 0, errors: [] })
  const abort = useRef<AbortController | null>(null)
  const input = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (!open) return
    setStep('attach')
    setFile(null)
    setFailure(null)
    setRead(null)
    setProgress({ encrypted: 0, imported: 0, errors: [] })
    setCalendarId(initialCalendarId ?? writable[0]?.id ?? '')
    // eslint-disable-next-line react-hooks/exhaustive-deps -- once per opening
  }, [open])
  useEffect(() => () => abort.current?.abort(), [])

  const calendar: Calendar | undefined = writable.find((c) => c.id === calendarId) ?? writable[0]
  const close = () => {
    abort.current?.abort()
    onOpenChange(false)
  }

  const attach = (picked: File | undefined) => {
    if (!limits.data) return
    try {
      setFile(checkIcsFile(picked, limits.data))
      setFailure(null)
    } catch (error) {
      setFile(null)
      setFailure(error instanceof IcsFileRefused ? fileErrorText(t, error, limits.data) : t('ics.import.failed'))
    }
  }

  const start = async (from: IcsImport) => {
    if (!account.data || !calendar || !limits.data) return
    setStep('importing')
    const controller = new AbortController()
    abort.current = controller
    try {
      // An invitation imported as a simple event takes the calendar's default
      // reminders (Proton's getVeventWithDefaultCalendarAlarms); a published
      // file's events their own.
      const events = from.method === 'PUBLISH' ? from.events : from.events.map((event) => ({ ...event, reminders: null }))
      const done = await importEvents(session, account.data, calendar, events, limits.data, (next) => !controller.signal.aborted && setProgress(next), controller.signal)
      if (controller.signal.aborted) return
      setProgress(done)
      setStep('done')
    } catch (error) {
      if (controller.signal.aborted) return
      setStep('attach')
      setRead(null)
      setFailure(apiErrorMessage(error, t('ics.import.failed')))
    } finally {
      await queryClient.invalidateQueries({ queryKey: ['calendar'] })
    }
  }

  const submitFile = async () => {
    if (!file || !limits.data) return
    setReading(true)
    try {
      const result = await readIcsFile(file, prefs.zone, limits.data)
      const toImport = result.events.length + result.hidden
      setRead(result)
      setFailure(null)
      if (result.method !== 'PUBLISH') setStep('invitation')
      else if (result.errors.length > 0) setStep('partial')
      else if (toImport > 0) void start(result)
    } catch (error) {
      setFile(null)
      setFailure(error instanceof IcsFileRefused ? fileErrorText(t, error, limits.data) : t('ics.import.failed'))
    } finally {
      setReading(false)
    }
  }

  const sum = read ? totals(read, progress) : null
  const discarded = read ? read.errors.filter((e) => e.component === 'vevent').length : 0

  const title =
    step === 'invitation'
      ? t('ics.import.invitationTitle', { count: read ? read.events.length + read.errors.length + read.hidden : 0 })
      : step === 'partial'
        ? sum?.toImport
          ? t('ics.import.partialTitle')
          : t('ics.import.failedTitle')
        : t('ics.import.title')

  return (
    <Dialog open={open} onOpenChange={(next) => (next ? onOpenChange(true) : step === 'importing' ? undefined : close())}>
      <DialogContent className="sm:max-w-lg" data-testid="import-dialog">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
        </DialogHeader>
        {step === 'attach' ? (
          <div className="space-y-4">
            {failure ? (
              <Alert variant="error" data-testid="import-failure">
                {failure}
              </Alert>
            ) : (
              <p className="text-sm text-muted-foreground">
                {limits.data ? t('ics.import.intro', { size: sizeText(limits.data.maxBytes), count: limits.data.maxEvents }) : null}
              </p>
            )}
            <div className="flex items-center justify-center rounded-xl border border-dashed p-4">
              {file ? (
                <div className="flex min-w-0 items-center gap-2 text-sm">
                  <FileUp className="size-4 shrink-0" aria-hidden />
                  <span className="truncate" data-testid="import-file-name">
                    {file.name}
                  </span>
                  <Button type="button" size="sm" variant="ghost" onClick={() => setFile(null)} aria-label={t('ics.import.remove')}>
                    <X className="size-4" aria-hidden />
                  </Button>
                </div>
              ) : (
                <>
                  <input
                    ref={input}
                    id="import-file"
                    type="file"
                    hidden
                    accept={ICS_EXTENSIONS.map((e) => `.${e}`).join(',')}
                    onChange={(e) => {
                      attach(e.target.files?.[0])
                      e.target.value = ''
                    }}
                    data-testid="import-file"
                  />
                  <Button type="button" variant="outline" onClick={() => input.current?.click()} disabled={!limits.data}>
                    {t('ics.import.choose')}
                  </Button>
                </>
              )}
            </div>
            {writable.length > 1 ? (
              <div className="space-y-1.5">
                <Label htmlFor="import-calendar">{t('ics.import.to')}</Label>
                <Choice id="import-calendar" value={calendar?.id ?? ''} options={writable.map((c) => ({ value: c.id, label: c.name }))} onChange={setCalendarId} testId="import-calendar" />
              </div>
            ) : null}
            <DialogFooter>
              <Button type="button" variant="ghost" onClick={close}>
                {t('common.cancel')}
              </Button>
              <Button type="button" disabled={!file || !calendar || !account.data} loading={reading} onClick={() => void submitFile()} data-testid="import-submit">
                {t('ics.import.submit')}
              </Button>
            </DialogFooter>
          </div>
        ) : null}
        {step === 'invitation' && read ? (
          <div className="space-y-4">
            <p className="text-sm">{t(['REPLY', 'COUNTER', 'REFRESH'].includes(read.method) ? 'ics.import.invitationResponse' : 'ics.import.invitation', { count: read.events.length })}</p>
            <p className="text-sm text-muted-foreground">{t('ics.import.invitationHint')}</p>
            <DialogFooter>
              <Button type="button" variant="ghost" onClick={close}>
                {t('common.cancel')}
              </Button>
              <Button type="button" onClick={() => (read.errors.length ? setStep('partial') : void start(read))}>
                {t('ics.import.submit')}
              </Button>
            </DialogFooter>
          </div>
        ) : null}
        {step === 'partial' && read && sum ? (
          <div className="space-y-4" data-testid="import-partial">
            <p className="text-sm">{t('ics.import.partialIntro')}</p>
            <Alert variant="warn">{t('ics.import.unsupported')}</Alert>
            <ErrorDetails
              summary={
                discarded === sum.toImport + discarded && discarded > 0
                  ? t('ics.import.noneImportable')
                  : discarded === 0
                    ? t('ics.import.someUnsupported')
                    : t('ics.import.discarded', { discarded, count: sum.toImport + discarded })
              }
              rows={read.errors.map((error) => ({ component: error.component, id: error.id, kind: error.kind }))}
            />
            <DialogFooter>
              <Button type="button" variant="ghost" onClick={close}>
                {t('common.cancel')}
              </Button>
              {sum.toImport > 0 ? (
                <Button type="button" onClick={() => void start(read)} data-testid="import-continue">
                  {t('ics.import.continue')}
                </Button>
              ) : null}
            </DialogFooter>
          </div>
        ) : null}
        {step === 'importing' && sum ? (
          <div className="space-y-4">
            <p className="text-sm">{t('ics.import.dontClose')}</p>
            <ProgressBar value={sum.processed} max={sum.toProcess} label={t('ics.import.progress', { imported: sum.imported, count: sum.toImport })} />
          </div>
        ) : null}
        {step === 'done' && sum && read ? (
          <div className="space-y-4" data-testid="import-done">
            {sum.imported === sum.toImport ? (
              <p className="text-sm">{t('ics.import.success', { count: sum.imported })}</p>
            ) : (
              <Alert variant={sum.imported > 0 ? 'warn' : 'error'}>
                {sum.imported > 0 ? t('ics.import.partialSuccess', { imported: sum.imported, count: sum.toImport }) : t('ics.import.noneImported', { count: sum.toImport })}
              </Alert>
            )}
            {sum.imported > 0 ? (
              <ProgressBar value={sum.toProcess} max={sum.toProcess} label={t('ics.import.done', { imported: sum.imported, count: sum.toImport })} />
            ) : null}
            <ErrorDetails summary={t('ics.import.details')} rows={submitErrorRows(progress.errors)} />
            <DialogFooter>
              <Button type="button" onClick={close} data-testid="import-close">
                {t('ics.import.close')}
              </Button>
            </DialogFooter>
          </div>
        ) : null}
      </DialogContent>
    </Dialog>
  )
}
