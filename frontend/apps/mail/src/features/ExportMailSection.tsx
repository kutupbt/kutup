import { Download } from 'lucide-react'
import { useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useMailAccount, type PlaceKey } from '@kutup/mail-core/api'
import { usePlaces } from '@kutup/mail-core/places'
import { Button } from '@kutup/ui/components/button'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { apiErrorMessage } from '@kutup/ui/lib/apiError'
import { exportPlace, type ExportProgress } from './mailExport'
import { sievePlaces } from './sieveFiles'

const FIXED: PlaceKey[] = ['all', 'inbox', 'sent', 'drafts', 'archive', 'spam', 'trash']

/**
 * Settings → General → Export (Proton's Export: one .eml per message): a
 * place's mail, opened in this browser, downloaded as a zip.
 */
export function ExportMailSection() {
  const { t } = useTranslation()
  const account = useMailAccount()
  const places = usePlaces()
  const [place, setPlace] = useState<PlaceKey>('all')
  const [progress, setProgress] = useState<ExportProgress | null>(null)
  const stop = useRef<AbortController | null>(null)
  const named = sievePlaces(places.data)
  const nameOf = (key: PlaceKey) =>
    key.startsWith('folder:')
      ? (named.folders.find((f) => `folder:${f.id}` === key)?.path ?? key)
      : key.startsWith('label:')
        ? (named.labels.find((l) => `label:${l.id}` === key)?.name ?? key)
        : t(`folders.${key}`)

  async function run() {
    if (!account.data) return
    const controller = new AbortController()
    stop.current = controller
    setProgress({ done: 0, total: 0 })
    try {
      const blob = await exportPlace(account.data, place, setProgress, controller.signal)
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `Kutup Mail - ${nameOf(place).replace(/[\\/:*?"<>|]/g, '_')} - ${new Date().toISOString().slice(0, 10)}.zip`
      link.click()
      setTimeout(() => URL.revokeObjectURL(url), 60_000)
      toast.success(t('export.done'))
    } catch (error) {
      if (!controller.signal.aborted) toast.error(apiErrorMessage(error, t('export.failed')))
    } finally {
      stop.current = null
      setProgress(null)
    }
  }

  const keys: PlaceKey[] = [...FIXED, ...named.folders.map((f) => `folder:${f.id}` as const), ...named.labels.map((l) => `label:${l.id}` as const)]
  return (
    <section className="mt-8 space-y-3" aria-labelledby="export-heading">
      <h2 id="export-heading" className="text-sm font-medium">
        {t('export.title')}
      </h2>
      <p className="text-sm text-muted-foreground">{t('export.hint')}</p>
      <div className="flex flex-wrap items-center gap-2">
        <Select value={place} onValueChange={(value) => setPlace(value as PlaceKey)} disabled={progress !== null}>
          <SelectTrigger className="w-64" aria-label={t('export.place')}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {keys.map((key) => (
              <SelectItem key={key} value={key}>
                {nameOf(key)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {progress ? (
          <>
            <span className="text-sm tabular-nums text-muted-foreground" role="status">
              {t('export.progress', { done: progress.done, total: progress.total })}
            </span>
            <Button variant="outline" onClick={() => stop.current?.abort()}>
              {t('export.stop')}
            </Button>
          </>
        ) : (
          <Button variant="outline" onClick={() => void run()} disabled={!account.data}>
            <Download />
            {t('export.start')}
          </Button>
        )}
      </div>
    </section>
  )
}
