import { Check, ChevronDown, ChevronUp, CircleAlert, X } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { cn } from '@kutup/ui/lib/cn'
import { formatBytes } from '@kutup/ui/lib/format'
import { uploads, useUploads, type UploadJob } from './uploadStore'

function JobRow({ job }: { job: UploadJob }) {
  const { t, i18n } = useTranslation()
  const ratio = job.total > 0 ? Math.min(1, job.sent / job.total) : job.status === 'done' ? 1 : 0
  const active = job.status === 'queued' || job.status === 'uploading'
  return (
    <li className="space-y-1.5 px-4 py-2.5">
      <div className="flex items-center gap-2 text-sm">
        <span className="min-w-0 flex-1 truncate" title={job.name}>{job.name}</span>
        {job.status === 'done' ? <Check className="size-4 text-status-ok" aria-label={t('uploads.done')} /> : null}
        {job.status === 'failed' ? <CircleAlert className="size-4 text-destructive" aria-hidden /> : null}
        {active ? (
          <Button variant="ghost" size="icon" className="size-7" aria-label={t('uploads.cancel', { name: job.name })} onClick={() => uploads.cancel(job.id)}>
            <X />
          </Button>
        ) : null}
      </div>
      {active ? (
        <div className="h-1 overflow-hidden rounded-full bg-muted" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(ratio * 100)} aria-label={job.name}>
          <div className={cn('h-full rounded-full bg-primary transition-[width]', job.status === 'queued' && 'bg-muted-foreground/30')} style={{ width: `${ratio * 100}%` }} />
        </div>
      ) : null}
      <p className={cn('text-xs text-muted-foreground', job.status === 'failed' && 'text-destructive')}>
        {job.status === 'failed'
          ? t(`uploads.failure.${job.failure ?? 'other'}`)
          : job.status === 'cancelled'
            ? t('uploads.cancelled')
            : job.status === 'queued'
              ? t('uploads.waiting')
              : job.status === 'done'
                ? t('uploads.intoFolder', { folder: job.folderName })
                : t('uploads.progress', { sent: formatBytes(job.sent, i18n.language), total: formatBytes(job.total, i18n.language) })}
      </p>
    </li>
  )
}

/** The upload queue, bottom-right, while there is anything to show. */
export function UploadPanel() {
  const { t } = useTranslation()
  const jobs = useUploads()
  const [collapsed, setCollapsed] = useState(false)
  if (jobs.length === 0) return null
  const active = jobs.filter((j) => j.status === 'queued' || j.status === 'uploading').length
  const failed = jobs.filter((j) => j.status === 'failed').length

  return (
    <section
      aria-label={t('uploads.title')}
      className="fixed bottom-4 right-4 z-40 w-[min(22rem,calc(100vw-2rem))] overflow-hidden rounded-lg border border-border bg-popover text-popover-foreground shadow-lg"
    >
      <header className="flex items-center gap-2 border-b border-border px-4 py-2.5">
        <p className="min-w-0 flex-1 text-sm font-medium">
          {active > 0
            ? t('uploads.uploading', { count: active })
            : failed > 0
              ? t('uploads.someFailed', { count: failed })
              : t('uploads.allDone')}
        </p>
        <Button variant="ghost" size="icon" className="size-7" aria-label={collapsed ? t('uploads.expand') : t('uploads.collapse')} onClick={() => setCollapsed((c) => !c)}>
          {collapsed ? <ChevronUp /> : <ChevronDown />}
        </Button>
        <Button
          variant="ghost"
          size="icon"
          className="size-7"
          aria-label={active > 0 ? t('uploads.cancelAll') : t('common.close')}
          onClick={() => (active > 0 ? uploads.cancelAll() : uploads.clearFinished())}
        >
          <X />
        </Button>
      </header>
      {!collapsed ? <ul className="max-h-72 divide-y divide-border overflow-y-auto">{jobs.map((j) => <JobRow key={j.id} job={j} />)}</ul> : null}
    </section>
  )
}
