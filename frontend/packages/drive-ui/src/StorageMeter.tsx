import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { storageLevel, usageCategories, useStorageUsage } from '@kutup/drive-core/storage'
import { appUrl } from '@kutup/session/apps'
import { useRequiredSession } from '@kutup/session/store'
import { Button } from '@kutup/ui/components/button'
import { Donut } from '@kutup/ui/components/donut'
import { Popover, PopoverContent, PopoverTrigger } from '@kutup/ui/components/popover'
import { Skeleton } from '@kutup/ui/components/skeleton'
import { cn } from '@kutup/ui/lib/cn'
import { formatBytes } from '@kutup/ui/lib/format'

const LEVEL_BAR = { ok: 'bg-chrome-active', warning: 'bg-status-warn', danger: 'bg-status-danger' } as const
const LEVEL_RING = { ok: 'var(--primary)', warning: 'var(--status-warn)', danger: 'var(--status-danger)' } as const

/**
 * The account's one storage pool, in the chrome's footer. Like Proton's
 * sidebar meter it reads "X of Y"; clicking it opens a summary of what fills
 * the pool, with the way to free space and to the full Storage page in
 * Account.
 */
export function StorageMeter() {
  const { t, i18n } = useTranslation()
  const session = useRequiredSession()
  const [open, setOpen] = useState(false)
  const quota = session.storageQuotaBytes
  const used = session.storageUsedBytes
  const ratio = quota > 0 ? Math.min(1, used / quota) : 0
  const level = storageLevel({ quotaBytes: quota, usedBytes: used, reservedBytes: 0 })
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button
          type="button"
          className="block w-full space-y-2 rounded-md px-1 py-1 text-left hover:bg-chrome-accent/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          aria-label={t('storage.open', {
            used: formatBytes(used, i18n.language),
            total: formatBytes(quota, i18n.language),
          })}
        >
          <div
            className="h-1.5 overflow-hidden rounded-full bg-chrome-accent"
            role="meter"
            aria-valuemin={0}
            aria-valuemax={quota}
            aria-valuenow={used}
            aria-label={t('storage.label')}
          >
            <div className={cn('h-full rounded-full', LEVEL_BAR[level])} style={{ width: `${ratio * 100}%` }} />
          </div>
          <p className="text-xs text-chrome-muted">
            {t('storage.usage', {
              used: formatBytes(used, i18n.language),
              total: formatBytes(quota, i18n.language),
            })}
          </p>
        </button>
      </PopoverTrigger>
      <PopoverContent side="top" align="start">
        <StorageSummary enabled={open} />
      </PopoverContent>
    </Popover>
  )
}

function StorageSummary({ enabled }: { enabled: boolean }) {
  const { t, i18n } = useTranslation()
  const lang = i18n.language
  const usage = useStorageUsage(enabled)
  if (!usage.data) {
    return usage.isError ? <p className="text-sm text-muted-foreground">{t('storage.unavailable')}</p> : <Skeleton className="h-40 w-full" />
  }
  const data = usage.data
  const level = storageLevel(data)
  const quota = Math.max(data.quotaBytes, 1)
  const top = usageCategories(data).slice(0, 4)
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Donut
          className="size-12 shrink-0"
          thickness={0.2}
          minPercent={3}
          segments={[[((data.usedBytes + data.reservedBytes) / quota) * 100, LEVEL_RING[level]]]}
        />
        <div className="min-w-0">
          <p className="text-sm font-medium">{t('storage.title')}</p>
          <p className="text-sm">
            <span className="font-semibold tabular-nums">{formatBytes(data.usedBytes, lang)}</span>{' '}
            <span className="text-muted-foreground">{t('storage.ofQuota', { total: formatBytes(data.quotaBytes, lang) })}</span>
          </p>
        </div>
      </div>
      {level !== 'ok' ? (
        <p className={cn('text-sm', level === 'danger' ? 'text-destructive' : 'text-foreground')}>{t(`storage.level.${level}`)}</p>
      ) : null}
      {top.length > 0 ? (
        <ul className="space-y-1.5 text-sm">
          {top.map((c) => (
            <li key={c.id} className="flex items-center gap-2">
              <span aria-hidden className="size-2.5 shrink-0 rounded-full" style={{ background: c.color }} />
              <span className="min-w-0 flex-1 truncate">{t(`storage.categories.${c.id}`)}</span>
              <span className="tabular-nums text-muted-foreground">{formatBytes(c.bytes, lang)}</span>
            </li>
          ))}
        </ul>
      ) : null}
      <p className="text-xs text-muted-foreground">{t('storage.shared')}</p>
      <div className="flex flex-wrap justify-end gap-2">
        <Button asChild variant="outline" size="sm">
          <a href={appUrl('account', '/settings/storage?cleanup=1')}>{t('storage.freeUp')}</a>
        </Button>
        <Button asChild size="sm">
          <a href={appUrl('account', '/settings/storage')}>{t('storage.details')}</a>
        </Button>
      </div>
    </div>
  )
}
