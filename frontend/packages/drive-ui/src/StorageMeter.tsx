import { useTranslation } from 'react-i18next'
import { useRequiredSession } from '@kutup/session/store'
import { cn } from '@kutup/ui/lib/cn'
import { formatBytes } from '@kutup/ui/lib/format'

/** Storage used of the quota Drive and Photos share, in the chrome's footer. */
export function StorageMeter() {
  const { t, i18n } = useTranslation()
  const session = useRequiredSession()
  const quota = session.storageQuotaBytes
  const used = session.storageUsedBytes
  const ratio = quota > 0 ? Math.min(1, used / quota) : 0
  const tone = ratio >= 0.95 ? 'bg-status-danger' : ratio >= 0.8 ? 'bg-status-warn' : 'bg-chrome-active'
  return (
    <div className="space-y-2 px-1">
      <div
        className="h-1.5 overflow-hidden rounded-full bg-chrome-accent"
        role="meter"
        aria-valuemin={0}
        aria-valuemax={quota}
        aria-valuenow={used}
        aria-label={t('storage.label')}
      >
        <div className={cn('h-full rounded-full', tone)} style={{ width: `${ratio * 100}%` }} />
      </div>
      <p className="text-xs text-chrome-muted">
        {t('storage.usage', {
          used: formatBytes(used, i18n.language),
          total: formatBytes(quota, i18n.language),
        })}
      </p>
    </div>
  )
}
