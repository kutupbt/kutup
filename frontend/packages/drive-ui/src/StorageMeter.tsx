import { useTranslation } from 'react-i18next'
import { appUrl } from '@kutup/session/apps'
import { useRequiredSession } from '@kutup/session/store'
import { cn } from '@kutup/ui/lib/cn'
import { formatBytes } from '@kutup/ui/lib/format'

/**
 * The account's one storage pool, in the chrome's footer; it opens the
 * Storage page in Account, which shows what fills it.
 */
export function StorageMeter() {
  const { t, i18n } = useTranslation()
  const session = useRequiredSession()
  const quota = session.storageQuotaBytes
  const used = session.storageUsedBytes
  const ratio = quota > 0 ? Math.min(1, used / quota) : 0
  const tone = ratio >= 0.95 ? 'bg-status-danger' : ratio >= 0.8 ? 'bg-status-warn' : 'bg-chrome-active'
  return (
    <a
      href={appUrl('account', '/settings/storage')}
      title={t('storage.details')}
      className="block space-y-2 rounded-md px-1 py-1 hover:bg-chrome-accent/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
    >
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
    </a>
  )
}
