import { useTranslation } from 'react-i18next'
import { Icon, ICONS } from '@/components/mobile/Icon'
import { Surface } from '@/components/ui/surface'
import { formatBytes } from '@/lib/format'
import { cn } from '@/lib/utils'

/**
 * StorageCard — "Storage · End-to-end encrypted · Upgrade" surface used on the
 * Files page (root view only) and on the Account page. Reflects current usage
 * with a horizontal progress bar.
 *
 * The "Upgrade" button is rendered but its click handler is wired by the
 * caller; in PR 2 it points at /settings or noops (no upgrade flow yet).
 */
interface StorageCardProps {
  used: number
  quota: number
  onUpgrade?: () => void
  className?: string
}

export function StorageCard({ used, quota, onUpgrade, className }: StorageCardProps) {
  const { t } = useTranslation()
  const pct = quota > 0 ? Math.min((used / quota) * 100, 100) : 0

  return (
    <Surface className={cn('p-3.5', className)}>
      <div className="flex items-center gap-2.5 mb-2.5">
        <div className="w-8 h-8 rounded-[10px] bg-primary-faint flex items-center justify-center text-primary shrink-0">
          <Icon d={ICONS.shield} size={16} />
        </div>
        <div className="flex-1">
          <div className="text-[13px] font-semibold text-text-primary">
            {t('mobile.account.storage', 'Storage')}
          </div>
          <div className="text-[11.5px] text-text-tertiary">
            {t('mobile.item.e2eBadge', 'End-to-end encrypted')}
          </div>
        </div>
        {onUpgrade && (
          <button
            type="button"
            onClick={onUpgrade}
            className="bg-transparent border border-border px-2.5 py-1 rounded-[14px] text-[12px] font-medium text-text-primary cursor-pointer hover:bg-surface-raised transition-colors"
          >
            {t('mobile.account.upgrade', 'Upgrade')}
          </button>
        )}
      </div>
      <div className="flex justify-between text-[11.5px] text-text-tertiary mb-1.5">
        <span className="font-medium">
          {t('mobile.account.storageUsed', '{{used}} used', {
            used: formatBytes(used),
          })}
        </span>
        <span>
          {t('mobile.account.storageOf', 'of {{total}}', {
            total: formatBytes(quota),
          })}
        </span>
      </div>
      <div className="h-[5px] bg-surface-sunken rounded-[3px] overflow-hidden">
        <div
          className="h-full bg-primary rounded-[3px] transition-all duration-300"
          style={{ width: `${pct}%` }}
        />
      </div>
    </Surface>
  )
}
