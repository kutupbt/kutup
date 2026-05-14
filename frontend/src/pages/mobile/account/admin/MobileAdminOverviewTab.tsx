import { useTranslation } from 'react-i18next'
import { Icon, ICONS } from '@/components/mobile/Icon'
import { KpiCard } from '@/components/mobile/admin/KpiCard'
import { formatBytes } from '@/lib/format'
import type { AdminStats } from '@/types/api'

/**
 * MobileAdminOverviewTab — 2×2 KPI grid (Total users / Active users /
 * Total files / Storage used) + an E2E reassurance card at the bottom.
 *
 * Hidden in this PR (no backend endpoint yet — see plan):
 *  - Recent activity feed
 *  - System info card (public URL / uptime / server load)
 *
 * The KPIs come straight from `GET /admin/stats`. Cards render with
 * skeleton-ish placeholders when stats are loading.
 */
interface MobileAdminOverviewTabProps {
  stats: AdminStats | undefined
  loading: boolean
}

export function MobileAdminOverviewTab({ stats, loading }: MobileAdminOverviewTabProps) {
  const { t } = useTranslation()
  const placeholder = loading ? '—' : '0'

  return (
    <div className="px-3.5 pt-4 pb-8">
      <div className="grid grid-cols-2 gap-2.5 mb-5">
        <KpiCard
          icon="users"
          label={t('mobile.admin.kpi.totalUsers', 'Total users')}
          value={stats?.totalUsers ?? placeholder}
          accent
        />
        <KpiCard
          icon="userCheck"
          label={t('mobile.admin.kpi.activeUsers', 'Active users')}
          value={stats?.activeUsers ?? placeholder}
        />
        <KpiCard
          icon="file"
          label={t('mobile.admin.kpi.totalFiles', 'Total files')}
          value={stats?.totalFiles ?? placeholder}
        />
        <KpiCard
          icon="hardDrive"
          label={t('mobile.admin.kpi.storageUsed', 'Storage used')}
          value={stats ? formatBytes(stats.totalStorageUsedBytes) : placeholder}
        />
      </div>

      {/* E2E reassurance — static. Same copy + tinted card the design uses. */}
      <div className="flex gap-2.5 p-3.5 bg-success-faint rounded-[var(--radius-lg)] border border-success/20">
        <Icon
          d={ICONS.lock}
          size={16}
          color="var(--success)"
          style={{ flexShrink: 0, marginTop: 2 }}
        />
        <div>
          <div className="text-[12.5px] font-semibold text-success">
            {t('mobile.item.e2eBadge', 'End-to-end encrypted')}
          </div>
          <div className="text-[11.5px] text-success/85 mt-0.5 leading-relaxed">
            {t(
              'mobile.admin.overview.e2eNote',
              'File names and contents are encrypted on every device. Admins can manage accounts but cannot read user data.',
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
