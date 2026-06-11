import { useTranslation } from 'react-i18next'
import { Icon, ICONS } from '@/components/mobile/Icon'
import { KpiCard } from '@/components/mobile/admin/KpiCard'
import { activityText, activityIcon } from '@/components/admin/activity'
import { useAdminActivity } from '@/api/hooks/useAdmin'
import { formatBytes } from '@/lib/format'
import { formatTimeAgo } from '@/components/mobile/dateFormat'
import type { AdminStats } from '@/types/api'

/**
 * MobileAdminOverviewTab — 2×2 KPI grid (Total users / Active users /
 * Total files / Storage used) + the Recent-activity feed (the admin audit
 * log via `GET /admin/activity`) + an E2E reassurance card at the bottom.
 *
 * Still hidden (no backend endpoint yet — see docs/roadmap.md):
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
  const { data: activity } = useAdminActivity(5)

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

      {/* Recent activity — the admin audit log */}
      <div
        data-testid="admin-activity"
        className="bg-surface border border-border-light rounded-[var(--radius-lg)] overflow-hidden mb-5"
      >
        <div className="px-3.5 py-2.5 border-b border-border-light text-[12.5px] font-semibold text-text-primary">
          {t('admin.activity.title', 'Recent activity')}
        </div>
        {!activity || activity.entries.length === 0 ? (
          <div className="px-3.5 py-6 text-center text-[12px] text-text-tertiary">
            {t('admin.activity.empty', 'No admin actions recorded yet.')}
          </div>
        ) : (
          activity.entries.map((e, i) => (
            <div
              key={e.id}
              className={
                'flex items-center gap-2.5 px-3.5 py-2.5' +
                (i < activity.entries.length - 1 ? ' border-b border-border-light' : '')
              }
            >
              <div className="w-6 h-6 rounded-full bg-surface-sunken text-text-tertiary flex items-center justify-center shrink-0">
                <Icon d={activityIcon(e.action)} size={11} />
              </div>
              <div className="min-w-0 flex-1 text-[12px] text-text-secondary truncate">
                {activityText(e, t)}
              </div>
              <div className="text-[11px] text-text-tertiary whitespace-nowrap">
                {formatTimeAgo(e.occurredAt)}
              </div>
            </div>
          ))
        )}
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
