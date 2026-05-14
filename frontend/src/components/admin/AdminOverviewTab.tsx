import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { Icon, ICONS } from '@/components/mobile/Icon'
import { AdminKpiCard } from './AdminKpiCard'
import { EncryptionBanner } from './EncryptionBanner'
import { avatarColor, initials } from '@/components/mobile/admin/avatar'
import { formatBytes } from '@/lib/format'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'
import type { AdminStats, UserRow } from '@/types/api'

/**
 * AdminOverviewTab — KPI grid + EncryptionBanner + Top-users table.
 *
 * Honest cut vs the design's prototype: kutup has no historical-stats
 * endpoint, so no "+N this week" delta pills. No activity feed (no backend
 * endpoint). No system-status card (no backend endpoints for uptime / TLS
 * / public URL — mobile admin made the same call).
 *
 * The 5th KPI swaps the design's "API requests" (no endpoint) for kutup's
 * `totalCollections` from `/admin/stats`.
 *
 * If `storageTotalBytes > 0` the Storage KPI hint reads "of X allocated";
 * otherwise it falls back to "across all accounts" — honest about whether
 * total capacity is configured.
 */
interface AdminOverviewTabProps {
  stats: AdminStats | undefined
  statsLoading: boolean
  users: UserRow[] | undefined
  usersLoading: boolean
}

export function AdminOverviewTab({
  stats,
  statsLoading,
  users,
  usersLoading,
}: AdminOverviewTabProps) {
  const { t } = useTranslation()

  const totalUsers = stats?.totalUsers ?? 0
  const activeUsers = stats?.activeUsers ?? 0
  const totalFiles = stats?.totalFiles ?? 0
  const totalCollections = stats?.totalCollections ?? 0
  const totalUsed = stats?.totalStorageUsedBytes ?? 0
  const totalCapacity = stats?.storageTotalBytes ?? 0

  const storageHint =
    totalCapacity > 0
      ? t('admin.overview.storageHint.of', 'of {{total}} allocated', {
          total: formatBytes(totalCapacity),
        })
      : t('admin.overview.storageHint.unknown', 'across all accounts')

  const topUsers = useMemo(
    () => [...(users ?? [])].sort((a, b) => b.storageUsedBytes - a.storageUsedBytes).slice(0, 5),
    [users],
  )

  return (
    <div className="px-8 py-6">
      {/* KPI grid */}
      {statsLoading ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-3.5 mb-6">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-[120px] rounded-[var(--radius-lg)]" />
          ))}
        </div>
      ) : (
        <div
          className="grid gap-3.5 mb-6"
          style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))' }}
        >
          <AdminKpiCard
            icon="users"
            label={t('mobile.admin.kpi.totalUsers', 'Total users')}
            value={totalUsers}
            accent
          />
          <AdminKpiCard
            icon="userCheck"
            label={t('mobile.admin.kpi.activeUsers', 'Active')}
            value={activeUsers}
          />
          <AdminKpiCard
            icon="file"
            label={t('mobile.admin.kpi.totalFiles', 'Total files')}
            value={totalFiles}
          />
          <AdminKpiCard
            icon="folder"
            label={t('admin.kpi.collections', 'Collections')}
            value={totalCollections}
          />
          <AdminKpiCard
            icon="hardDrive"
            label={t('mobile.admin.kpi.storageUsed', 'Storage used')}
            value={formatBytes(totalUsed)}
            hint={storageHint}
          />
        </div>
      )}

      <EncryptionBanner />

      {/* Top users by storage */}
      <div className="bg-surface border border-border-light rounded-[var(--radius-lg)] overflow-hidden mt-6">
        <div className="flex items-center justify-between px-4 py-3 border-b border-border-light">
          <div className="text-[13.5px] font-semibold text-text-primary">
            {t('admin.overview.topUsersTitle', 'Top users by storage')}
          </div>
          {totalCapacity > 0 && (
            <div className="text-[11.5px] text-text-tertiary">
              {t('admin.overview.totalCapacity', 'Total capacity: {{total}}', {
                total: formatBytes(totalCapacity),
              })}
            </div>
          )}
        </div>
        {usersLoading ? (
          <div className="p-4 space-y-2">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        ) : topUsers.length === 0 ? (
          <div className="px-4 py-8 text-center text-[12.5px] text-text-tertiary">
            {t('admin.overview.topUsersEmpty', 'No users yet.')}
          </div>
        ) : (
          topUsers.map((u, i) => {
            const pct = u.storageQuotaBytes
              ? Math.min((u.storageUsedBytes / u.storageQuotaBytes) * 100, 100)
              : 0
            const over = pct > 75
            return (
              <div
                key={u.id}
                className={cn(
                  'grid items-center gap-3.5 px-4 py-3',
                  i < topUsers.length - 1 && 'border-b border-border-light',
                )}
                style={{
                  gridTemplateColumns: '32px 1fr 120px 160px 90px',
                }}
              >
                <div
                  className="w-7 h-7 rounded-full text-white flex items-center justify-center text-[11px] font-bold"
                  style={{ background: avatarColor(u.username) }}
                  aria-hidden="true"
                >
                  {initials(u.username)}
                </div>
                <div className="min-w-0">
                  <div className="text-[13px] font-medium text-text-primary truncate">
                    {u.email}
                  </div>
                  <div className="text-[11px] text-text-tertiary truncate">
                    @{u.username}
                  </div>
                </div>
                <div className="text-[12.5px] text-text-secondary">
                  {formatBytes(u.storageUsedBytes)}
                </div>
                <div className="h-1 bg-surface-sunken rounded-full overflow-hidden">
                  <div
                    className={cn('h-full rounded-full', over ? 'bg-warning' : 'bg-primary')}
                    style={{ width: `${Math.max(pct, 2)}%` }}
                  />
                </div>
                <div
                  className={cn(
                    'text-[12px] text-right',
                    over ? 'text-warning font-semibold' : 'text-text-tertiary',
                  )}
                >
                  {pct.toFixed(1)}%
                </div>
              </div>
            )
          })
        )}
      </div>

      {/* Subtle footnote: features the design has but kutup's backend doesn't yet */}
      <div className="flex items-center gap-1.5 mt-5 text-[11.5px] text-text-tertiary">
        <Icon d={ICONS.info} size={12} />
        <span>
          {t(
            'admin.overview.footnote',
            'Activity feed, server uptime, and TLS status are not exposed by kutup’s backend yet — they’ll appear here when the endpoints land.',
          )}
        </span>
      </div>
    </div>
  )
}
