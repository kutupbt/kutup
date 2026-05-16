import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Loader2 } from 'lucide-react'
import { Icon, ICONS } from '@/components/mobile/Icon'
import { Surface } from '@/components/ui/surface'
import { UserListRow } from '@/components/mobile/admin/UserListRow'
import { FilterChips, type FilterOption } from '@/components/mobile/admin/FilterChips'
import { EmptyState } from '@/components/ui/empty-state'
import type { UserRow } from '@/types/api'

/**
 * MobileAdminUsersTab — search + filter chips + count + "+ New user" pill
 * + list of UserListRow.
 *
 * Filters: All / Active / Disabled / Admins / Over 75% — no "pending"
 * because kutup's UserRow has no pending status (only `isActive`). The
 * "Over 75%" filter is computed client-side from
 * `storageUsedBytes / storageQuotaBytes`.
 *
 * Tap a row → navigate to `/drive/account/admin/users/:id`.
 * Tap "New user" → navigate to `/drive/account/admin/new-user`.
 */

type FilterId = 'all' | 'active' | 'disabled' | 'admins' | 'overquota'

interface MobileAdminUsersTabProps {
  users: UserRow[] | undefined
  loading: boolean
}

export function MobileAdminUsersTab({ users, loading }: MobileAdminUsersTabProps) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState<FilterId>('all')

  const list = users ?? []
  const counts = useMemo(
    () => ({
      all: list.length,
      active: list.filter((u) => u.isActive).length,
      disabled: list.filter((u) => !u.isActive).length,
      admins: list.filter((u) => u.isAdmin).length,
      overquota: list.filter(
        (u) =>
          u.storageQuotaBytes > 0 &&
          u.storageUsedBytes / u.storageQuotaBytes > 0.75,
      ).length,
    }),
    [list],
  )

  const filtered = useMemo(() => {
    let r = list
    if (filter === 'active') r = r.filter((u) => u.isActive)
    if (filter === 'disabled') r = r.filter((u) => !u.isActive)
    if (filter === 'admins') r = r.filter((u) => u.isAdmin)
    if (filter === 'overquota')
      r = r.filter(
        (u) =>
          u.storageQuotaBytes > 0 &&
          u.storageUsedBytes / u.storageQuotaBytes > 0.75,
      )
    if (search) {
      const q = search.toLowerCase()
      r = r.filter(
        (u) =>
          u.email.toLowerCase().includes(q) ||
          u.username.toLowerCase().includes(q),
      )
    }
    return r
  }, [list, filter, search])

  const options: ReadonlyArray<FilterOption<FilterId>> = [
    { id: 'all', label: t('mobile.admin.users.filterAll', 'All'), count: counts.all },
    { id: 'active', label: t('mobile.admin.users.filterActive', 'Active'), count: counts.active },
    { id: 'disabled', label: t('mobile.admin.users.filterDisabled', 'Disabled'), count: counts.disabled },
    { id: 'admins', label: t('mobile.admin.users.filterAdmins', 'Admins'), count: counts.admins },
    { id: 'overquota', label: t('mobile.admin.users.filterOver75', 'Over 75%'), count: counts.overquota },
  ]

  return (
    <div className="px-3.5 pt-3.5 pb-8">
      {/* Count + New user pill */}
      <div className="flex items-center justify-between mb-3 gap-2">
        <div className="text-[11.5px] font-semibold tracking-[0.06em] uppercase text-text-tertiary">
          {filter === 'all' && !search
            ? t('mobile.admin.users.countAll', '{{n}} users', { n: list.length })
            : t('mobile.admin.users.countOf', '{{shown}} of {{total}}', {
                shown: filtered.length,
                total: list.length,
              })}
        </div>
        <button
          type="button"
          onClick={() => navigate('/drive/account/admin/new-user')}
          className="inline-flex items-center gap-1.5 h-8.5 px-3.5 rounded-full border-0 bg-primary text-white text-[13px] font-semibold cursor-pointer shadow-[0_2px_8px_oklch(0.40_0.18_220/0.18)] min-h-tap"
        >
          <Icon d={ICONS.userPlus} size={14} />
          {t('mobile.admin.users.newUser', 'New user')}
        </button>
      </div>

      {/* Search */}
      <div className="mb-2.5 h-9.5 rounded-[10px] bg-surface-sunken border border-border-light flex items-center px-3 gap-2">
        <Icon d={ICONS.search} size={15} color="var(--text-tertiary)" />
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder={t(
            'mobile.admin.users.searchPlaceholder',
            'Search by email or username…',
          )}
          aria-label={t('mobile.admin.users.searchPlaceholder', 'Search')}
          className="flex-1 h-full border-0 outline-none bg-transparent text-[13px] text-text-primary placeholder:text-text-tertiary"
        />
        {search && (
          <button
            type="button"
            onClick={() => setSearch('')}
            aria-label={t('mobile.admin.users.searchClear', 'Clear search')}
            className="w-6.5 h-6.5 rounded-full border-0 bg-transparent text-text-tertiary cursor-pointer flex items-center justify-center"
          >
            <Icon d={ICONS.x} size={13} />
          </button>
        )}
      </div>

      <div className="mb-3.5">
        <FilterChips value={filter} onChange={setFilter} options={options} />
      </div>

      {/* List */}
      {loading ? (
        <div className="flex justify-center py-10">
          <Loader2 className="h-5 w-5 animate-spin text-text-tertiary" />
        </div>
      ) : filtered.length === 0 ? (
        <EmptyState
          icon="users"
          title={t('mobile.admin.users.emptyTitle', 'No users match')}
          subtitle={t('mobile.admin.users.emptySubtitle', 'Try a different filter or search')}
          tint="muted"
        />
      ) : (
        <Surface>
          {filtered.map((u, i) => (
            <UserListRow
              key={u.id}
              user={u}
              onOpen={() => navigate(`/drive/account/admin/users/${u.id}`)}
              last={i === filtered.length - 1}
            />
          ))}
        </Surface>
      )}
    </div>
  )
}
