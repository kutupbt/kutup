import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Icon, ICONS } from '@/components/mobile/Icon'
import { Skeleton } from '@/components/ui/skeleton'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { FilterChips, type FilterOption } from '@/components/mobile/admin/FilterChips'
import { StatusPill } from '@/components/mobile/admin/StatusPill'
import { RolePill } from '@/components/mobile/admin/RolePill'
import { avatarColor, initials } from '@/components/mobile/admin/avatar'
import { formatBytes } from '@/lib/format'
import { useUpdateUser, useDeleteUser, useForceDisable2fa } from '@/api/hooks/useAdmin'
import { cn } from '@/lib/utils'
import { AdminUserMenu, type AdminUserMenuState, type AdminMenuAction } from './AdminUserMenu'
import { AdminEditQuotaDialog } from './AdminEditQuotaDialog'
import { usersToCsv, downloadCsv } from './csv'
import type { UserRow } from '@/types/api'

/**
 * AdminUsersTab — desktop Users list with search + filter chips + sortable
 * columns + Export CSV + pagination + per-row ⋯ menu.
 *
 * Per the design's chat2 rule and kutup's actual backend:
 *  - **5 filter chips** (not 6 — kutup has no "Pending" status, only `isActive`).
 *  - **Sortable** columns: User (email), Status (isActive), Storage (used),
 *    2FA (totpEnabled), Joined (createdAt). No `lastActive` — not in the schema.
 *  - **Export CSV** is client-side (no backend export endpoint needed).
 *  - **Pagination** is client-side, 25 per page — fits today's user counts.
 *  - **Make/Remove admin + Force-disable 2FA** are wired end-to-end; the
 *    break-glass admin (`isProtected`) can't be demoted/disabled/deleted.
 */

const PAGE_SIZE = 25

type FilterId = 'all' | 'active' | 'disabled' | 'admins' | 'overquota'
type SortBy = 'email' | 'isActive' | 'storageUsedBytes' | 'totpEnabled' | 'createdAt'
type SortDir = 'asc' | 'desc'

interface AdminUsersTabProps {
  users: UserRow[] | undefined
  loading: boolean
  /** Opens the AdminCreateUserDialog (parent owns its state). */
  onCreate: () => void
}

export function AdminUsersTab({ users, loading, onCreate }: AdminUsersTabProps) {
  const { t } = useTranslation()
  const updateUser = useUpdateUser()
  const deleteUser = useDeleteUser()
  const forceDisable2fa = useForceDisable2fa()

  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState<FilterId>('all')
  const [sortBy, setSortBy] = useState<SortBy>('createdAt')
  const [sortDir, setSortDir] = useState<SortDir>('desc')
  const [page, setPage] = useState(1)
  const [menu, setMenu] = useState<AdminUserMenuState | null>(null)
  const [editTarget, setEditTarget] = useState<UserRow | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<UserRow | null>(null)
  const [adminTarget, setAdminTarget] = useState<UserRow | null>(null)
  const [totpTarget, setTotpTarget] = useState<UserRow | null>(null)
  const [hoveredId, setHoveredId] = useState<string | null>(null)

  const counts = useMemo(() => {
    const list = users ?? []
    return {
      all: list.length,
      active: list.filter((u) => u.isActive).length,
      disabled: list.filter((u) => !u.isActive).length,
      admins: list.filter((u) => u.isAdmin).length,
      overquota: list.filter(
        (u) => u.storageQuotaBytes > 0 && u.storageUsedBytes / u.storageQuotaBytes > 0.75,
      ).length,
    }
  }, [users])

  const filterOptions: ReadonlyArray<FilterOption<FilterId>> = [
    { id: 'all', label: t('mobile.admin.users.filterAll', 'All'), count: counts.all },
    { id: 'active', label: t('mobile.admin.users.filterActive', 'Active'), count: counts.active },
    {
      id: 'disabled',
      label: t('mobile.admin.users.filterDisabled', 'Disabled'),
      count: counts.disabled,
    },
    { id: 'admins', label: t('mobile.admin.users.filterAdmins', 'Admins'), count: counts.admins },
    {
      id: 'overquota',
      label: t('mobile.admin.users.filterOver75', 'Over 75%'),
      count: counts.overquota,
    },
  ]

  const filtered = useMemo(() => {
    let r = users ?? []
    if (filter === 'active') r = r.filter((u) => u.isActive)
    else if (filter === 'disabled') r = r.filter((u) => !u.isActive)
    else if (filter === 'admins') r = r.filter((u) => u.isAdmin)
    else if (filter === 'overquota')
      r = r.filter(
        (u) => u.storageQuotaBytes > 0 && u.storageUsedBytes / u.storageQuotaBytes > 0.75,
      )

    if (search) {
      const q = search.toLowerCase()
      r = r.filter(
        (u) => u.email.toLowerCase().includes(q) || u.username.toLowerCase().includes(q),
      )
    }

    const sorted = [...r].sort((a, b) => {
      let va: string | number | boolean = a[sortBy]
      let vb: string | number | boolean = b[sortBy]
      if (typeof va === 'string') va = va.toLowerCase()
      if (typeof vb === 'string') vb = vb.toLowerCase()
      const cmp = va < vb ? -1 : va > vb ? 1 : 0
      return sortDir === 'asc' ? cmp : -cmp
    })

    return sorted
  }, [users, filter, search, sortBy, sortDir])

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
  const currentPage = Math.min(page, totalPages)
  const paged = useMemo(
    () => filtered.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE),
    [filtered, currentPage],
  )

  function sortClick(col: SortBy) {
    if (sortBy === col) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    else {
      setSortBy(col)
      setSortDir('asc')
    }
    setPage(1)
  }

  function openMenu(e: React.MouseEvent, user: UserRow) {
    e.preventDefault()
    e.stopPropagation()
    setMenu({ x: e.clientX, y: e.clientY, user })
  }

  function onAction(action: AdminMenuAction, user: UserRow) {
    // Every action is wired end-to-end. Promote/demote + force-disable-2FA
    // open a confirm dialog; toggleActive is reversible so it applies
    // directly; delete + editQuota have their own dialogs.
    if (action === 'editQuota') {
      setEditTarget(user)
    } else if (action === 'toggleActive') {
      updateUser.mutate({ id: user.id, body: { isActive: !user.isActive } })
    } else if (action === 'toggleAdmin') {
      setAdminTarget(user)
    } else if (action === 'disableTotp') {
      setTotpTarget(user)
    } else if (action === 'delete') {
      setDeleteTarget(user)
    }
  }

  function onExportCsv() {
    const csv = usersToCsv(filtered)
    const date = new Date().toISOString().slice(0, 10)
    downloadCsv(`kutup-users-${date}.csv`, csv)
  }

  return (
    <div className="px-8 py-6">
      {/* Search + filters + Export */}
      <div className="flex items-center gap-3.5 mb-4 flex-wrap">
        <div className="flex-1 min-w-[240px] max-w-[360px] h-9 flex items-center gap-2 px-3.5 rounded-[19px] border border-border bg-surface">
          <Icon d={ICONS.search} size={15} color="var(--text-tertiary)" />
          <input
            value={search}
            onChange={(e) => {
              setSearch(e.target.value)
              setPage(1)
            }}
            placeholder={t(
              'mobile.admin.users.searchPlaceholder',
              'Search by email or username…',
            )}
            className="flex-1 border-0 outline-none bg-transparent text-[13.5px] text-text-primary placeholder:text-text-tertiary"
          />
          {search && (
            <button
              onClick={() => setSearch('')}
              className="w-[22px] h-[22px] rounded-full border-0 cursor-pointer bg-border text-surface flex items-center justify-center"
              aria-label={t('mobile.admin.users.searchClear', 'Clear search')}
            >
              <Icon d={ICONS.x} size={11} />
            </button>
          )}
        </div>

        <div className="flex-1 min-w-[200px]">
          <FilterChips
            value={filter}
            onChange={(v) => {
              setFilter(v)
              setPage(1)
            }}
            options={filterOptions}
          />
        </div>

        <Button variant="outline" size="sm" onClick={onExportCsv} className="gap-1.5 h-9">
          <Icon d={ICONS.download} size={14} />
          {t('admin.users.exportCsv', 'Export CSV')}
        </Button>
      </div>

      {/* Table */}
      <div className="bg-surface border border-border-light rounded-[var(--radius-lg)] overflow-hidden">
        {loading ? (
          <div className="p-4 space-y-2">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-12 w-full" />
            ))}
          </div>
        ) : (
          <table className="w-full border-collapse">
            <thead>
              <tr className="bg-surface-raised">
                <SortHeader col="email" onClick={sortClick} active={sortBy === 'email'} dir={sortDir}>
                  {t('admin.users.column.user', 'User')}
                </SortHeader>
                <SortHeader
                  col="isActive"
                  onClick={sortClick}
                  active={sortBy === 'isActive'}
                  dir={sortDir}
                >
                  {t('admin.users.column.status', 'Status')}
                </SortHeader>
                <SortHeader
                  col="storageUsedBytes"
                  onClick={sortClick}
                  active={sortBy === 'storageUsedBytes'}
                  dir={sortDir}
                >
                  {t('admin.users.column.storage', 'Storage')}
                </SortHeader>
                <SortHeader
                  col="totpEnabled"
                  onClick={sortClick}
                  active={sortBy === 'totpEnabled'}
                  dir={sortDir}
                >
                  {t('admin.users.column.totp', '2FA')}
                </SortHeader>
                <SortHeader
                  col="createdAt"
                  onClick={sortClick}
                  active={sortBy === 'createdAt'}
                  dir={sortDir}
                >
                  {t('admin.users.column.joined', 'Joined')}
                </SortHeader>
                <th className="border-b border-border-light" aria-hidden="true" />
              </tr>
            </thead>
            <tbody>
              {paged.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-10 text-center text-[13px] text-text-tertiary">
                    {t('mobile.admin.users.emptyTitle', 'No users match')}
                  </td>
                </tr>
              ) : (
                paged.map((u) => {
                  const pct = u.storageQuotaBytes
                    ? Math.min((u.storageUsedBytes / u.storageQuotaBytes) * 100, 100)
                    : 0
                  const over = pct > 75
                  const hov = hoveredId === u.id
                  return (
                    <tr
                      key={u.id}
                      onMouseEnter={() => setHoveredId(u.id)}
                      onMouseLeave={() => setHoveredId(null)}
                      onContextMenu={(e) => openMenu(e, u)}
                      className={cn(
                        'transition-colors',
                        hov ? 'bg-surface-raised' : 'bg-transparent',
                      )}
                    >
                      <td className="px-4 py-3 border-b border-border-light">
                        <div className="flex items-center gap-3">
                          <div
                            className="w-8 h-8 rounded-full text-white flex items-center justify-center text-[12px] font-bold shrink-0"
                            style={{ background: avatarColor(u.username) }}
                            aria-hidden="true"
                          >
                            {initials(u.username)}
                          </div>
                          <div className="min-w-0">
                            <div className="flex items-center gap-1.5">
                              <span className="text-[13.5px] font-medium text-text-primary truncate">
                                {u.email}
                              </span>
                              <RolePill isAdmin={u.isAdmin} />
                              {u.isProtected && <BreakGlassBadge />}
                            </div>
                            <div className="text-[11.5px] text-text-tertiary truncate mt-px">
                              @{u.username}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3 border-b border-border-light">
                        <StatusPill active={u.isActive} />
                      </td>
                      <td className="px-4 py-3 border-b border-border-light">
                        <div className="flex flex-col gap-1 min-w-[140px]">
                          <div className="flex justify-between text-[11.5px]">
                            <span className="text-text-secondary font-medium">
                              {formatBytes(u.storageUsedBytes)}
                            </span>
                            <span className="text-text-tertiary">
                              {formatBytes(u.storageQuotaBytes)}
                            </span>
                          </div>
                          <div className="h-1 bg-surface-sunken rounded-full overflow-hidden">
                            <div
                              className={cn(
                                'h-full rounded-full',
                                over ? 'bg-warning' : 'bg-primary',
                              )}
                              style={{ width: `${Math.max(pct, 2)}%` }}
                            />
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3 border-b border-border-light text-[12.5px] text-text-secondary">
                        {u.totpEnabled ? (
                          <span className="inline-flex items-center gap-1 text-success font-medium">
                            <Icon d={ICONS.key} size={12} />
                            {t('admin.users.totpEnabled', 'Enabled')}
                          </span>
                        ) : (
                          <span className="text-text-tertiary">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3 border-b border-border-light text-[12.5px] text-text-secondary">
                        {new Date(u.createdAt).toLocaleDateString()}
                      </td>
                      <td className="px-4 py-3 border-b border-border-light text-right">
                        <button
                          onClick={(e) => openMenu(e, u)}
                          className={cn(
                            'w-[30px] h-[30px] rounded-full border-0 cursor-pointer text-text-tertiary inline-flex items-center justify-center transition-opacity',
                            hov
                              ? 'opacity-100 bg-surface'
                              : 'opacity-40 bg-transparent',
                          )}
                          aria-label={t('admin.users.menuLabel', 'Actions')}
                        >
                          <Icon d={ICONS.more} size={16} />
                        </button>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        )}

        {/* Footer */}
        <div className="flex items-center justify-between px-4 py-2.5 text-[12px] text-text-tertiary bg-surface-raised border-t border-border-light">
          <span>
            {t('admin.users.showing', 'Showing {{count}} of {{total}}', {
              count: filtered.length,
              total: counts.all,
            })}
          </span>
          <div className="flex items-center gap-1.5">
            <Button
              variant="outline"
              size="sm"
              disabled={currentPage <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              className="gap-1 h-7"
            >
              <Icon d={ICONS.chevronLeft} size={11} />
              {t('admin.users.prev', 'Prev')}
            </Button>
            <span className="px-2">
              {t('admin.users.pageOf', 'Page {{current}} of {{total}}', {
                current: currentPage,
                total: totalPages,
              })}
            </span>
            <Button
              variant="outline"
              size="sm"
              disabled={currentPage >= totalPages}
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              className="gap-1 h-7"
            >
              {t('admin.users.next', 'Next')}
              <Icon d={ICONS.chevronRight} size={11} />
            </Button>
          </div>
        </div>
      </div>

      {/* "+ New user" footer pill — sticks below the table for one-click access */}
      <div className="mt-3.5 flex justify-end">
        <Button onClick={onCreate} size="sm" className="gap-1.5 h-9">
          <Icon d={ICONS.userPlus} size={14} />
          {t('mobile.admin.users.newUser', 'New user')}
        </Button>
      </div>

      {/* Per-row menu (positioned popover) */}
      <AdminUserMenu menu={menu} onClose={() => setMenu(null)} onAction={onAction} />

      {/* Edit-quota dialog */}
      <AdminEditQuotaDialog user={editTarget} onClose={() => setEditTarget(null)} />

      {/* Delete confirm */}
      <AlertDialog
        open={deleteTarget !== null}
        onOpenChange={(open) => {
          if (!open) setDeleteTarget(null)
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t('admin.deleteDialog.title', 'Delete {{email}}?', {
                email: deleteTarget?.email ?? '',
              })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t(
                'admin.deleteDialog.desc',
                'This permanently removes the user and all their data. This action cannot be undone.',
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('admin.deleteDialog.cancel', 'Cancel')}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => {
                if (deleteTarget) deleteUser.mutate(deleteTarget.id)
                setDeleteTarget(null)
              }}
            >
              {t('admin.deleteDialog.confirm', 'Delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Promote / demote confirm */}
      <AlertDialog
        open={adminTarget !== null}
        onOpenChange={(open) => {
          if (!open) setAdminTarget(null)
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {adminTarget?.isAdmin
                ? t('admin.adminDialog.demoteTitle', 'Remove admin from {{email}}?', {
                    email: adminTarget?.email ?? '',
                  })
                : t('admin.adminDialog.promoteTitle', 'Make {{email}} an admin?', {
                    email: adminTarget?.email ?? '',
                  })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {adminTarget?.isAdmin
                ? t(
                    'admin.adminDialog.demoteDesc',
                    'They lose access to this admin panel. Takes effect on their next sign-in or token refresh.',
                  )
                : t(
                    'admin.adminDialog.promoteDesc',
                    'They gain full access to this admin panel — managing users, settings, and storage. Takes effect on their next sign-in or token refresh.',
                  )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('admin.deleteDialog.cancel', 'Cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (adminTarget) {
                  updateUser.mutate({
                    id: adminTarget.id,
                    body: { isAdmin: !adminTarget.isAdmin },
                  })
                }
                setAdminTarget(null)
              }}
            >
              {adminTarget?.isAdmin
                ? t('admin.users.menu.removeAdmin', 'Remove admin role')
                : t('admin.users.menu.makeAdmin', 'Make admin')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Force-disable 2FA confirm */}
      <AlertDialog
        open={totpTarget !== null}
        onOpenChange={(open) => {
          if (!open) setTotpTarget(null)
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t('admin.totpDialog.title', 'Disable 2FA for {{email}}?', {
                email: totpTarget?.email ?? '',
              })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t(
                'admin.totpDialog.desc',
                'This makes the account password-only until the user re-enables 2FA from their Security page. Use this when a user is locked out of their authenticator.',
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('admin.deleteDialog.cancel', 'Cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (totpTarget) forceDisable2fa.mutate(totpTarget.id)
                setTotpTarget(null)
              }}
            >
              {t('admin.users.menu.disableTotp', 'Disable 2FA')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

/* ── Break-glass badge ──────────────────────────────────────────── */

function BreakGlassBadge() {
  const { t } = useTranslation()
  return (
    <span
      className="text-[10px] font-bold tracking-[0.04em] uppercase bg-warning-faint text-warning px-1.5 py-0.5 rounded-md"
      title={t(
        'admin.breakGlass.tooltip',
        'Break-glass admin — protected from demote, disable, and delete.',
      )}
    >
      {t('admin.breakGlass.badge', 'Break-glass')}
    </span>
  )
}

/* ── Sortable column header ─────────────────────────────────────── */

interface SortHeaderProps {
  col: SortBy
  active: boolean
  dir: SortDir
  onClick: (col: SortBy) => void
  children: React.ReactNode
}

function SortHeader({ col, active, dir, onClick, children }: SortHeaderProps) {
  return (
    <th
      onClick={() => onClick(col)}
      className={cn(
        'text-left px-4 py-2.5 cursor-pointer select-none',
        'text-[11.5px] font-semibold tracking-[0.04em] uppercase',
        'border-b border-border-light',
        active ? 'text-text-primary' : 'text-text-tertiary',
      )}
    >
      <span className="inline-flex items-center gap-1">
        {children}
        {active && <Icon d={ICONS[dir === 'asc' ? 'chevronUp' : 'chevronDown']} size={12} />}
      </span>
    </th>
  )
}
