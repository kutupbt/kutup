import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Navigate } from 'react-router-dom'
import { useAppSelector } from '@/store'
import { selectIsLoggedIn, selectIsAdmin } from '@/store/authSlice'
import { useAdminUsers, useAdminStats } from '@/api/hooks/useAdmin'
import { Icon, ICONS } from '@/components/mobile/Icon'
import { Button } from '@/components/ui/button'
import { AdminSidebar, type AdminTab } from '@/components/admin/AdminSidebar'
import { AdminTopBar } from '@/components/admin/AdminTopBar'
import { AdminOverviewTab } from '@/components/admin/AdminOverviewTab'
import { AdminUsersTab } from '@/components/admin/AdminUsersTab'
import { AdminSettingsTab } from '@/components/admin/AdminSettingsTab'
import { AdminCreateUserDialog } from '@/components/admin/AdminCreateUserDialog'

/**
 * Admin — desktop `/admin` page, redesigned per `kutup-admin.html`
 * (Claude Design handoff at `/tmp/kutup-admin-desktop-design/`).
 *
 * Shell composition:
 *
 *   ┌────────────┬───────────────────────────────────────────────┐
 *   │            │  AdminTopBar (title + subtitle + actions)    │
 *   │ AdminSide- ├───────────────────────────────────────────────┤
 *   │ bar        │                                               │
 *   │ (220px)    │   {Overview | Users | Settings}Tab            │
 *   │            │                                               │
 *   └────────────┴───────────────────────────────────────────────┘
 *
 * Tab state is local. Data hooks (`useAdminUsers`, `useAdminStats`) live
 * here so both the Overview KPI grid + Top-users + the Users-tab table
 * share one fetch (no double-request when switching tabs).
 *
 * Per kutup convention: the `AdminContent` split keeps the gating cheap
 * (one `useAppSelector` pair at the top; if the user isn't an admin we
 * redirect without running any of the admin hooks).
 */
export default function Admin() {
  const isLoggedIn = useAppSelector(selectIsLoggedIn)
  const isAdmin = useAppSelector(selectIsAdmin)

  if (!isLoggedIn) return <Navigate to="/login" replace />
  if (!isAdmin) return <Navigate to="/drive" replace />

  return <AdminContent />
}

function AdminContent() {
  const { t } = useTranslation()
  const [tab, setTab] = useState<AdminTab>('overview')
  const [createOpen, setCreateOpen] = useState(false)

  const { data: users, isLoading: usersLoading } = useAdminUsers()
  const { data: stats, isLoading: statsLoading } = useAdminStats()

  const titles: Record<AdminTab, { title: string; subtitle: string }> = {
    overview: {
      title: t('admin.topBar.overviewTitle', 'Admin Overview'),
      subtitle: t(
        'admin.topBar.overviewSubtitle',
        'kutup · self-hosted, end-to-end encrypted',
      ),
    },
    users: {
      title: t('admin.topBar.usersTitle', 'Users'),
      subtitle: t('admin.topBar.usersSubtitle', '{{count}} accounts on this instance', {
        count: users?.length ?? 0,
      }),
    },
    settings: {
      title: t('admin.topBar.settingsTitle', 'Settings'),
      subtitle: t(
        'admin.topBar.settingsSubtitle',
        'Configure registration and storage',
      ),
    },
  }

  const action =
    tab === 'users' ? (
      <Button size="sm" className="gap-1.5 h-9" onClick={() => setCreateOpen(true)}>
        <Icon d={ICONS.userPlus} size={14} />
        {t('admin.createUser', 'Create user')}
      </Button>
    ) : tab === 'overview' ? (
      <Button size="sm" className="gap-1.5 h-9" onClick={() => setCreateOpen(true)}>
        <Icon d={ICONS.userPlus} size={14} />
        {t('admin.createUser', 'Create user')}
      </Button>
    ) : null

  return (
    <div className="flex min-h-screen bg-background">
      <AdminSidebar tab={tab} onTab={setTab} />

      <main className="flex-1 flex flex-col min-w-0">
        <AdminTopBar
          title={titles[tab].title}
          subtitle={titles[tab].subtitle}
          action={action}
        />

        <div className="flex-1 overflow-auto">
          {tab === 'overview' && (
            <AdminOverviewTab
              stats={stats}
              statsLoading={statsLoading}
              users={users}
              usersLoading={usersLoading}
            />
          )}
          {tab === 'users' && (
            <AdminUsersTab
              users={users}
              loading={usersLoading}
              onCreate={() => setCreateOpen(true)}
            />
          )}
          {tab === 'settings' && <AdminSettingsTab />}
        </div>
      </main>

      <AdminCreateUserDialog open={createOpen} onOpenChange={setCreateOpen} />
    </div>
  )
}
