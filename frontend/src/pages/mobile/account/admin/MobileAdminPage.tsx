import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { MobileShell } from '@/components/mobile/MobileShell'
import { MobilePageHeader } from '@/components/mobile/MobilePageHeader'
import { SegmentedTabs } from '@/components/mobile/admin/SegmentedTabs'
import { MobileAdminOverviewTab } from '@/pages/mobile/account/admin/MobileAdminOverviewTab'
import { MobileAdminUsersTab } from '@/pages/mobile/account/admin/MobileAdminUsersTab'
import { MobileAdminSettingsTab } from '@/pages/mobile/account/admin/MobileAdminSettingsTab'
import { useAdminUsers, useAdminStats } from '@/api/hooks/useAdmin'
import { useIsMobile } from '@/hooks/useIsMobile'
import { useAppSelector } from '@/store'

/**
 * MobileAdminPage — `/drive/account/admin`.
 *
 * Shell for the mobile admin dashboard. Top: a `MobilePageHeader` titled
 * "Admin" with a Back chevron to the Account tab. Below: an iOS-style
 * segmented control (Overview / Users / Settings) that swaps the body
 * content beneath. Tab state lives only in this page; sub-flows (user
 * detail, create user) are real routes (`/drive/account/admin/users/:id`,
 * `.../new-user`) so they survive backgrounding + bookmarks.
 *
 * Role-gated: non-admins get redirected to /drive (the rest of the app).
 * Desktop hits redirect to /admin (the existing desktop pane covers
 * the same surface — and gets a wider screen to work with).
 */

type AdminTab = 'overview' | 'users' | 'settings'

export default function MobileAdminPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const isMobile = useIsMobile()
  const isAdmin = useAppSelector((s) => s.auth.isAdmin)
  const [tab, setTab] = useState<AdminTab>('overview')

  useEffect(() => {
    if (!isMobile) navigate('/admin', { replace: true })
  }, [isMobile, navigate])
  useEffect(() => {
    if (!isAdmin) navigate('/drive', { replace: true })
  }, [isAdmin, navigate])

  // Fetch on this shell so both Overview + Users tabs share the same
  // request (and we don't re-fetch users when switching tabs).
  const { data: stats, isLoading: statsLoading } = useAdminStats()
  const { data: users, isLoading: usersLoading } = useAdminUsers()

  if (!isMobile || !isAdmin) return null

  return (
    <MobileShell>
      <MobilePageHeader
        title={t('mobile.admin.title', 'Admin')}
        back
        onBack={() => navigate('/drive/account')}
      />
      <SegmentedTabs
        tabs={[
          { id: 'overview', label: t('mobile.admin.tabs.overview', 'Overview') },
          { id: 'users', label: t('mobile.admin.tabs.users', 'Users') },
          { id: 'settings', label: t('mobile.admin.tabs.settings', 'Settings') },
        ]}
        value={tab}
        onChange={setTab}
      />
      <div className="flex-1 overflow-auto pb-20">
        {tab === 'overview' && (
          <MobileAdminOverviewTab stats={stats} loading={statsLoading} />
        )}
        {tab === 'users' && (
          <MobileAdminUsersTab users={users} loading={usersLoading} />
        )}
        {tab === 'settings' && <MobileAdminSettingsTab />}
      </div>
    </MobileShell>
  )
}
