import { useEffect } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Icon, ICONS } from '@/components/mobile/Icon'
import { MobileAccountSubPage } from '@/pages/mobile/account/MobileAccountSubPage'
import { Surface } from '@/components/ui/surface'
import { PressableRow } from '@/components/ui/pressable-row'
import { useAppSelector } from '@/store'

/**
 * MobileAdminPage — `/drive/account/admin`.
 *
 * Admin role-gated. The full Admin pane (users / storage / system) is a
 * desktop page (`/admin`); this mobile entry surfaces the most-common
 * actions (or just links into the desktop view) so Account's "Admin" row
 * has a real destination instead of bouncing to Settings.
 */
export default function MobileAdminPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const auth = useAppSelector((s) => s.auth)

  // Hard-gate on the admin role: non-admins get bounced to Account.
  if (!auth.isAdmin) return <Navigate to="/drive/account" replace />

  // Trigger handler kept separate from the bouncing useEffect so any link
  // to a future mobile-native admin page can replace `() => navigate('/admin')`
  // without touching the page chrome.
  useEffect(() => {
    // No-op for now — page renders normally; PR 11 (or sooner) ships mobile
    // admin slices.
  }, [])

  return (
    <MobileAccountSubPage title={t('mobile.account.admin', 'Admin')}>
      <Surface className="mb-4">
        <PressableRow
          onClick={() => navigate('/admin')}
          last
          ariaLabel={t('mobile.account.admin.open', 'Open admin dashboard')}
        >
          <div className="w-8 h-8 rounded-[10px] bg-primary-faint text-primary flex items-center justify-center shrink-0">
            <Icon d={ICONS.shield} size={16} />
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-sm font-medium text-text-primary">
              {t('mobile.account.admin.open', 'Open admin dashboard')}
            </div>
            <div className="text-[12px] text-text-tertiary mt-0.5">
              {t(
                'mobile.account.admin.openSub',
                'Manage users, storage and system settings',
              )}
            </div>
          </div>
          <Icon d={ICONS.chevronRight} size={16} color="var(--text-tertiary)" />
        </PressableRow>
      </Surface>

      <p className="text-[12px] text-text-tertiary px-1">
        {t(
          'mobile.account.admin.note',
          'The full admin pane is desktop-only for now — a mobile-native version is on the roadmap.',
        )}
      </p>
    </MobileAccountSubPage>
  )
}
