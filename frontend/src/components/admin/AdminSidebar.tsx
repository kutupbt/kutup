import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { Icon, ICONS, type IconName } from '@/components/mobile/Icon'
import { KutupLogo } from '@/components/KutupLogo'
import { useAppDispatch, useAppSelector } from '@/store'
import { logout } from '@/store/authSlice'
import { useTheme } from '@/hooks/useTheme'
import { broadcastLogout } from '@/lib/sessionSync'
import * as sessionVault from '@/lib/sessionVault'
import { cn } from '@/lib/utils'

/**
 * AdminSidebar — left rail for the desktop `/admin` page.
 *
 * Different chrome from the Drive Sidebar on purpose: admin is its own
 * surface (a different kind of page), so the design ships a dedicated
 * sidebar that just has a "← Drive" escape hatch + the three admin tabs
 * + the user card at the bottom. Reuses kutup's existing auth/logout/theme
 * plumbing (`useAppSelector`, `dispatch(logout())`, `useTheme`,
 * `broadcastLogout`, `sessionVault.clear`) so behavior matches the rest
 * of the app exactly.
 *
 * Distinct from the Drive Sidebar (`components/layout/Sidebar.tsx`):
 *  - No Drive state (`viewMode`, callbacks). Just a tab string.
 *  - Drive nav rows collapse into a single "← Drive" row at the top.
 *  - 2FA reminder card only shows if the admin hasn't enabled TOTP yet.
 */

export type AdminTab = 'overview' | 'users' | 'settings'

interface AdminSidebarProps {
  tab: AdminTab
  onTab: (t: AdminTab) => void
}

export function AdminSidebar({ tab, onTab }: AdminSidebarProps) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const dispatch = useAppDispatch()
  const auth = useAppSelector((s) => s.auth)
  const [theme, toggleTheme] = useTheme()
  const isDark = theme === 'dark'

  const username = auth.username ?? auth.email ?? ''
  const email = auth.email ?? ''
  const initial = (username || '?').slice(0, 1).toUpperCase()

  async function handleLogout() {
    broadcastLogout()
    try {
      await sessionVault.clear()
    } catch {
      // best-effort; logout proceeds regardless
    }
    dispatch(logout())
    navigate('/login')
  }

  return (
    <aside className="w-[220px] h-screen bg-surface-sunken border-r border-border flex flex-col shrink-0 sticky top-0">
      {/* Logo */}
      <div className="flex items-center gap-2 px-4 pt-4 pb-3">
        <KutupLogo size={26} />
        <span className="text-[17px] font-bold text-primary tracking-[-0.3px]">
          Kutup
        </span>
      </div>
      <div className="h-px bg-border-light mx-3 mb-2" />

      {/* Back to Drive */}
      <nav className="px-2 flex flex-col gap-0.5">
        <NavRow
          icon="folder"
          label={t('admin.sidebar.drive', '← Drive')}
          onClick={() => navigate('/drive')}
        />
      </nav>

      {/* Admin tabs */}
      <div className="pt-3.5 pb-1.5 px-2">
        <div className="px-2 pb-1.5 text-[10.5px] font-semibold tracking-[0.08em] uppercase text-text-tertiary">
          {t('admin.sidebar.adminSection', 'Admin')}
        </div>
        <div className="flex flex-col gap-0.5">
          <NavRow
            icon="activity"
            label={t('mobile.admin.tabs.overview', 'Overview')}
            active={tab === 'overview'}
            onClick={() => onTab('overview')}
          />
          <NavRow
            icon="users"
            label={t('mobile.admin.tabs.users', 'Users')}
            active={tab === 'users'}
            onClick={() => onTab('users')}
          />
          <NavRow
            icon="settings"
            label={t('mobile.admin.tabs.settings', 'Settings')}
            active={tab === 'settings'}
            onClick={() => onTab('settings')}
          />
        </div>
      </div>

      <div className="flex-1" />

      {/* TOTP reminder — only when not enabled */}
      <div className="px-2">
        {!auth.totpEnabled && (
          <button
            onClick={() => navigate('/drive/account/security/totp-setup')}
            className="w-full text-left px-3 py-2.5 bg-primary-faint border border-border-light rounded-[var(--radius)] flex items-center gap-2.5 mb-2 cursor-pointer hover:bg-primary-faint/80 transition-colors"
          >
            <Icon d={ICONS.shield} size={16} color="var(--primary)" />
            <div className="min-w-0">
              <div className="text-[11.5px] font-semibold text-primary truncate">
                {t('admin.sidebar.signedInAs', 'Signed in as admin')}
              </div>
              <div className="text-[10.5px] text-text-tertiary mt-px truncate">
                {t('admin.sidebar.totpOff', '2FA off · enable now')}
              </div>
            </div>
          </button>
        )}

        {/* Sign out + dark-mode toggle row */}
        <div className="flex items-center">
          <div className="flex-1">
            <NavRow
              icon="logout"
              label={t('mobile.account.signOut', 'Sign out')}
              onClick={handleLogout}
            />
          </div>
          <button
            onClick={() => toggleTheme()}
            title={
              isDark
                ? t('mobile.account.lightMode', 'Light mode')
                : t('mobile.account.darkMode', 'Dark mode')
            }
            className="w-8 h-8 rounded-[var(--radius)] border-0 bg-transparent cursor-pointer flex items-center justify-center text-text-tertiary shrink-0 mr-1 hover:bg-border-light hover:text-text-primary transition-colors"
          >
            <Icon d={isDark ? ICONS.sun : ICONS.moon} size={15} />
          </button>
        </div>

        {/* User card */}
        <div className="px-2 pb-3.5 pt-1.5 flex items-center gap-1.5">
          <div className="w-[26px] h-[26px] rounded-full bg-primary text-white flex items-center justify-center text-[11px] font-bold shrink-0">
            {initial}
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-[12.5px] font-medium text-text-primary truncate">
              {username}
            </div>
            {email && username !== email && (
              <div className="text-[11px] text-text-tertiary truncate">
                {email}
              </div>
            )}
          </div>
        </div>
      </div>
    </aside>
  )
}

/* ── NavRow primitive ───────────────────────────────────────────────── */

interface NavRowProps {
  icon: IconName
  label: string
  active?: boolean
  onClick?: () => void
}

function NavRow({ icon, label, active, onClick }: NavRowProps) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'flex items-center gap-2.5 w-full px-2.5 py-1.5 rounded-[var(--radius)] border-0 cursor-pointer text-left transition-colors',
        'text-[13.5px]',
        active
          ? 'bg-primary-light text-primary font-semibold'
          : 'bg-transparent text-text-secondary hover:bg-border-light hover:text-text-primary',
      )}
    >
      <Icon d={ICONS[icon]} size={16} />
      <span className="flex-1 truncate">{label}</span>
    </button>
  )
}
