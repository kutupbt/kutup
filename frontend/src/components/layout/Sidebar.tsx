import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Home, Users, Settings, LogOut, ShieldCheck, Sun, Moon, HardDrive, Trash2, MessageCircle } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useAppSelector, useAppDispatch } from '@/store'
import { logout } from '@/store/authSlice'
import { broadcastLogout } from '@/lib/sessionSync'
import * as sessionVault from '@/lib/sessionVault'
import { KutupLogo } from '@/components/KutupLogo'
import { Progress } from '@/components/ui/progress'
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
import { cn } from '@/lib/utils'
import { formatBytes } from '@/lib/format'
import { useTheme } from '@/hooks/useTheme'
import { isSupportedChat, useChatCapabilities } from '@/chat/capabilities'

interface SidebarProps {
  viewMode: 'myfiles' | 'shared' | 'trash'
  sharedCount?: number
  trashCount?: number
  onGoHome: () => void
  onGoShared: () => void
  onGoTrash: () => void
}

interface NavRowProps {
  icon: React.ElementType
  label: string
  active?: boolean
  badge?: number
  onClick?: () => void
}

function NavRow({ icon: Icon, label, active, badge, onClick }: NavRowProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'flex items-center gap-3 w-full rounded-lg px-3 py-2 text-sm font-medium transition-colors',
        active
          ? 'bg-primary/10 text-primary'
          : 'text-muted-foreground hover:bg-accent hover:text-foreground',
      )}
    >
      <Icon className="h-4 w-4 shrink-0" />
      <span className="flex-1 text-left">{label}</span>
      {badge != null && badge > 0 && (
        <span
          className={cn(
            'inline-flex h-5 min-w-5 items-center justify-center rounded-full px-1.5 text-xs',
            active ? 'bg-primary/20 text-primary' : 'bg-muted text-muted-foreground',
          )}
        >
          {badge}
        </span>
      )}
    </button>
  )
}

export default function Sidebar({
  viewMode,
  sharedCount,
  trashCount,
  onGoHome,
  onGoShared,
  onGoTrash,
}: SidebarProps) {
  const navigate = useNavigate()
  const dispatch = useAppDispatch()
  const auth = useAppSelector((s) => s.auth)
  const [theme, toggle] = useTheme()
  const [signOutOpen, setSignOutOpen] = useState(false)
  const { t } = useTranslation()
  const chatCapabilities = useChatCapabilities()

  const quotaPercent =
    auth.storageQuotaBytes > 0
      ? Math.min(Math.round((auth.storageUsedBytes / auth.storageQuotaBytes) * 100), 100)
      : 0

  async function handleLogout() {
    // Tell every other tab to log out too — otherwise a sibling editor tab
    // (or the BroadcastChannel session-sync) would re-hydrate the session.
    broadcastLogout()
    // Tauri-only: wipe the OS-keychain vault so the next app launch doesn't
    // silently rehydrate the just-cleared session. No-op on the web.
    try {
      await sessionVault.clear()
    } catch {
      // best-effort; logout proceeds regardless
    }
    dispatch(logout())
    navigate('/login')
  }

  const initial = (auth.username ?? auth.email ?? '?').slice(0, 1).toUpperCase()

  return (
    <aside className="w-64 shrink-0 flex flex-col border-r border-sidebar-border bg-sidebar">
      {/* Brand */}
      <div className="flex h-16 items-center gap-2 px-5 border-b border-sidebar-border">
        <KutupLogo size={26} />
        <span className="text-xl font-bold tracking-tight">Kutup</span>
      </div>

      {/* Primary nav */}
      <nav className="flex-1 px-3 py-4 space-y-1">
        <NavRow
          icon={Home}
          label={t('nav.myFiles')}
          active={viewMode === 'myfiles'}
          onClick={onGoHome}
        />
        <NavRow
          icon={Users}
          label={t('nav.sharedWithMe')}
          active={viewMode === 'shared'}
          badge={sharedCount}
          onClick={onGoShared}
        />
        <NavRow
          icon={Trash2}
          label={t('nav.trash', 'Trash')}
          active={viewMode === 'trash'}
          badge={trashCount}
          onClick={onGoTrash}
        />
        {isSupportedChat(chatCapabilities.data) && (
          <NavRow
            icon={MessageCircle}
            label={t('nav.messages')}
            onClick={() => navigate('/chat')}
          />
        )}
      </nav>

      {/* Storage card */}
      <div className="mx-3 mb-3 rounded-lg border border-sidebar-border bg-card/40 p-3">
        <div className="flex items-center gap-2 text-xs text-muted-foreground mb-2">
          <HardDrive className="h-3.5 w-3.5" />
          <span className="font-medium">Storage</span>
        </div>
        <Progress value={quotaPercent} className="h-1.5" />
        <p className="mt-2 text-xs text-muted-foreground">
          {formatBytes(auth.storageUsedBytes)}
          <span className="opacity-60"> / {formatBytes(auth.storageQuotaBytes)}</span>
        </p>
      </div>

      {/* Footer */}
      <div className="border-t border-sidebar-border px-3 py-2 space-y-1">
        {auth.isAdmin && (
          <NavRow
            icon={ShieldCheck}
            label={t('nav.admin')}
            onClick={() => navigate('/admin')}
          />
        )}
        <NavRow
          icon={Settings}
          label={t('nav.settings')}
          onClick={() => navigate('/settings')}
        />
        <button
          type="button"
          onClick={() => setSignOutOpen(true)}
          className="w-full flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-muted-foreground hover:bg-accent hover:text-foreground transition-colors"
        >
          <LogOut className="h-4 w-4 shrink-0" />
          {t('nav.signOut')}
        </button>

        {/* User chip + theme toggle */}
        <div className="flex items-center gap-2 mt-2 mx-1 rounded-lg px-2 py-1.5">
          <span className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-primary/15 text-primary text-sm font-semibold">
            {initial}
          </span>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-medium leading-tight">
              {auth.username ?? auth.email ?? ''}
            </p>
            {auth.username && auth.email && (
              <p className="truncate text-xs text-muted-foreground leading-tight">
                {auth.email}
              </p>
            )}
          </div>
          <button
            type="button"
            onClick={() => toggle()}
            title={theme === 'dark' ? t('nav.switchToLight') : t('nav.switchToDark')}
            aria-label={theme === 'dark' ? t('nav.switchToLight') : t('nav.switchToDark')}
            className="h-8 w-8 shrink-0 inline-flex items-center justify-center rounded-lg text-muted-foreground hover:bg-accent hover:text-foreground transition-colors"
          >
            {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </button>
        </div>
      </div>

      <AlertDialog open={signOutOpen} onOpenChange={setSignOutOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('nav.signOutConfirmTitle')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('nav.signOutConfirmDescription')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction onClick={handleLogout}>
              {t('nav.signOut')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </aside>
  )
}
