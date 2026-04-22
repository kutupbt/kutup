import { useNavigate } from 'react-router-dom'
import { Folder, Users, Settings, LogOut, ShieldCheck } from 'lucide-react'
import { useAppSelector, useAppDispatch } from '@/store'
import { logout } from '@/store/authSlice'
import { KutupLogo } from '@/components/KutupLogo'
import { Progress } from '@/components/ui/progress'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { cn } from '@/lib/utils'
import { formatBytes } from '@/lib/format'

interface SidebarProps {
  viewMode: 'myfiles' | 'shared'
  onGoHome: () => void
  onGoShared: () => void
}

export default function Sidebar({ viewMode, onGoHome, onGoShared }: SidebarProps) {
  const navigate = useNavigate()
  const dispatch = useAppDispatch()
  const auth = useAppSelector((s) => s.auth)

  const quotaPercent =
    auth.storageQuotaBytes > 0
      ? Math.min(Math.round((auth.storageUsedBytes / auth.storageQuotaBytes) * 100), 100)
      : 0

  function handleLogout() {
    dispatch(logout())
    navigate('/login')
  }

  return (
    <aside className="w-60 shrink-0 flex flex-col bg-sidebar border-r border-sidebar-border p-4 gap-2">
      <div className="flex items-center gap-2 mb-1">
        <KutupLogo size={26} />
        <span className="text-xl font-bold text-primary tracking-tight">Kutup</span>
      </div>

      {auth.username && (
        <p className="text-xs text-muted-foreground -mt-1">@{auth.username}</p>
      )}

      <div className="mt-1 mb-2">
        <p className="text-xs text-muted-foreground mb-1">
          {formatBytes(auth.storageUsedBytes)} / {formatBytes(auth.storageQuotaBytes)}
        </p>
        <Progress value={quotaPercent} className="h-1" />
      </div>

      <Separator />

      <nav className="flex flex-col gap-1 mt-1">
        <Button
          variant="ghost"
          className={cn(
            'justify-start gap-2 h-9',
            viewMode === 'myfiles' && 'bg-sidebar-accent text-sidebar-accent-foreground',
          )}
          onClick={onGoHome}
        >
          <Folder className="h-4 w-4" />
          My Files
        </Button>
        <Button
          variant="ghost"
          className={cn(
            'justify-start gap-2 h-9',
            viewMode === 'shared' && 'bg-sidebar-accent text-sidebar-accent-foreground',
          )}
          onClick={onGoShared}
        >
          <Users className="h-4 w-4" />
          Shared with me
        </Button>
      </nav>

      <div className="flex-1" />

      <Separator />

      <div className="flex flex-col gap-1 mt-1">
        {auth.isAdmin && (
          <Button
            variant="ghost"
            className="justify-start gap-2 h-9 text-muted-foreground"
            onClick={() => navigate('/admin')}
          >
            <ShieldCheck className="h-4 w-4" />
            Admin
          </Button>
        )}
        <Button
          variant="ghost"
          className="justify-start gap-2 h-9 text-muted-foreground"
          onClick={() => navigate('/settings')}
        >
          <Settings className="h-4 w-4" />
          Settings
        </Button>
        <Button
          variant="ghost"
          className="justify-start gap-2 h-9 text-muted-foreground"
          onClick={handleLogout}
        >
          <LogOut className="h-4 w-4" />
          Sign out
        </Button>
      </div>
    </aside>
  )
}
