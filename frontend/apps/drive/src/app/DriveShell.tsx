import { HardDrive, MessagesSquare, Trash2, UserRound, Users } from 'lucide-react'
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Outlet } from 'react-router-dom'
import { appUrl } from '@kutup/session/apps'
import { signOut } from '@kutup/session/signOut'
import { useRequiredSession } from '@kutup/session/store'
import { AppShell, SidebarNavLink } from '@kutup/ui/components/app-shell'
import { AppSwitcher } from '@kutup/ui/components/app-switcher'
import { UserMenu } from '@kutup/ui/components/user-menu'
import { StorageMeter } from './StorageMeter'

/** Drive's frame: New, My files / Shared with me / Trash, storage, account menu. */
export function DriveShell({ primaryAction }: { primaryAction?: ReactNode }) {
  const { t } = useTranslation()
  const session = useRequiredSession()
  return (
    <AppShell
      appName={t('apps.drive')}
      flush
      switcher={
        <AppSwitcher
          currentId="drive"
          apps={[
            { id: 'drive', name: t('apps.drive'), href: appUrl('drive'), icon: <HardDrive /> },
            { id: 'chat', name: t('apps.chat'), href: appUrl('chat'), icon: <MessagesSquare /> },
            { id: 'account', name: t('apps.account'), href: appUrl('account'), icon: <UserRound /> },
          ]}
        />
      }
      primaryAction={primaryAction}
      nav={
        <>
          <SidebarNavLink to="/" end icon={<HardDrive />} label={t('nav.myFiles')} />
          <SidebarNavLink to="/shared" icon={<Users />} label={t('nav.shared')} />
          <SidebarNavLink to="/trash" icon={<Trash2 />} label={t('nav.trash')} />
        </>
      }
      sidebarFooter={<StorageMeter />}
      headerEnd={
        <UserMenu
          name={session.username ?? session.email}
          email={session.email}
          settingsHref={appUrl('account', '/settings/account')}
          onSignOut={() => {
            void signOut().then(() => window.location.assign(appUrl('account', '/login')))
          }}
        />
      }
    >
      <Outlet />
    </AppShell>
  )
}
