import { HardDrive, Map as MapIcon, MessagesSquare, Settings, UserRound } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Outlet } from 'react-router-dom'
import { usePeople } from '@kutup/drive-core/people'
import { appUrl } from '@kutup/session/apps'
import { signOut } from '@kutup/session/signOut'
import { useRequiredSession } from '@kutup/session/store'
import { AppShell, SidebarNavLink } from '@kutup/ui/components/app-shell'
import { AppSwitcher } from '@kutup/ui/components/app-switcher'
import { UserMenu } from '@kutup/ui/components/user-menu'

/** The Maps frame: your lists, settings, the account menu. */
export function MapsShell() {
  const { t } = useTranslation()
  const session = useRequiredSession()
  // Names and pictures of the people lists are shared with.
  usePeople()
  return (
    <AppShell
      appName={t('apps.maps')}
      switcher={
        <AppSwitcher
          currentId="maps"
          apps={[
            { id: 'drive', name: t('apps.drive'), href: appUrl('drive'), icon: <HardDrive /> },
            { id: 'chat', name: t('apps.chat'), href: appUrl('chat'), icon: <MessagesSquare /> },
            { id: 'maps', name: t('apps.maps'), href: appUrl('maps'), icon: <MapIcon /> },
            { id: 'account', name: t('apps.account'), href: appUrl('account'), icon: <UserRound /> },
          ]}
        />
      }
      nav={
        <>
          <SidebarNavLink to="/" end icon={<MapIcon />} label={t('nav.lists')} />
          <SidebarNavLink to="/settings" icon={<Settings />} label={t('nav.settings')} />
        </>
      }
      headerEnd={
        <UserMenu
          name={session.username ?? session.email}
          email={session.email}
          settingsHref={appUrl('account', '/settings/profile')}
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
