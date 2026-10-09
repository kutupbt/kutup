import { Archive, BookImage, EyeOff, FileType, HardDrive, Heart, Images, Map as MapIcon, MapPinned, MessagesSquare, Settings, Trash2, UserRound } from 'lucide-react'
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Outlet } from 'react-router-dom'
import { StorageMeter } from '@kutup/drive-ui/StorageMeter'
import { appUrl } from '@kutup/session/apps'
import { signOut } from '@kutup/session/signOut'
import { useRequiredSession } from '@kutup/session/store'
import { useAccountUiPreferences } from '@kutup/session/uiPreferences'
import { AppShell, SidebarNavLink } from '@kutup/ui/components/app-shell'
import { AppSwitcher } from '@kutup/ui/components/app-switcher'
import { UserMenu } from '@kutup/ui/components/user-menu'

/** Photos' frame: Upload, the library and its settings, the storage it shares with Drive. */
export function PhotosShell({ primaryAction }: { primaryAction?: ReactNode }) {
  const { t } = useTranslation()
  const session = useRequiredSession()
  useAccountUiPreferences()
  return (
    <AppShell
      appName={t('apps.photos')}
      flush
      switcher={
        <AppSwitcher
          currentId="photos"
          apps={[
            { id: 'drive', name: t('apps.drive'), href: appUrl('drive'), icon: <HardDrive /> },
            { id: 'office', name: t('apps.office'), href: appUrl('office'), icon: <FileType /> },
            { id: 'chat', name: t('apps.chat'), href: appUrl('chat'), icon: <MessagesSquare /> },
            { id: 'photos', name: t('apps.photos'), href: appUrl('photos'), icon: <Images /> },
            { id: 'maps', name: t('apps.maps'), href: appUrl('maps'), icon: <MapIcon /> },
            { id: 'account', name: t('apps.account'), href: appUrl('account'), icon: <UserRound /> },
          ]}
        />
      }
      primaryAction={primaryAction}
      nav={
        <>
          <SidebarNavLink to="/" end icon={<Images />} label={t('nav.photos')} />
          <SidebarNavLink to="/places" icon={<MapPinned />} label={t('nav.places')} />
          <SidebarNavLink to="/albums" icon={<BookImage />} label={t('nav.albums')} />
          <SidebarNavLink to="/favourites" icon={<Heart />} label={t('nav.favourites')} />
          <SidebarNavLink to="/archive" icon={<Archive />} label={t('nav.archive')} />
          <SidebarNavLink to="/hidden" icon={<EyeOff />} label={t('nav.hidden')} />
          <SidebarNavLink to="/trash" icon={<Trash2 />} label={t('nav.trash')} />
          <SidebarNavLink to="/settings" icon={<Settings />} label={t('nav.settings')} />
        </>
      }
      sidebarFooter={<StorageMeter />}
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
