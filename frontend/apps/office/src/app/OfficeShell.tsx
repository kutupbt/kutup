import { FileSpreadsheet, FileText, FileType, Files, HardDrive, Images, Map as MapIcon, MessagesSquare, PenTool, Presentation, UserRound } from 'lucide-react'
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

/** Office's frame: the kinds of document, and the storage they share with Drive. */
export function OfficeShell() {
  const { t } = useTranslation()
  const session = useRequiredSession()
  useAccountUiPreferences()
  return (
    <AppShell
      appName={t('apps.office')}
      switcher={
        <AppSwitcher
          currentId="office"
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
      nav={
        <>
          <SidebarNavLink to="/" end icon={<Files />} label={t('nav.all')} />
          <SidebarNavLink to="/notes" icon={<FileText />} label={t('nav.notes')} />
          <SidebarNavLink to="/documents" icon={<FileType />} label={t('nav.documents')} />
          <SidebarNavLink to="/spreadsheets" icon={<FileSpreadsheet />} label={t('nav.spreadsheets')} />
          <SidebarNavLink to="/presentations" icon={<Presentation />} label={t('nav.presentations')} />
          <SidebarNavLink to="/whiteboards" icon={<PenTool />} label={t('nav.whiteboards')} />
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
