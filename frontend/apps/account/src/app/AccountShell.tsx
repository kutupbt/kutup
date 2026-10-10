import { Activity, BookUser, ChartPie, CircleUser, FileType, Flag, Globe, HardDrive, Images, KeyRound, LayoutGrid, Mail as MailIcon, Map, MessagesSquare, MonitorSmartphone, Send, Settings2, ShieldCheck, UserRound, Users } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Outlet, useNavigate } from 'react-router-dom'
import { appUrl } from '@kutup/session/apps'
import { signOut } from '@kutup/session/signOut'
import { useRequiredSession } from '@kutup/session/store'
import { useAccountUiPreferences } from '@kutup/session/uiPreferences'
import { useEnsureMailKeys } from '../features/keys/mailKeys'
import { AppShell, SidebarNavLink } from '@kutup/ui/components/app-shell'
import { AppSwitcher } from '@kutup/ui/components/app-switcher'
import { UserMenu } from '@kutup/ui/components/user-menu'

function SectionLabel({ children }: { children: string }) {
  return (
    <li className="px-3 pb-1 pt-4 text-[11px] font-medium uppercase tracking-wider text-chrome-muted">
      {children}
    </li>
  )
}

export function AccountShell() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const session = useRequiredSession()
  useAccountUiPreferences()
  // Every address gets its encryption key right after sign-in.
  useEnsureMailKeys()

  return (
    <AppShell
      appName={t('apps.account')}
      switcher={
        <AppSwitcher
          currentId="account"
          apps={[
            { id: 'drive', name: t('apps.drive'), href: appUrl('drive'), icon: <HardDrive /> },
            { id: 'office', name: t('apps.office'), href: appUrl('office'), icon: <FileType /> },
            { id: 'chat', name: t('apps.chat'), href: appUrl('chat'), icon: <MessagesSquare /> },
            { id: 'mail', name: t('apps.mail'), href: appUrl('mail'), icon: <MailIcon /> },
            { id: 'contacts', name: t('apps.contacts'), href: appUrl('contacts'), icon: <BookUser /> },
            { id: 'photos', name: t('apps.photos'), href: appUrl('photos'), icon: <Images /> },
            { id: 'maps', name: t('apps.maps'), href: appUrl('maps'), icon: <Map /> },
            { id: 'account', name: t('apps.account'), href: appUrl('account'), icon: <UserRound /> },
          ]}
        />
      }
      nav={
        <>
          <SidebarNavLink to="/" end icon={<LayoutGrid />} label={t('nav.apps')} />
          <SectionLabel>{t('nav.settings')}</SectionLabel>
          <SidebarNavLink to="/settings/profile" icon={<CircleUser />} label={t('nav.profile')} />
          <SidebarNavLink to="/settings/account" icon={<UserRound />} label={t('nav.account')} />
          <SidebarNavLink to="/settings/storage" icon={<ChartPie />} label={t('nav.storage')} />
          <SidebarNavLink to="/settings/security" icon={<ShieldCheck />} label={t('nav.security')} />
          <SidebarNavLink to="/settings/keys" icon={<KeyRound />} label={t('nav.keys')} />
          <SidebarNavLink to="/settings/devices" icon={<MonitorSmartphone />} label={t('nav.devicesSessions')} />
          <SidebarNavLink to="/settings/maps" icon={<Map />} label={t('nav.maps')} />
          {session.isAdmin ? (
            <>
              <SectionLabel>{t('nav.admin')}</SectionLabel>
              <SidebarNavLink to="/admin/users" icon={<Users />} label={t('nav.users')} />
              <SidebarNavLink to="/admin/reports" icon={<Flag />} label={t('nav.reports')} />
              <SidebarNavLink to="/admin/activity" icon={<Activity />} label={t('nav.activity')} />
              <SidebarNavLink to="/admin/federation" icon={<Globe />} label={t('nav.federation')} />
              <SidebarNavLink to="/admin/settings" icon={<Settings2 />} label={t('nav.serverSettings')} />
              <SidebarNavLink to="/admin/maps" icon={<Map />} label={t('nav.adminMaps')} />
              <SidebarNavLink to="/admin/mail" icon={<Send />} label={t('nav.mailSending')} />
            </>
          ) : null}
        </>
      }
      headerEnd={
        <UserMenu
          name={session.username ?? session.email}
          email={session.email}
          settingsHref={appUrl('account', '/settings/profile')}
          onSignOut={() => {
            void signOut().then(() => navigate('/login', { replace: true }))
          }}
        />
      }
    >
      <Outlet />
    </AppShell>
  )
}
