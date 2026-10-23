import { FeedbackButton } from '@kutup/ui/components/feedback'
import { feedbackServices } from '@kutup/session/feedback'
import { Activity, BookUser, CalendarDays, ChartPie, CircleUser, FileType, Flag, Gauge, Globe, Globe2, HardDrive, Images, KeyRound, LayoutGrid, Mail as MailIcon, Mails, Map, MessageSquareText, MessagesSquare, MonitorSmartphone, Send, Settings2, ShieldCheck, Ticket, UserRound, Users } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Outlet, useNavigate } from 'react-router-dom'
import { appUrl } from '@kutup/session/apps'
import { signOut } from '@kutup/session/signOut'
import { useRequiredSession } from '@kutup/session/store'
import { useAccountUiPreferences } from '@kutup/session/uiPreferences'
import { useEnsureMailKeys } from '../features/keys/mailKeys'
import { GroupMembershipNavLink } from '../features/settings/GroupMembershipNavLink'
import { AppShell, SidebarNavLink } from '@kutup/ui/components/app-shell'
import { AppSwitcher } from '@kutup/ui/components/app-switcher'
import { UserMenu } from '@kutup/ui/components/user-menu'
import { useAccountHeadState } from '@kutup/session/useAccountHeadState'
import { HeadStateBanner } from '@kutup/ui/components/head-state-banner'

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
  // The account's state here: a rolled-back or forked history, or a long absence.
  const accountHeadState = useAccountHeadState()
  useAccountUiPreferences()
  // Every address gets its encryption key right after sign-in.
  useEnsureMailKeys()

  return (
    <AppShell
      banner={<HeadStateBanner {...accountHeadState} />}
      appName={t('apps.account')}
      switcher={
        <AppSwitcher
          currentId="account"
          apps={[
            { id: 'drive', name: t('apps.drive'), href: appUrl('drive'), icon: <HardDrive /> },
            { id: 'office', name: t('apps.office'), href: appUrl('office'), icon: <FileType /> },
            { id: 'chat', name: t('apps.chat'), href: appUrl('chat'), icon: <MessagesSquare /> },
            { id: 'mail', name: t('apps.mail'), href: appUrl('mail'), icon: <MailIcon /> },
            { id: 'calendar', name: t('apps.calendar'), href: appUrl('calendar'), icon: <CalendarDays /> },
            { id: 'pass', name: t('apps.pass'), href: appUrl('pass'), icon: <KeyRound /> },
            { id: 'contacts', name: t('apps.contacts'), href: appUrl('contacts'), icon: <BookUser /> },
            { id: 'photos', name: t('apps.photos'), href: appUrl('photos'), icon: <Images /> },
            { id: 'maps', name: t('apps.maps'), href: appUrl('maps'), icon: <Map /> },
            { id: 'account', name: t('apps.account'), href: appUrl('account'), icon: <UserRound /> },
          ]}
        />
      }
      sidebarFooter={<FeedbackButton app="account" services={feedbackServices} />}
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
          <GroupMembershipNavLink />
          <SidebarNavLink to="/settings/maps" icon={<Map />} label={t('nav.maps')} />
          {session.isAdmin ? (
            <>
              <SectionLabel>{t('nav.admin')}</SectionLabel>
              <SidebarNavLink to="/admin/users" icon={<Users />} label={t('nav.users')} />
              <SidebarNavLink to="/admin/codes" icon={<Ticket />} label={t('nav.referralCodes')} />
              <SidebarNavLink to="/admin/reports" icon={<Flag />} label={t('nav.reports')} />
              <SidebarNavLink to="/admin/feedback" icon={<MessageSquareText />} label={t('nav.feedback')} />
              <SidebarNavLink to="/admin/activity" icon={<Activity />} label={t('nav.activity')} />
              <SidebarNavLink to="/admin/federation" icon={<Globe />} label={t('nav.federation')} />
              <SidebarNavLink to="/admin/settings" icon={<Settings2 />} label={t('nav.serverSettings')} />
              <SidebarNavLink to="/admin/rate-limits" icon={<Gauge />} label={t('nav.rateLimits')} />
              <SidebarNavLink to="/admin/maps" icon={<Map />} label={t('nav.adminMaps')} />
              <SidebarNavLink to="/admin/mail" end icon={<Send />} label={t('nav.mailSending')} />
              <SidebarNavLink to="/admin/mail/groups" icon={<Mails />} label={t('nav.mailGroups')} />
              <SidebarNavLink to="/admin/mail/domains" icon={<Globe2 />} label={t('nav.mailDomains')} />
            </>
          ) : null}
        </>
      }
      headerEnd={
        <UserMenu
          name={session.username ?? session.address}
          address={session.address}
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
