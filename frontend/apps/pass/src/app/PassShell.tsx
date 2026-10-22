import { BookUser, CalendarDays, FileType, HardDrive, Images, KeyRound, LockKeyhole, LockKeyholeOpen, Mail as MailIcon, Map as MapIcon, MessagesSquare, Plus, UserRound, Vault } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Outlet } from 'react-router-dom'
import { StorageMeter } from '@kutup/drive-ui/StorageMeter'
import { appUrl } from '@kutup/session/apps'
import { feedbackServices } from '@kutup/session/feedback'
import { signOut } from '@kutup/session/signOut'
import { useRequiredSession } from '@kutup/session/store'
import { useAccountUiPreferences } from '@kutup/session/uiPreferences'
import { AppShell, SidebarNavLink } from '@kutup/ui/components/app-shell'
import { AppSwitcher } from '@kutup/ui/components/app-switcher'
import { Button } from '@kutup/ui/components/button'
import { FeedbackButton } from '@kutup/ui/components/feedback'
import { UserMenu } from '@kutup/ui/components/user-menu'
import { useVaultFiles, vaultTitle } from '../drive/vaults'
import { CreateVaultDialog } from '../features/CreateVaultDialog'
import { lockAndForget, startAutoLock } from '../sync/autoLock'
import { lockAll, openVaultIds, useVaultSession } from '../sync/openVaults'
import { useAccountHeadState } from '@kutup/session/useAccountHeadState'
import { HeadStateBanner } from '@kutup/ui/components/head-state-banner'

function VaultLink({ fileId, name }: { fileId: string; name: string }) {
  const { t } = useTranslation()
  const open = Boolean(useVaultSession(fileId))
  return (
    <SidebarNavLink
      to={`/v/${fileId}`}
      icon={<Vault />}
      label={name}
      trailing={
        open ? (
          <LockKeyholeOpen className="size-3.5 text-chrome-muted" aria-label={t('vaults.unlocked')} />
        ) : (
          <LockKeyhole className="size-3.5 text-chrome-muted" aria-label={t('vaults.locked')} />
        )
      }
    />
  )
}

/** Pass's frame: new vault, the vaults, and the shared storage. */
export function PassShell() {
  const { t } = useTranslation()
  const session = useRequiredSession()
  // The account's state here: a rolled-back or forked history, or a long absence.
  const accountHeadState = useAccountHeadState()
  useAccountUiPreferences()
  const { vaults } = useVaultFiles()
  const [creating, setCreating] = useState(false)
  useEffect(startAutoLock, [])
  useVaultSession(undefined)
  const anyOpen = openVaultIds().length > 0
  return (
    <AppShell
      banner={<HeadStateBanner {...accountHeadState} />}
      appName={t('apps.pass')}
      switcher={
        <AppSwitcher
          currentId="pass"
          apps={[
            { id: 'drive', name: t('apps.drive'), href: appUrl('drive'), icon: <HardDrive /> },
            { id: 'office', name: t('apps.office'), href: appUrl('office'), icon: <FileType /> },
            { id: 'chat', name: t('apps.chat'), href: appUrl('chat'), icon: <MessagesSquare /> },
            { id: 'mail', name: t('apps.mail'), href: appUrl('mail'), icon: <MailIcon /> },
            { id: 'calendar', name: t('apps.calendar'), href: appUrl('calendar'), icon: <CalendarDays /> },
            { id: 'pass', name: t('apps.pass'), href: appUrl('pass'), icon: <KeyRound /> },
            { id: 'contacts', name: t('apps.contacts'), href: appUrl('contacts'), icon: <BookUser /> },
            { id: 'photos', name: t('apps.photos'), href: appUrl('photos'), icon: <Images /> },
            { id: 'maps', name: t('apps.maps'), href: appUrl('maps'), icon: <MapIcon /> },
            { id: 'account', name: t('apps.account'), href: appUrl('account'), icon: <UserRound /> },
          ]}
        />
      }
      flush
      primaryAction={
        <Button className="w-full" onClick={() => setCreating(true)}>
          <Plus />
          {t('vaults.new')}
        </Button>
      }
      nav={
        <>
          <SidebarNavLink to="/" end icon={<KeyRound />} label={t('nav.vaults')} />
          {vaults.length > 0 && (
            <li className="px-3 pb-1 pt-4 text-[11px] font-medium uppercase tracking-wider text-chrome-muted">{t('nav.yourVaults')}</li>
          )}
          {vaults.map((v) => (
            <VaultLink key={v.file.id} fileId={v.file.id} name={vaultTitle(v.file.name)} />
          ))}
          {anyOpen && (
            <li className="pt-2">
              <button
                type="button"
                onClick={() => void lockAll()}
                className="flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm text-chrome-muted hover:bg-chrome-accent/60 hover:text-chrome-foreground"
              >
                <LockKeyhole className="size-4" aria-hidden />
                {t('vaults.lockAll')}
              </button>
            </li>
          )}
        </>
      }
      sidebarFooter={
        <div className="space-y-2">
          <FeedbackButton app="pass" services={feedbackServices} />
          <StorageMeter />
        </div>
      }
      headerEnd={
        <UserMenu
          name={session.username ?? session.address}
          address={session.address}
          settingsHref={appUrl('account', '/settings/profile')}
          onSignOut={() => {
            // Locked, and what this device kept for offline use forgotten.
            void lockAndForget(session.userId)
              .then(() => signOut())
              .then(() => window.location.assign(appUrl('account', '/login')))
          }}
        />
      }
    >
      <Outlet />
      <CreateVaultDialog open={creating} onOpenChange={setCreating} />
    </AppShell>
  )
}
