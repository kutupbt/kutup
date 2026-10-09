import { BookUser, FileType, HardDrive, Images, Map as MapIcon, MessagesSquare, Plus, UserRound, Users } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Outlet } from 'react-router-dom'
import { useContactGroups, useContacts } from '@kutup/contacts-core/api'
import { StorageMeter } from '@kutup/drive-ui/StorageMeter'
import { appUrl } from '@kutup/session/apps'
import { signOut } from '@kutup/session/signOut'
import { useRequiredSession } from '@kutup/session/store'
import { useAccountUiPreferences } from '@kutup/session/uiPreferences'
import { AppShell, SidebarNavLink } from '@kutup/ui/components/app-shell'
import { AppSwitcher } from '@kutup/ui/components/app-switcher'
import { Button } from '@kutup/ui/components/button'
import { UserMenu } from '@kutup/ui/components/user-menu'
import { GroupDialog } from '../features/GroupDialog'
import { ContactEditorDialog } from '../features/ContactEditor'
import { useEditor } from '../features/editorState'

function Count({ value }: { value: number }) {
  return <span className="text-xs tabular-nums text-chrome-muted">{value}</span>
}

/** Contacts' frame: new contact, everyone, the groups, and the shared storage. */
export function ContactsShell() {
  const { t } = useTranslation()
  const session = useRequiredSession()
  useAccountUiPreferences()
  const contacts = useContacts()
  const groups = useContactGroups()
  const editor = useEditor()
  const [newGroup, setNewGroup] = useState(false)
  return (
    <AppShell
      appName={t('apps.contacts')}
      switcher={
        <AppSwitcher
          currentId="contacts"
          apps={[
            { id: 'drive', name: t('apps.drive'), href: appUrl('drive'), icon: <HardDrive /> },
            { id: 'office', name: t('apps.office'), href: appUrl('office'), icon: <FileType /> },
            { id: 'chat', name: t('apps.chat'), href: appUrl('chat'), icon: <MessagesSquare /> },
            { id: 'contacts', name: t('apps.contacts'), href: appUrl('contacts'), icon: <BookUser /> },
            { id: 'photos', name: t('apps.photos'), href: appUrl('photos'), icon: <Images /> },
            { id: 'maps', name: t('apps.maps'), href: appUrl('maps'), icon: <MapIcon /> },
            { id: 'account', name: t('apps.account'), href: appUrl('account'), icon: <UserRound /> },
          ]}
        />
      }
      flush
      primaryAction={
        <Button className="w-full" onClick={() => editor.open({ kind: 'new' })}>
          <Plus />
          {t('contacts.new')}
        </Button>
      }
      nav={
        <>
          <SidebarNavLink
            to="/"
            end
            icon={<Users />}
            label={t('nav.all')}
            trailing={contacts.data ? <Count value={contacts.data.contacts.length} /> : undefined}
          />
          <li className="px-3 pb-1 pt-4 text-[11px] font-medium uppercase tracking-wider text-chrome-muted">{t('nav.groups')}</li>
          {(groups.data ?? []).map((group) => (
            <SidebarNavLink
              key={group.id}
              to={`/groups/${group.id}`}
              icon={<span aria-hidden className="size-2.5 rounded-full" style={{ background: group.color }} />}
              label={group.name}
              trailing={<Count value={group.members} />}
            />
          ))}
          <li>
            <button
              type="button"
              onClick={() => setNewGroup(true)}
              className="flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm text-chrome-muted hover:bg-chrome-accent/60 hover:text-chrome-foreground"
            >
              <Plus className="size-4" aria-hidden />
              {t('groups.new')}
            </button>
          </li>
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
      <GroupDialog open={newGroup} onOpenChange={setNewGroup} />
      <ContactEditorDialog />
    </AppShell>
  )
}
