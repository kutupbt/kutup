import { HardDrive, MessageSquare, MessagesSquare, Settings, SquarePen, UserRound } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Outlet } from 'react-router-dom'
import { appUrl } from '@kutup/session/apps'
import { signOut } from '@kutup/session/signOut'
import { useRequiredSession } from '@kutup/session/store'
import { AppShell, SidebarNavLink } from '@kutup/ui/components/app-shell'
import { AppSwitcher } from '@kutup/ui/components/app-switcher'
import { Button } from '@kutup/ui/components/button'
import { UserMenu } from '@kutup/ui/components/user-menu'
import { NewChatDialog } from '../features/list/NewChatDialog'
import { ChatSearchBox } from '../features/list/ChatSearchBox'
import { BackupIndicator } from '../features/settings/BackupIndicator'
import { useNow } from '../lib/useNow'
import { useReadMarks } from '../state/readState'
import { unreadCounts } from '../state/views'
import { closeChat, useChat } from './chatStore'

/**
 * Chat in the Kutup frame: the dark sidebar (New chat, Chats, Settings,
 * backup status) and the header (search, app switcher, account menu). The
 * Signal-style panes live in the page.
 */
export function ChatShell() {
  const { t } = useTranslation()
  const session = useRequiredSession()
  const chat = useChat()
  const marks = useReadMarks()
  const now = useNow(60_000)
  const [newChat, setNewChat] = useState(false)
  const unread = useMemo(() => {
    let total = 0
    for (const count of unreadCounts(chat.snapshot.history, marks, now).values()) total += count
    return total
  }, [chat.snapshot.history, marks, now])

  return (
    <AppShell
      appName={t('apps.chat')}
      flush
      switcher={
        <AppSwitcher
          currentId="chat"
          apps={[
            { id: 'drive', name: t('apps.drive'), href: appUrl('drive'), icon: <HardDrive /> },
            { id: 'chat', name: t('apps.chat'), href: appUrl('chat'), icon: <MessagesSquare /> },
            { id: 'account', name: t('apps.account'), href: appUrl('account'), icon: <UserRound /> },
          ]}
        />
      }
      primaryAction={
        <Button variant="chrome" className="w-full justify-start border border-chrome-border" onClick={() => setNewChat(true)}>
          <SquarePen />
          {t('chat.newChat.action')}
        </Button>
      }
      nav={
        <>
          <SidebarNavLink
            to="/"
            end
            icon={<MessageSquare />}
            label={t('chat.nav.chats')}
            trailing={
              unread > 0 ? (
                <span className="min-w-[1.125rem] rounded-full bg-primary px-1.5 text-center text-[0.6875rem] font-bold leading-[1.125rem] text-primary-foreground" aria-label={t('chat.list.unread', { count: unread })}>
                  {unread > 99 ? '99+' : unread}
                </span>
              ) : undefined
            }
          />
          <SidebarNavLink to="/settings" icon={<Settings />} label={t('chat.nav.settings')} />
        </>
      }
      sidebarFooter={<BackupIndicator />}
      headerStart={<ChatSearchBox />}
      headerEnd={
        <UserMenu
          name={session.username ?? session.email}
          email={session.email}
          settingsHref={appUrl('account', '/settings/account')}
          onSignOut={() => {
            closeChat()
            void signOut().then(() => window.location.assign(appUrl('account', '/login')))
          }}
        />
      }
    >
      <Outlet />
      <NewChatDialog open={newChat} onOpenChange={setNewChat} />
    </AppShell>
  )
}
