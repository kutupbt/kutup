import { BookUser, FileType, HardDrive, Images, Map as MapIcon, MessageSquare, MessagesSquare, Settings, SquarePen, UserRound, Video } from 'lucide-react'
import { useCallback, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Outlet, useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { appUrl } from '@kutup/session/apps'
import { signOut } from '@kutup/session/signOut'
import { useRequiredSession } from '@kutup/session/store'
import { useAccountUiPreferences } from '@kutup/session/uiPreferences'
import { AppShell, SidebarNavLink } from '@kutup/ui/components/app-shell'
import { AppSwitcher } from '@kutup/ui/components/app-switcher'
import { Button } from '@kutup/ui/components/button'
import { UserMenu } from '@kutup/ui/components/user-menu'
import { apiErrorCode } from '@kutup/ui/lib/apiError'
import { useMeetings } from '../features/callLinks/useMeetings'
import { CallHost } from '../features/calls/CallScreen'
import { JoinGroupHost } from '../features/groupLink/JoinGroupDialog'
import { SharedPlaceHost } from '../features/thread/ForwardDialog'
import { NewChatDialog } from '../features/list/NewChatDialog'
import { ChatSearchBox } from '../features/list/ChatSearchBox'
import { BackupIndicator } from '../features/settings/BackupIndicator'
import { useNow } from '../lib/useNow'
import { clearDrafts } from '../lib/drafts'
import { disableWebPush } from '../lib/webPush'
import { isMuted } from '../state/accountState'
import { useAccountState, useReadThrough } from '../state/useAccountState'
import { unreadCounts } from '../state/views'
import { ChatNotifier } from './ChatNotifier'
import { Shortcuts } from './Shortcuts'
import { forgetAccountHostTokens } from '../features/callLinks/hostTokens'
import { closeChat, useChat } from './chatStore'

/**
 * Chat in the Kutup frame: the sidebar (New chat, Chats, Settings,
 * backup status) and the header (search, app switcher, account menu). The
 * Signal-style panes live in the page.
 */
export function ChatShell() {
  const { t } = useTranslation()
  const session = useRequiredSession()
  useAccountUiPreferences()
  const chat = useChat()
  const readThrough = useReadThrough()
  const { lists } = useAccountState()
  const now = useNow(60_000)
  const [newChat, setNewChat] = useState(false)
  const openNewChat = useCallback(() => setNewChat(true), [])
  // A meeting to join right away: made, its link copied, and shown in the list.
  const meetings = useMeetings(false)
  const navigate = useNavigate()
  async function newMeeting() {
    try {
      const meeting = await meetings.create.mutateAsync({ info: { title: t('chat.meetings.defaultTitle') }, waitingRoom: false })
      try {
        await navigator.clipboard.writeText(meeting.url)
        toast.success(t('chat.meetings.startedCopied'))
      } catch {
        toast.message(t('chat.meetings.started'))
      }
      void navigate('/meetings')
    } catch (error) {
      toast.error(apiErrorCode(error) === 'conflict' ? t('chat.meetings.tooMany') : t('chat.meetings.createFailed'))
    }
  }
  // Muted chats stay out of the count; a chat marked unread counts one.
  const unread = useMemo(() => {
    const counts = unreadCounts(chat.snapshot.history, readThrough, now)
    let total = 0
    for (const [key, count] of counts) if (!isMuted(lists.get(key), now)) total += count
    for (const [key, state] of lists) {
      if (state.markedUnread && !counts.get(key) && !isMuted(state, now)) total += 1
    }
    return total
  }, [chat.snapshot.history, readThrough, lists, now])

  return (
    <AppShell
      appName={t('apps.chat')}
      flush
      switcher={
        <AppSwitcher
          currentId="chat"
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
      primaryAction={
        <div className="flex flex-col gap-2">
          <Button variant="chrome" className="w-full justify-start border border-chrome-border" onClick={() => setNewChat(true)}>
            <SquarePen />
            {t('chat.newChat.action')}
          </Button>
          {chat.capabilities?.callLinks ? (
            <Button
              variant="chrome"
              className="w-full justify-start border border-chrome-border"
              onClick={() => void newMeeting()}
              disabled={meetings.create.isPending}
              data-testid="chat-new-meeting"
            >
              <Video />
              {t('chat.meetings.new')}
            </Button>
          ) : null}
        </div>
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
          {chat.capabilities?.callLinks ? <SidebarNavLink to="/meetings" icon={<Video />} label={t('chat.nav.meetings')} /> : null}
          <SidebarNavLink to="/settings" icon={<Settings />} label={t('chat.nav.settings')} />
        </>
      }
      sidebarFooter={<BackupIndicator />}
      headerStart={<ChatSearchBox />}
      headerEnd={
        <UserMenu
          name={session.username ?? session.email}
          email={session.email}
          settingsHref={appUrl('account', '/settings/profile')}
          onSignOut={() => {
            // A signed-out browser is not woken for this account any more.
            clearDrafts()
            // Nor does it host this account's meetings any more.
            forgetAccountHostTokens(session.userId)
            void disableWebPush(chat.service)
              .catch(() => undefined)
              .then(() => {
                closeChat()
                return signOut()
              })
              .then(() => window.location.assign(appUrl('account', '/login')))
          }}
        />
      }
    >
      <Outlet />
      <NewChatDialog open={newChat} onOpenChange={setNewChat} />
      <JoinGroupHost />
      <SharedPlaceHost />
      <ChatNotifier unread={unread} />
      <CallHost />
      <Shortcuts onNewChat={openNewChat} />
    </AppShell>
  )
}
