import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useLocation, useNavigate } from 'react-router-dom'
import { parseConversationKey, pathForConversation } from '../features/list/paths'
import { groupTitle, messagePreview, personName } from '../lib/names'
import { notificationsAllowed } from '../lib/notificationPermission'
import { playNotificationSound } from '../lib/notificationSound'
import { NotifyTabs } from '../lib/notifyTabs'
import { enableWebPush, pushWords, webPushSupported } from '../lib/webPush'
import { noticesFor, type Notice } from '../state/notify'
import { getNotificationContent, getNotifications, getNotificationSound, getWebPush } from '../state/prefs'
import { useAccountState, useReadThrough } from '../state/useAccountState'
import { useChat } from './chatStore'

/** More at once than this and one notification sums them up. */
const MAX_AT_ONCE = 3

/**
 * Notifications while the chat is open in a tab, as Signal Desktop shows
 * them: new messages, reactions to your messages, group invitations and
 * requests to join your groups, with a sound. None while any tab of the chat
 * has focus (only the sound, for another conversation), one tab notifies
 * for all, and the tab title counts unread messages.
 */
export function ChatNotifier({ unread }: { unread: number }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const location = useLocation()
  const chat = useChat()
  const { lists } = useAccountState()
  const readThrough = useReadThrough()
  const self = chat.self
  const address = self?.address ?? ''
  const [tabs, setTabs] = useState<NotifyTabs | null>(null)
  const baseTitle = useRef(document.title)
  const seenEntries = useRef<Set<string> | null>(null)
  const seenInvitations = useRef<Set<string> | null>(null)
  const seenJoinRequests = useRef<Set<string> | null>(null)

  useEffect(() => {
    if (!address) return
    const created = new NotifyTabs(address)
    setTabs(created)
    return () => {
      created.dispose()
      setTabs(null)
    }
  }, [address])

  // Keep this device's wake-up subscription current (a new server key, a
  // new language for the service worker's words, a lost server record).
  const service = chat.service
  const pushKey = chat.capabilities?.webPushPublicKey
  const language = t('chat.notifications.pushBody')
  useEffect(() => {
    if (!service || !pushKey || !getWebPush() || !webPushSupported() || !notificationsAllowed()) return
    enableWebPush(service, pushKey, pushWords(t)).catch((error: unknown) =>
      console.warn('chat: could not renew Web Push', error))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [service, pushKey, language])

  useEffect(() => {
    document.title = unread > 0 ? `(${unread}) ${baseTitle.current}` : baseTitle.current
  }, [unread])
  useEffect(() => {
    const title = baseTitle.current
    return () => {
      document.title = title
    }
  }, [])

  // What this tab shows, for the other tabs.
  const openKey = location.pathname.startsWith('/c/')
    ? decodeURIComponent(location.pathname.slice('/c/'.length))
    : null
  useEffect(() => {
    if (!tabs) return
    const announce = () => tabs.update(document.visibilityState === 'visible' && document.hasFocus(), openKey)
    announce()
    window.addEventListener('focus', announce)
    window.addEventListener('blur', announce)
    document.addEventListener('visibilitychange', announce)
    return () => {
      window.removeEventListener('focus', announce)
      window.removeEventListener('blur', announce)
      document.removeEventListener('visibilitychange', announce)
    }
  }, [tabs, openKey])

  function show(title: string, body: string, tag: string, path: string | null) {
    if (!getNotifications() || !notificationsAllowed()) return
    try {
      const notification = new Notification(title, {
        body,
        tag,
        icon: '/favicon.svg',
        silent: true,
        // Not in every TypeScript DOM library yet: alert again for a new message in the same chat.
        ...({ renotify: true } as NotificationOptions),
      })
      notification.onclick = () => {
        window.focus()
        if (path) void navigate(path)
        notification.close()
      }
    } catch (error) {
      // Some browsers only allow notifications from a service worker.
      console.warn('chat: could not show a notification', error)
    }
  }

  const profiles = useMemo(() => new Map(chat.snapshot.profiles.map((p) => [p.peer, p])), [chat.snapshot.profiles])
  const groupInfo = useMemo(
    () => new Map(chat.snapshot.groups.map((group) => [group.request.genesis.conversationId, group.currentGroupInfo])),
    [chat.snapshot.groups],
  )

  function describe(notice: Notice): { title: string; body: string } {
    const content = getNotificationContent()
    const appName = t('chat.notifications.appName')
    if (content === 'none') return { title: appName, body: t('chat.notifications.newMessage') }
    const conversation = notice.entry.conversation
    const sender = personName(notice.sender, profiles, address, t)
    const group = conversation.kind === 'group' ? groupTitle(conversation.groupId, t, groupInfo.get(conversation.groupId)) : null
    const title = group ?? sender
    if (content === 'name') {
      const body = notice.kind === 'reaction'
        ? t('chat.notifications.reactedHidden', { name: sender })
        : group ? t('chat.notifications.newMessageFrom', { name: sender }) : t('chat.notifications.newMessage')
      return { title, body }
    }
    const nameOf = (member: string) => personName(member, profiles, address, t)
    if (notice.kind === 'reaction') {
      const preview = messagePreview(notice.target, null, t, { self: address, nameOf })
      return { title, body: t('chat.notifications.reacted', { name: sender, emoji: notice.emoji, preview }) }
    }
    const preview = notice.entry.content.viewOnce
      ? t('chat.notifications.viewOnce')
      : messagePreview(notice.entry, null, t, { self: address, nameOf })
    return { title, body: group ? `${sender}: ${preview}` : preview }
  }

  // New history entries.
  const history = chat.snapshot.history
  useEffect(() => {
    if (!chat.loaded || !tabs) return
    if (seenEntries.current === null) {
      // What was there when the chat opened is not news.
      seenEntries.current = new Set(history.map((entry) => entry.id))
      return
    }
    const seen = seenEntries.current
    const fresh = history.filter((entry) => !seen.has(entry.id))
    for (const entry of fresh) seen.add(entry.id)
    if (fresh.length === 0 || !tabs.isNotifier) return
    const blocked = new Set(chat.snapshot.contacts.filter((c) => c.state === 'blocked').map((c) => c.peer))
    const notices = noticesFor(fresh, history, {
      selfAddress: address,
      nowMs: Date.now(),
      lists,
      readThrough,
      blocked,
      focusedKey: tabs.focusedKey(),
    })
    if (notices.length === 0) return
    if (getNotifications() && getNotificationSound()) playNotificationSound()
    if (tabs.anyFocused()) return
    if (notices.length > MAX_AT_ONCE) {
      show(t('chat.notifications.appName'), t('chat.notifications.many', { count: notices.length }), 'kutup-chat', '/')
      return
    }
    const hidden = getNotificationContent() === 'none'
    for (const notice of notices) {
      const { title, body } = describe(notice)
      show(title, body, hidden ? 'kutup-chat' : notice.key, hidden ? '/' : pathForKey(notice.key))
    }
    // Only this history change: the rest are read from the render that made it.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [history, chat.loaded, tabs])

  // Group invitations.
  const invitations = chat.snapshot.invitations
  useEffect(() => {
    if (!chat.loaded || !tabs) return
    const ids = invitations.map((invitation) => `${invitation.conversationId}:${invitation.incarnation}`)
    if (seenInvitations.current === null) {
      seenInvitations.current = new Set(ids)
      return
    }
    const seen = seenInvitations.current
    const fresh = ids.filter((id) => !seen.has(id))
    for (const id of fresh) seen.add(id)
    // One this account asked for through a link is accepted by itself.
    const requested = new Set(chat.snapshot.ownJoinRequests.map((request) => request.conversationId))
    const news = invitations.filter((invitation) =>
      fresh.includes(`${invitation.conversationId}:${invitation.incarnation}`) && !requested.has(invitation.conversationId))
    if (news.length === 0 || !tabs.isNotifier) return
    if (getNotifications() && getNotificationSound()) playNotificationSound()
    if (tabs.anyFocused()) return
    show(t('chat.notifications.appName'), t('chat.notifications.invited', { count: news.length }), 'kutup-chat-invitations', '/')
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [invitations, chat.loaded, tabs])

  // People asking to join groups this account administers.
  const joinRequests = chat.snapshot.joinRequests
  useEffect(() => {
    if (!chat.loaded || !tabs) return
    const ids = joinRequests.map((request) => `${request.conversationId}:${request.requester}`)
    if (seenJoinRequests.current === null) {
      seenJoinRequests.current = new Set(ids)
      return
    }
    const seen = seenJoinRequests.current
    const news = joinRequests.filter((request) => !seen.has(`${request.conversationId}:${request.requester}`))
    for (const id of ids) seen.add(id)
    if (news.length === 0 || !tabs.isNotifier) return
    if (getNotifications() && getNotificationSound()) playNotificationSound()
    if (tabs.anyFocused()) return
    const hidden = getNotificationContent() === 'none'
    for (const request of news.slice(0, MAX_AT_ONCE)) {
      const key = `group:${request.conversationId}`
      show(
        hidden ? t('chat.notifications.appName') : groupTitle(request.conversationId, t, groupInfo.get(request.conversationId)),
        hidden
          ? t('chat.notifications.joinRequestHidden')
          : t('chat.notifications.joinRequest', { name: personName(request.requester, profiles, address, t) }),
        `kutup-chat-join:${request.conversationId}`,
        pathForKey(key),
      )
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [joinRequests, chat.loaded, tabs])

  return null
}

function pathForKey(key: string): string {
  const conversation = parseConversationKey(key)
  return conversation ? pathForConversation(conversation) : '/'
}
