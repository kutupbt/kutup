import { Ban, MessageSquareDashed } from 'lucide-react'
import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { cn } from '@kutup/ui/lib/cn'
import { useChat } from '../../app/chatStore'
import { Avatar } from '../../components/Avatar'
import { conversationTitle, messagePreview, personName } from '../../lib/names'
import { formatShortTime } from '../../lib/time'
import { useNow } from '../../lib/useNow'
import { useReadMarks } from '../../state/readState'
import { conversationList, foldMutations, unreadCounts, type ConversationSummary } from '../../state/views'
import { conversationPath } from './paths'

/**
 * The conversations, newest first, as Signal Desktop lists them: picture,
 * name and time on the first line; the latest message (or "Message
 * request", "Blocked", who is typing) on the next two; an unread count.
 */
export function ConversationList({ selectedKey }: { selectedKey: string | null }) {
  const { t, i18n } = useTranslation()
  const chat = useChat()
  const now = useNow(60_000)
  const marks = useReadMarks()
  const self = chat.self!
  const { snapshot } = chat

  const items = useMemo(() => conversationList(snapshot, self.address, now), [snapshot, self.address, now])
  const mutations = useMemo(() => foldMutations(snapshot.history, self.address), [snapshot.history, self.address])
  const unread = useMemo(() => unreadCounts(snapshot.history, marks, now), [snapshot.history, marks, now])
  const profiles = useMemo(() => new Map(snapshot.profiles.map((p) => [p.peer, p])), [snapshot.profiles])

  if (items.length === 0) {
    return (
      <div className="flex flex-col items-center gap-3 px-8 pt-24 text-center text-sm text-muted-foreground">
        <MessageSquareDashed className="size-8" aria-hidden />
        <p>{t('chat.empty')}</p>
      </div>
    )
  }

  return (
    <ul className="space-y-0.5 px-2 py-2" aria-label={t('chat.list.label')}>
      {items.map((item) => (
        <li key={item.key}>
          <ConversationRow
            item={item}
            selected={item.key === selectedKey}
            title={conversationTitle(item.conversation, item.address, item.profile, self.address, t)}
            snippet={snippet(item)}
            time={item.last || item.activityMs ? formatShortTime(item.last?.timestampMs ?? item.activityMs, now, i18n.language, t) : ''}
            unread={item.key === selectedKey ? 0 : (unread.get(item.key) ?? 0)}
            typing={(chat.typing.get(item.key)?.size ?? 0) > 0}
          />
        </li>
      ))}
    </ul>
  )

  function snippet(item: ConversationSummary): { text: string; tone?: 'request' | 'blocked' } {
    if (item.contact?.state === 'blocked') return { text: t('chat.list.blocked'), tone: 'blocked' }
    if (item.contact?.state === 'pendingIncoming') return { text: t('chat.list.request'), tone: 'request' }
    if (!item.last) {
      return { text: item.kind === 'group' ? t('chat.list.newGroup') : '' }
    }
    const preview = messagePreview(item.last, mutations.get(item.last.content.messageId ?? item.last.id), t)
    if (item.conversation.kind === 'group') {
      const author = item.last.direction === 'outgoing' ? self.address : item.last.peer
      return { text: t('chat.list.byAuthor', { author: personName(author, profiles, self.address, t), text: preview }) }
    }
    return { text: preview }
  }
}

function ConversationRow({
  item,
  selected,
  title,
  snippet,
  time,
  unread,
  typing,
}: {
  item: ConversationSummary
  selected: boolean
  title: string
  snippet: { text: string; tone?: 'request' | 'blocked' }
  time: string
  unread: number
  typing: boolean
}) {
  const { t } = useTranslation()
  return (
    <Link
      to={conversationPath(item.key)}
      aria-current={selected ? 'page' : undefined}
      data-testid={item.conversation.kind === 'group' ? `chat-group-${item.conversation.groupId}` : undefined}
      className={cn(
        'flex h-[4.5rem] items-center gap-3 rounded-[10px] px-3 outline-none transition-colors',
        'hover:bg-muted focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring',
        selected && 'bg-accent hover:bg-accent',
      )}
    >
      <Avatar
        name={title}
        image={item.profile?.avatar}
        contentType={item.profile?.avatarContentType}
        group={item.conversation.kind === 'group'}
      />
      <span className="min-w-0 flex-1">
        <span className="flex items-baseline gap-1.5">
          <span className="min-w-0 flex-1 truncate text-sm font-semibold text-foreground">{title}</span>
          <span className={cn('shrink-0 text-xs', unread > 0 ? 'font-semibold text-primary' : 'text-muted-foreground')}>
            {time}
          </span>
        </span>
        <span className="mt-0.5 flex items-start gap-2">
          <span
            className={cn(
              'line-clamp-2 min-h-[2.25rem] min-w-0 flex-1 text-[0.8125rem] leading-[1.125rem] text-muted-foreground',
              snippet.tone === 'request' && 'font-medium text-primary',
            )}
          >
            {typing ? (
              <span className="italic">{t('chat.typing.short')}</span>
            ) : snippet.tone === 'blocked' ? (
              <span className="inline-flex items-center gap-1">
                <Ban className="size-3.5" aria-hidden />
                {snippet.text}
              </span>
            ) : (
              snippet.text
            )}
          </span>
          {unread > 0 ? (
            <span
              className="mt-0.5 inline-flex h-[1.125rem] min-w-[1.125rem] shrink-0 items-center justify-center rounded-full bg-primary px-1 text-[0.6875rem] font-bold text-primary-foreground"
              aria-label={t('chat.list.unread', { count: unread })}
            >
              {unread > 99 ? '99+' : unread}
            </span>
          ) : null}
        </span>
      </span>
    </Link>
  )
}
