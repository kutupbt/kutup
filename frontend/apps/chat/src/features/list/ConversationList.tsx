import { Archive, ArrowLeft, Ban, BellOff, MessageSquareDashed, MoreHorizontal, Pin } from 'lucide-react'
import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useNavigate } from 'react-router-dom'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { ContextMenu, ContextMenuContent, ContextMenuTrigger } from '@kutup/ui/components/context-menu'
import { DropdownMenu, DropdownMenuContent, DropdownMenuTrigger } from '@kutup/ui/components/dropdown-menu'
import { cn } from '@kutup/ui/lib/cn'
import { useChat } from '../../app/chatStore'
import { Avatar } from '../../components/Avatar'
import { conversationTitle, messagePreview, personName } from '../../lib/names'
import { formatShortTime } from '../../lib/time'
import { useNow } from '../../lib/useNow'
import { isArchived, isMuted, type ListState } from '../../state/accountState'
import { setListPane, useListPane } from '../../state/listPane'
import { useAccountState, useReadThrough } from '../../state/useAccountState'
import { conversationList, foldMutations, unreadCounts, type ConversationSummary } from '../../state/views'
import { ConversationMenuItems } from './ConversationMenu'
import { CONTEXT_PARTS, DROPDOWN_PARTS } from './menuParts'
import { conversationPath } from './paths'
import { useListActions } from './useListActions'

/**
 * The conversations as Signal Desktop lists them: pinned ones first, then
 * the rest newest first; archived ones behind "Archived chats". A row has
 * the picture, name and time on the first line, the latest message (or
 * "Message request", "Blocked", who is typing) on the next two, and an
 * unread count. Right click (or "⋯") for pin, mark unread, mute, archive,
 * delete.
 */
export function ConversationList({ selectedKey }: { selectedKey: string | null }) {
  const { t, i18n } = useTranslation()
  const chat = useChat()
  const navigate = useNavigate()
  const now = useNow(60_000)
  const readThrough = useReadThrough()
  const { lists } = useAccountState()
  const pane = useListPane()
  const actions = useListActions()
  const [deleting, setDeleting] = useState<ConversationSummary | null>(null)
  const self = chat.self!
  const { snapshot } = chat

  const items = useMemo(() => conversationList(snapshot, self.address, now), [snapshot, self.address, now])
  const mutations = useMemo(() => foldMutations(snapshot.history, self.address), [snapshot.history, self.address])
  const unread = useMemo(() => unreadCounts(snapshot.history, readThrough, now), [snapshot.history, readThrough, now])
  const profiles = useMemo(() => new Map(snapshot.profiles.map((p) => [p.peer, p])), [snapshot.profiles])

  const { inbox, archived } = useMemo(() => {
    const inbox: ConversationSummary[] = []
    const archived: ConversationSummary[] = []
    for (const item of items) {
      if (isArchived(lists.get(item.key), item.last, now)) archived.push(item)
      else inbox.push(item)
    }
    // Pinned first; each group keeps newest-first.
    inbox.sort((a, b) => Number(lists.get(b.key)?.pinned ?? false) - Number(lists.get(a.key)?.pinned ?? false))
    return { inbox, archived }
  }, [items, lists, now])

  // Nothing left in the archive: back to the chats.
  useEffect(() => {
    if (pane === 'archived' && archived.length === 0) setListPane('inbox')
  }, [pane, archived.length])

  const shown = pane === 'archived' ? archived : inbox

  if (items.length === 0) {
    return (
      <div className="flex flex-col items-center gap-3 px-8 pt-24 text-center text-sm text-muted-foreground">
        <MessageSquareDashed className="size-8" aria-hidden />
        <p>{t('chat.empty')}</p>
      </div>
    )
  }

  return (
    <>
      {pane === 'archived' ? (
        <div className="flex items-center gap-2 px-2 pt-2">
          <Button variant="ghost" size="icon" onClick={() => setListPane('inbox')} aria-label={t('chat.list.backToChats')}>
            <ArrowLeft />
          </Button>
          <h2 className="text-sm font-semibold">{t('chat.list.archived')}</h2>
        </div>
      ) : null}
      <ul className="space-y-0.5 px-2 py-2" aria-label={pane === 'archived' ? t('chat.list.archived') : t('chat.list.label')}>
        {shown.map((item) => {
          const count = item.key === selectedKey ? 0 : (unread.get(item.key) ?? 0)
          const state = lists.get(item.key)
          return (
            <li key={item.key}>
              <ConversationRow
                item={item}
                state={state}
                muted={isMuted(state, now)}
                selected={item.key === selectedKey}
                title={conversationTitle(item.conversation, item.address, item.profile, self.address, t, item.groupInfo)}
                snippet={snippet(item)}
                time={item.last || item.activityMs ? formatShortTime(item.last?.timestampMs ?? item.activityMs, now, i18n.language, t) : ''}
                unread={count}
                typing={(chat.typing.get(item.key)?.size ?? 0) > 0}
                menu={(parts) => (
                  <ConversationMenuItems
                    parts={parts}
                    conversation={item.conversation}
                    last={item.last}
                    unread={count > 0 || (state?.markedUnread ?? false)}
                    onDelete={() => setDeleting(item)}
                    onMarkUnread={() => {
                      if (item.key === selectedKey) void navigate('/')
                    }}
                  />
                )}
              />
            </li>
          )
        })}
        {pane === 'inbox' && archived.length > 0 ? (
          <li>
            <button
              type="button"
              onClick={() => setListPane('archived')}
              className="flex h-12 w-full items-center gap-3 rounded-[10px] px-3 text-left text-sm outline-none transition-colors hover:bg-muted focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring"
              data-testid="chat-archived-open"
            >
              <span className="flex size-12 shrink-0 items-center justify-center" aria-hidden>
                <Archive className="size-5 text-muted-foreground" />
              </span>
              <span className="flex-1 font-medium">{t('chat.list.archived')}</span>
              <span className="text-xs text-muted-foreground">{archived.length}</span>
            </button>
          </li>
        ) : null}
      </ul>
      <ConfirmDestructive
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={t('chat.list.deleteTitle')}
        description={t('chat.list.deleteDescription')}
        submit={t('chat.list.delete')}
        errorFallback={t('chat.errors.unavailable')}
        onConfirm={() => {
          const target = deleting
          setDeleting(null)
          if (!target) return
          if (target.key === selectedKey) void navigate('/')
          void actions.deleteChat(target.conversation)
        }}
      />
    </>
  )

  function snippet(item: ConversationSummary): { text: string; tone?: 'request' | 'blocked' } {
    if (item.contact?.state === 'blocked') return { text: t('chat.list.blocked'), tone: 'blocked' }
    if (item.contact?.state === 'pendingIncoming') return { text: t('chat.list.request'), tone: 'request' }
    if (!item.last) {
      return { text: item.kind === 'group' ? t('chat.list.newGroup') : '' }
    }
    const nameOf = (address: string) => personName(address, profiles, self.address, t)
    const preview = messagePreview(item.last, mutations.get(item.last.content.messageId ?? item.last.id), t, {
      self: self.address,
      nameOf,
    })
    if (item.last.content.groupUpdate) return { text: preview }
    if (item.conversation.kind === 'group') {
      const author = item.last.direction === 'outgoing' ? self.address : item.last.peer
      return { text: t('chat.list.byAuthor', { author: personName(author, profiles, self.address, t), text: preview }) }
    }
    return { text: preview }
  }
}

function ConversationRow({
  item,
  state,
  muted,
  selected,
  title,
  snippet,
  time,
  unread,
  typing,
  menu,
}: {
  item: ConversationSummary
  state: ListState | undefined
  muted: boolean
  selected: boolean
  title: string
  snippet: { text: string; tone?: 'request' | 'blocked' }
  time: string
  unread: number
  typing: boolean
  menu: (parts: typeof DROPDOWN_PARTS) => ReactNode
}) {
  const { t } = useTranslation()
  const [menuOpen, setMenuOpen] = useState(false)
  const markedUnread = unread === 0 && (state?.markedUnread ?? false)
  const highlighted = unread > 0 || markedUnread
  return (
    <ContextMenu>
      <ContextMenuTrigger asChild>
        <div className="group/row relative">
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
              image={item.groupInfo?.avatar?.data ?? item.profile?.avatar}
              contentType={item.groupInfo?.avatar?.contentType ?? item.profile?.avatarContentType}
              group={item.conversation.kind === 'group'}
            />
            <span className="min-w-0 flex-1">
              <span className="flex items-baseline gap-1.5">
                <span className="min-w-0 flex-1 truncate text-sm font-semibold text-foreground">
                  {title}
                  {muted ? (
                    <BellOff className="ml-1 inline size-3.5 align-[-2px] text-muted-foreground" aria-label={t('chat.list.muted')} />
                  ) : null}
                </span>
                <span
                  className={cn(
                    'shrink-0 text-xs group-focus-within/row:invisible group-hover/row:invisible',
                    highlighted && !muted ? 'font-semibold text-primary' : 'text-muted-foreground',
                    menuOpen && 'invisible',
                  )}
                >
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
                    className={cn(
                      'mt-0.5 inline-flex h-[1.125rem] min-w-[1.125rem] shrink-0 items-center justify-center rounded-full px-1 text-[0.6875rem] font-bold',
                      muted ? 'bg-muted-foreground/25 text-foreground' : 'bg-primary text-primary-foreground',
                    )}
                    aria-label={t('chat.list.unread', { count: unread })}
                  >
                    {unread > 99 ? '99+' : unread}
                  </span>
                ) : markedUnread ? (
                  <span
                    className={cn('mt-1.5 size-2.5 shrink-0 rounded-full', muted ? 'bg-muted-foreground/40' : 'bg-primary')}
                    role="img"
                    aria-label={t('chat.list.markedUnread')}
                    data-testid="chat-marked-unread"
                  />
                ) : state?.pinned ? (
                  <Pin className="mt-0.5 size-3.5 shrink-0 text-muted-foreground" aria-label={t('chat.list.pinned')} data-testid="chat-pinned" />
                ) : null}
              </span>
            </span>
          </Link>
          <DropdownMenu open={menuOpen} onOpenChange={setMenuOpen}>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                className={cn(
                  'absolute right-2 top-2 size-7 opacity-0 group-focus-within/row:opacity-100 group-hover/row:opacity-100',
                  menuOpen && 'opacity-100',
                )}
                aria-label={t('chat.list.actions', { name: title })}
                data-testid="chat-row-menu"
              >
                <MoreHorizontal />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">{menu(DROPDOWN_PARTS)}</DropdownMenuContent>
          </DropdownMenu>
        </div>
      </ContextMenuTrigger>
      <ContextMenuContent>{menu(CONTEXT_PARTS)}</ContextMenuContent>
    </ContextMenu>
  )
}
