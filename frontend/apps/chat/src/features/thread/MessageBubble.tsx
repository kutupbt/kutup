import { Check, CheckCheck, Copy, Forward, MoreHorizontal, Pencil, Reply, SmilePlus, Sticker as StickerIcon, Timer, Trash2 } from 'lucide-react'
import { useEffect, useRef, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { formatRemainingTime } from '@kutup/chat-core/disappearing'
import { CHAT_REACTION_EMOJIS, type ChatReactionEmoji, type ReactionAggregate } from '@kutup/chat-core/reactions'
import { Button } from '@kutup/ui/components/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@kutup/ui/components/dropdown-menu'
import { cn } from '@kutup/ui/lib/cn'
import { Avatar } from '../../components/Avatar'
import { messagePreview } from '../../lib/names'
import { formatClock } from '../../lib/time'
import { useNow } from '../../lib/useNow'
import type { MessageView } from '../../state/views'
import { LinkPreviewCard } from '../linkPreview/LinkPreviewCard'
import { MessageText } from './MessageText'

export interface BubbleActions {
  onReply?: () => void
  onReact?: (emoji: ChatReactionEmoji, active: boolean) => void
  onEdit?: () => void
  onDelete?: () => void
  onForward?: () => void
  /** Add a received sticker to your own. */
  onSaveSticker?: () => void
  /** Scroll to the message a reply quotes. */
  onJump?: (messageId: string) => void
}

/**
 * One message, as Signal Desktop draws it: outgoing on the right in the
 * accent colour, incoming on the left on a neutral surface; a group's
 * messages share tighter corners, with the author's name on the first and
 * picture and time on the last. Replies quote their original inside the
 * bubble; reactions sit on its lower edge; the actions (react, reply, more)
 * appear beside it on hover or focus.
 */
export function MessageBubble({
  view,
  inGroup,
  authorName,
  authorImage,
  joinedAbove,
  joinedBelow,
  highlighted,
  profiles,
  selfAddress,
  selfName,
  actions,
  attachment,
  onVisible,
}: {
  view: MessageView
  /** A group conversation: incoming messages show who wrote them. */
  inGroup: boolean
  authorName: string
  authorImage?: { data: string; contentType?: string }
  joinedAbove: boolean
  joinedBelow: boolean
  highlighted: boolean
  profiles: ReadonlyMap<string, { displayName: string }>
  selfAddress: string
  /** This account's profile name, for mentions of you. */
  selfName?: string
  actions: BubbleActions
  /** The attachment's body, drawn by the media feature. */
  attachment?: ReactNode
  /** First shown on screen (starts a disappearing message's countdown). */
  onVisible?: () => void
}) {
  const { t, i18n } = useTranslation()
  const ref = useRef<HTMLDivElement>(null)
  const { entry, outgoing, mutation } = view
  const deleted = mutation?.deleted === true
  const text = mutation?.editedText ?? entry.content.text
  const expiresAt = entry.content.expiresAtMs
  const edited = mutation?.editedText !== undefined && !deleted
  const showMeta = !joinedBelow || edited || expiresAt !== undefined

  useEffect(() => {
    const element = ref.current
    if (!element || !onVisible || typeof IntersectionObserver === 'undefined') return
    const observer = new IntersectionObserver((items) => {
      if (items.some((item) => item.isIntersecting)) onVisible()
    }, { threshold: 0.1 })
    observer.observe(element)
    return () => observer.disconnect()
  }, [onVisible])

  const corners = outgoing
    ? cn(joinedAbove && 'rounded-tr-[4px]', joinedBelow && 'rounded-br-[4px]')
    : cn(joinedAbove && 'rounded-tl-[4px]', joinedBelow && 'rounded-bl-[4px]')

  return (
    <div
      ref={ref}
      id={`chat-message-${entry.direction}-${entry.id}`}
      data-testid="chat-message"
      data-message-id={view.id}
      className={cn(
        'group flex items-end gap-2 px-4',
        outgoing ? 'flex-row-reverse' : 'flex-row',
        joinedAbove ? 'mt-px' : 'mt-1.5',
        view.reactions.length > 0 && !deleted && 'mb-3',
      )}
    >
      {!outgoing && inGroup ? (
        joinedBelow ? (
          <span className="w-7 shrink-0" aria-hidden />
        ) : (
          <Avatar name={authorName} image={authorImage?.data} contentType={authorImage?.contentType} size={28} />
        )
      ) : null}

      <div className={cn('relative flex min-w-0 max-w-[min(30rem,calc(100%-3rem))] flex-col', outgoing ? 'items-end' : 'items-start')}>
        <div
          className={cn(
            'relative min-w-0 max-w-full rounded-[18px] px-3 py-2 text-sm leading-5 transition-shadow',
            deleted
              ? 'border border-border bg-transparent text-muted-foreground'
              : entry.content.sticker
                ? // A sticker stands on its own, as in Signal.
                  'bg-transparent p-0 text-foreground'
                : outgoing
                  ? 'bg-primary text-primary-foreground'
                  : 'bg-muted text-foreground',
            corners,
            highlighted && 'ring-2 ring-ring ring-offset-2 ring-offset-background',
          )}
        >
          {!outgoing && inGroup && !joinedAbove && !deleted ? (
            <p className="mb-0.5 truncate text-xs font-semibold text-primary">{authorName}</p>
          ) : null}

          {entry.content.replyTo && !deleted ? (
            <button
              type="button"
              data-testid="chat-reply-context"
              onClick={() => entry.content.replyTo && actions.onJump?.(entry.content.replyTo)}
              className={cn(
                'mb-1.5 block w-full min-w-40 rounded-lg rounded-b-sm border-l-4 px-2 py-1.5 text-left text-xs',
                outgoing ? 'border-primary-foreground/70 bg-primary-foreground/15' : 'border-primary bg-background/70',
              )}
            >
              {view.replyTo ? (
                <>
                  <span className="block font-semibold">
                    {view.replyTo.direction === 'outgoing'
                      ? t('chat.you')
                      : profiles.get(view.replyTo.peer)?.displayName || view.replyTo.peer}
                  </span>
                  <span className="line-clamp-2 opacity-90">{messagePreview(view.replyTo, view.replyToMutation, t)}</span>
                </>
              ) : (
                <span className="italic opacity-80">{t('chat.replies.unavailable')}</span>
              )}
            </button>
          ) : null}

          {entry.content.forwarded && !deleted ? (
            <p className="mb-0.5 flex items-center gap-1 text-xs italic opacity-80" data-testid="chat-message-forwarded">
              <Forward className="size-3" aria-hidden />
              {t('chat.forward.label')}
            </p>
          ) : null}
          {deleted ? (
            <p className="italic" data-testid="chat-message-deleted">
              {outgoing ? t('chat.mutations.youDeleted') : t('chat.mutations.deleted')}
            </p>
          ) : entry.content.attachment || view.viewedOnce || view.poll ? (
            attachment
          ) : (
            <>
              {entry.content.linkPreview && !edited ? <LinkPreviewCard preview={entry.content.linkPreview} outgoing={outgoing} /> : null}
              <MessageText
                text={text ?? t('chat.newerClient')}
                outgoing={outgoing}
                // An edit replaces the text its mentions were ranges of.
                mentions={edited ? undefined : entry.content.mentions}
                nameOf={(address) => (address === selfAddress ? selfName : profiles.get(address)?.displayName) || address}
                selfAddress={selfAddress}
              />
            </>
          )}

          {showMeta ? (
            <span
              className={cn(
                'mt-0.5 flex items-center justify-end gap-1 text-[0.6875rem] leading-4',
                deleted ? 'text-muted-foreground' : outgoing ? 'text-primary-foreground/75' : 'text-muted-foreground',
              )}
            >
              {edited ? <span data-testid="chat-message-edited">{t('chat.mutations.edited')}</span> : null}
              <time dateTime={new Date(entry.timestampMs).toISOString()}>{formatClock(entry.timestampMs, i18n.language)}</time>
              {expiresAt !== undefined ? <Countdown expiresAt={expiresAt} /> : null}
              {outgoing && !deleted ? <DeliveryStatus view={view} /> : null}
            </span>
          ) : null}
        </div>

        {view.reactions.length > 0 && !deleted ? (
          <Reactions
            reactions={view.reactions}
            outgoing={outgoing}
            selfAddress={selfAddress}
            profiles={profiles}
            onReact={actions.onReact}
          />
        ) : null}
      </div>

      {/* A deleted message can still be removed from here, as in Signal. */}
      <HoverActions view={view} text={deleted ? undefined : text} actions={deleted ? { onJump: actions.onJump, onDelete: actions.onDelete } : actions} />
    </div>
  )
}

/** How long a disappearing message has left, ticking every second. */
function Countdown({ expiresAt }: { expiresAt: number }) {
  const { t } = useTranslation()
  const now = useNow(1_000)
  const left = formatRemainingTime(expiresAt - now)
  return (
    <span className="flex items-center gap-0.5" title={t('chat.disappearing.expires', { time: left })} data-testid="chat-message-expiry">
      <Timer className="size-3" aria-hidden />
      {left}
    </span>
  )
}

function DeliveryStatus({ view }: { view: MessageView }) {
  const { t } = useTranslation()
  const { receipt, entry } = view
  if (receipt?.read) {
    const label = t('chat.receipts.readBy', { count: receipt.read })
    return (
      <span className="flex items-center" title={label} aria-label={label} data-testid="chat-receipt-read">
        <CheckCheck className="size-3.5" strokeWidth={2.75} />
      </span>
    )
  }
  if (receipt?.delivered) {
    const label = t('chat.receipts.deliveredTo', { count: receipt.delivered })
    return (
      <span className="flex items-center opacity-80" title={label} aria-label={label} data-testid="chat-receipt-delivered">
        <CheckCheck className="size-3.5" />
      </span>
    )
  }
  if (entry.delivered) {
    return (
      <span className="flex items-center opacity-80" title={t('chat.receipts.sent')} aria-label={t('chat.receipts.sent')}>
        <Check className="size-3.5" />
      </span>
    )
  }
  return null
}

function Reactions({
  reactions,
  outgoing,
  selfAddress,
  profiles,
  onReact,
}: {
  reactions: ReactionAggregate[]
  outgoing: boolean
  selfAddress: string
  profiles: ReadonlyMap<string, { displayName: string }>
  onReact?: (emoji: ChatReactionEmoji, active: boolean) => void
}) {
  const { t } = useTranslation()
  return (
    <div
      className={cn('absolute -bottom-3.5 z-10 flex gap-1', outgoing ? 'right-2' : 'left-2')}
      data-testid="chat-reactions"
    >
      {reactions.map((reaction) => (
        <DropdownMenu key={reaction.emoji}>
          <DropdownMenuTrigger asChild>
            <button
              type="button"
              className={cn(
                'flex h-[1.375rem] min-w-7 items-center justify-center gap-1 rounded-full border-2 border-background px-1.5 text-xs outline-none transition-colors focus-visible:ring-2 focus-visible:ring-ring',
                reaction.reactedBySelf ? 'bg-accent text-accent-foreground' : 'bg-muted text-foreground hover:bg-accent',
              )}
              aria-label={t('chat.reactions.details', { emoji: reaction.emoji, count: reaction.count })}
              data-testid="chat-reaction-aggregate"
              data-emoji={reaction.emoji}
              data-count={reaction.count}
            >
              <span>{reaction.emoji}</span>
              {reaction.count > 1 ? <span className="font-semibold tabular-nums">{reaction.count}</span> : null}
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align={outgoing ? 'end' : 'start'} className="min-w-56">
            <div className="border-b border-border px-2 py-1.5 text-xs font-medium text-muted-foreground">
              {reaction.emoji} {t('chat.reactions.reactedWith')}
            </div>
            {reaction.reactors.map((reactor) => {
              const mine = reactor === selfAddress
              const label = mine ? t('chat.reactions.you') : profiles.get(reactor)?.displayName || reactor
              if (mine && reaction.reactedBySelf && onReact) {
                return (
                  <DropdownMenuItem key={reactor} onSelect={() => onReact(reaction.emoji, false)}>
                    <span className="min-w-0 flex-1 truncate">{label}</span>
                    <span className="text-xs text-muted-foreground">{t('chat.reactions.removeMine')}</span>
                  </DropdownMenuItem>
                )
              }
              return (
                <div key={reactor} className="truncate px-2 py-1.5 text-sm">
                  {label}
                </div>
              )
            })}
          </DropdownMenuContent>
        </DropdownMenu>
      ))}
    </div>
  )
}

function HoverActions({ view, text, actions }: { view: MessageView; text: string | undefined; actions: BubbleActions }) {
  const { t } = useTranslation()
  const mine = view.reactions.find((r) => r.reactedBySelf)?.emoji
  const reveal = 'opacity-70 md:opacity-0 md:transition-opacity md:group-hover:opacity-100 md:group-focus-within:opacity-100 md:focus-visible:opacity-100 data-[state=open]:opacity-100'
  const hasMore = Boolean(actions.onEdit || actions.onDelete || actions.onForward || actions.onSaveSticker || text)
  if (!actions.onReact && !actions.onReply && !hasMore) return null
  return (
    <div className="flex shrink-0 items-center gap-0.5 self-center">
      {actions.onReact ? (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button type="button" size="icon" variant="ghost" className={cn('size-8 rounded-full', reveal)} aria-label={t('chat.reactions.add')} data-testid="chat-reaction-button">
              <SmilePlus className="size-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent className="min-w-0 rounded-full p-1" data-testid="chat-reaction-picker">
            <div className="flex gap-0.5">
              {CHAT_REACTION_EMOJIS.map((emoji) => (
                <DropdownMenuItem
                  key={emoji}
                  className={cn('size-9 cursor-pointer justify-center rounded-full p-0 text-xl', mine === emoji && 'bg-accent')}
                  onSelect={() => actions.onReact?.(emoji, mine !== emoji)}
                  aria-label={mine === emoji ? `${emoji} ${t('chat.reactions.removeMine')}` : t('chat.reactions.addEmoji', { emoji })}
                  aria-pressed={mine === emoji}
                  data-emoji={emoji}
                >
                  {emoji}
                </DropdownMenuItem>
              ))}
            </div>
          </DropdownMenuContent>
        </DropdownMenu>
      ) : null}
      {actions.onReply ? (
        <Button type="button" size="icon" variant="ghost" className={cn('size-8 rounded-full', reveal)} onClick={actions.onReply} aria-label={t('chat.replies.reply')} data-testid="chat-reply-button">
          <Reply className="size-4" />
        </Button>
      ) : null}
      {hasMore ? (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button type="button" size="icon" variant="ghost" className={cn('size-8 rounded-full', reveal)} aria-label={t('chat.message.more')}>
              <MoreHorizontal className="size-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align={view.outgoing ? 'end' : 'start'}>
            {text ? (
              <DropdownMenuItem
                onSelect={() => {
                  void navigator.clipboard
                    .writeText(text)
                    .then(() => toast.success(t('chat.message.copied')))
                    .catch(() => toast.error(t('chat.message.copyFailed')))
                }}
              >
                <Copy />
                {t('chat.message.copy')}
              </DropdownMenuItem>
            ) : null}
            {actions.onSaveSticker ? (
              <DropdownMenuItem onSelect={actions.onSaveSticker} data-testid="chat-save-sticker">
                <StickerIcon />
                {t('chat.stickers.save')}
              </DropdownMenuItem>
            ) : null}
            {actions.onForward ? (
              <DropdownMenuItem onSelect={actions.onForward} data-testid="chat-forward-button">
                <Forward />
                {t('chat.forward.action')}
              </DropdownMenuItem>
            ) : null}
            {actions.onEdit ? (
              <DropdownMenuItem onSelect={actions.onEdit} data-testid="chat-edit-button">
                <Pencil />
                {t('chat.mutations.edit')}
              </DropdownMenuItem>
            ) : null}
            {actions.onDelete ? (
              <DropdownMenuItem onSelect={actions.onDelete} className="text-destructive focus:text-destructive" data-testid="chat-delete-button">
                <Trash2 />
                {t('chat.mutations.delete')}
              </DropdownMenuItem>
            ) : null}
          </DropdownMenuContent>
        </DropdownMenu>
      ) : null}
    </div>
  )
}
