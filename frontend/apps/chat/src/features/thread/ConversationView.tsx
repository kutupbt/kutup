import { ArrowLeft, Check, Info, Loader2, Timer } from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useSearchParams } from 'react-router-dom'
import type { ConversationId } from '@kutup/chat-core/types'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@kutup/ui/components/dropdown-menu'
import { cn } from '@kutup/ui/lib/cn'
import { refreshChat, useChat } from '../../app/chatStore'
import { Avatar } from '../../components/Avatar'
import { DISAPPEARING_PRESETS, disappearingLabel } from '../../lib/disappearing'
import { personName } from '../../lib/names'
import { formatDayHeader } from '../../lib/time'
import { useNow } from '../../lib/useNow'
import { setOpenConversation } from '../../state/openConversation'
import { getReadMark } from '../../state/readState'
import { timelineRows } from '../../state/timeline'
import type { MessageView } from '../../state/views'
import { DetailsPanel } from '../details/DetailsPanel'
import { AttachmentBody } from '../media/AttachmentBody'
import { Composer } from './Composer'
import { ConversationBar } from './ConversationBar'
import { MessageBubble } from './MessageBubble'
import { MessageScroller } from './MessageScroller'
import { useConversationActions } from './useConversationActions'
import { useConversationModel } from './useConversationModel'

/**
 * One conversation: its header, the timeline and the composer (or, where
 * nothing can be written, what to do instead: accept a request, unblock…).
 * The details panel slides over it, as in Signal Desktop.
 */
export function ConversationView({ conversation }: { conversation: ConversationId }) {
  const { t, i18n } = useTranslation()
  const chat = useChat()
  const service = chat.service!
  const self = chat.self!
  const now = useNow(15_000)
  const model = useConversationModel(conversation, now)
  const actions = useConversationActions(conversation, model.timerSeconds)
  const [params, setParams] = useSearchParams()
  const focus = params.get('focus')
  const [highlight, setHighlight] = useState<string | null>(focus)
  const [details, setDetails] = useState(false)
  const [replyingTo, setReplyingTo] = useState<MessageView | null>(null)
  const [editing, setEditing] = useState<MessageView | null>(null)
  const [deleting, setDeleting] = useState<MessageView | null>(null)
  const [timerBusy, setTimerBusy] = useState(false)
  // The read mark as it was on opening: where "unread messages" goes.
  const [unread] = useState(() => ({ after: getReadMark(model.key), openedAt: Date.now() }))
  const expiryStarted = useRef(new Set<string>())

  useEffect(() => {
    setOpenConversation(model.key)
    return () => setOpenConversation(null)
  }, [model.key])

  // A search result opens here highlighted, briefly.
  useEffect(() => {
    if (!focus) return
    setHighlight(focus)
    const timer = window.setTimeout(() => setHighlight(null), 2_500)
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev)
        next.delete('focus')
        return next
      },
      { replace: true },
    )
    return () => window.clearTimeout(timer)
  }, [focus, setParams])

  const profiles = useMemo(() => new Map(chat.snapshot.profiles.map((p) => [p.peer, p])), [chat.snapshot.profiles])
  const rows = useMemo(() => timelineRows(model.views, unread), [model.views, unread])
  const itemKeys = useMemo(() => rows.map((row) => row.key), [rows])
  const nameOf = useCallback((view: MessageView) => personName(view.author, profiles, self.address, t), [profiles, self.address, t])
  const lastOwnText = useMemo(
    () => [...model.views].reverse().find((v) => v.outgoing && !v.mutation?.deleted && v.entry.content.text && !v.entry.content.attachment) ?? null,
    [model.views],
  )
  const typing = [...(chat.typing.get(model.key)?.keys() ?? [])].filter((sender) => sender !== self.address)
  const writable = !model.readOnly

  const jump = useCallback((messageId: string) => {
    const element = document.querySelector(`[data-message-id="${CSS.escape(messageId)}"]`)
    if (!element) return
    element.scrollIntoView({ block: 'center', behavior: 'smooth' })
    setHighlight(messageId)
    window.setTimeout(() => setHighlight((current) => (current === messageId ? null : current)), 2_500)
  }, [])

  const startExpiry = useCallback(
    (view: MessageView) => {
      const content = view.entry.content
      if (view.outgoing || !content.messageId || !content.expiresAfterSeconds || content.expiresAtMs !== undefined) return
      if (expiryStarted.current.has(content.messageId)) return
      expiryStarted.current.add(content.messageId)
      void service
        .startDisappearingExpiry(conversation, content.messageId)
        .then(() => refreshChat())
        .catch((error: unknown) => console.warn('chat: expiry not started', error))
    },
    [service, conversation],
  )

  async function setTimer(seconds: number | undefined) {
    setTimerBusy(true)
    try {
      await actions.setTimer(seconds)
    } catch {
      // Said already.
    } finally {
      setTimerBusy(false)
    }
  }

  const subtitle = model.note
    ? t('chat.noteToSelfDescription')
    : model.group
      ? t('chat.group.members', { count: model.group.currentRoster.length })
      : model.timerSeconds !== undefined
        ? t('chat.disappearing.active', { duration: disappearingLabel(model.timerSeconds, t) })
        : model.address && model.profile?.displayName
          ? model.address
          : null

  return (
    <div className="relative flex h-full min-h-0 flex-col overflow-hidden">
      <header className="flex h-[3.25rem] shrink-0 items-center gap-3 border-b border-border px-3 shadow-[0_1px_2px_rgb(0_0_0/0.04)]">
        <Button variant="ghost" size="icon" className="md:hidden" asChild>
          <Link to="/" aria-label={t('chat.backToList')}>
            <ArrowLeft />
          </Link>
        </Button>
        <button
          type="button"
          onClick={() => setDetails(true)}
          className="flex min-w-0 flex-1 items-center gap-3 rounded-lg px-1 py-1 text-left outline-none hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring"
        >
          <Avatar name={model.title} image={model.profile?.avatar} contentType={model.profile?.avatarContentType} group={conversation.kind === 'group'} size={32} />
          <span className="min-w-0">
            <span className="block truncate text-sm font-semibold">{model.title}</span>
            {subtitle ? (
              <span className="flex items-center gap-1 truncate text-xs text-muted-foreground">
                {model.timerSeconds !== undefined && !model.note ? <Timer className="size-3 shrink-0" aria-hidden /> : null}
                {subtitle}
              </span>
            ) : null}
          </span>
        </button>
        {model.canSetTimer ? (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                disabled={timerBusy}
                aria-label={
                  model.timerSeconds === undefined
                    ? t('chat.disappearing.off')
                    : t('chat.disappearing.active', { duration: disappearingLabel(model.timerSeconds, t) })
                }
                data-testid="chat-disappearing-timer"
              >
                {timerBusy ? <Loader2 className="animate-spin" /> : <Timer className={cn(model.timerSeconds !== undefined && 'text-primary')} />}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" data-testid="chat-disappearing-menu">
              <DropdownMenuLabel>{t('chat.disappearing.setting')}</DropdownMenuLabel>
              <DropdownMenuSeparator />
              {DISAPPEARING_PRESETS.map((option) => (
                <DropdownMenuItem key={option.id} onSelect={() => void setTimer(option.seconds)} data-testid={`chat-disappearing-${option.id}`}>
                  <span className="flex-1">{t(`chat.disappearing.presets.${option.id}`)}</span>
                  {model.timerSeconds === option.seconds ? <Check className="ml-3" /> : null}
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        ) : null}
        <Button variant="ghost" size="icon" onClick={() => setDetails(true)} aria-label={t('chat.details.open')} data-testid={model.group ? 'chat-group-members' : undefined}>
          <Info />
        </Button>
      </header>

      <MessageScroller
        conversationKey={model.key}
        anchorId={focus ? null : rows.some((r) => r.kind === 'unread') ? 'chat-unread-marker' : null}
        itemKeys={itemKeys}
        jumpToLatestLabel={t('chat.jumpToLatest')}
        timelineLabel={t('chat.timeline')}
        className="pb-4"
      >
        {model.views.length === 0 ? (
          <p className="px-6 pt-16 text-center text-sm text-muted-foreground">
            {model.note ? t('chat.noteToSelfDescription') : t('chat.thread.empty')}
          </p>
        ) : null}
        {rows.map((row) => {
          if (row.kind === 'day') {
            return (
              <div key={row.key} className="px-4 pb-1 pt-5 text-center text-xs font-medium text-muted-foreground">
                {formatDayHeader(row.at, now, i18n.language, t)}
              </div>
            )
          }
          if (row.kind === 'unread') {
            return (
              <div key={row.key} id="chat-unread-marker" className="px-4 pb-4 pt-6">
                <div className="h-px bg-border" />
                <p className="mt-1.5 text-center text-xs font-semibold text-muted-foreground">
                  {t('chat.thread.unread', { count: row.count })}
                </p>
              </div>
            )
          }
          if (row.kind === 'notice') {
            const seconds = row.view.timerChange?.seconds
            const who = nameOf(row.view)
            return (
              <p key={row.key} className="mx-auto flex max-w-sm items-center justify-center gap-1.5 px-4 py-2.5 text-center text-xs text-muted-foreground">
                <Timer className="size-4 shrink-0" aria-hidden />
                {seconds === undefined
                  ? t('chat.disappearing.noticeOff', { name: who })
                  : t('chat.disappearing.noticeOn', { name: who, duration: disappearingLabel(seconds, t) })}
              </p>
            )
          }
          const view = row.view
          const author = view.outgoing ? null : profiles.get(view.author)
          const own = view.outgoing
          return (
            <MessageBubble
              key={row.key}
              view={view}
              inGroup={conversation.kind === 'group'}
              authorName={nameOf(view)}
              authorImage={author?.avatar ? { data: author.avatar, contentType: author.avatarContentType } : undefined}
              joinedAbove={row.joinedAbove}
              joinedBelow={row.joinedBelow}
              highlighted={highlight === view.id}
              profiles={profiles}
              selfAddress={self.address}
              onVisible={() => startExpiry(view)}
              attachment={
                view.entry.content.attachment ? (
                  <AttachmentBody
                    attachment={view.entry.content.attachment}
                    outgoing={own}
                    accepted={model.contact?.state !== 'pendingIncoming' && model.contact?.state !== 'blocked'}
                    expiresAtMs={view.entry.content.expiresAtMs}
                    deleted={view.mutation?.deleted === true}
                  />
                ) : undefined
              }
              actions={{
                onJump: jump,
                onReply: writable && view.entry.content.messageId ? () => { setEditing(null); setReplyingTo(view) } : undefined,
                onReact:
                  writable && view.entry.content.messageId
                    ? (emoji, active) => void actions.react(view.id, emoji, active).catch(() => undefined)
                    : undefined,
                onEdit:
                  writable && own && view.entry.content.messageId && view.entry.content.text && !view.entry.content.attachment
                    ? () => { setReplyingTo(null); setEditing(view) }
                    : undefined,
                onDelete: writable && own && view.entry.content.messageId ? () => setDeleting(view) : undefined,
              }}
            />
          )
        })}
        {typing.length > 0 ? (
          <div className="mt-2 flex items-center gap-2 px-4" data-testid="chat-typing-indicator" aria-live="polite">
            <span className="inline-flex gap-1 rounded-[18px] bg-muted px-3 py-2.5" aria-hidden>
              {[0, 1, 2].map((i) => (
                <span key={i} className="size-1.5 animate-bounce rounded-full bg-muted-foreground" style={{ animationDelay: `${i * 150}ms` }} />
              ))}
            </span>
            <span className="text-xs text-muted-foreground">
              {typing.length === 1
                ? t('chat.typing.one', { name: personName(typing[0], profiles, self.address, t) })
                : t('chat.typing.many', { count: typing.length })}
            </span>
          </div>
        ) : null}
      </MessageScroller>

      {model.readOnly ? (
        <ConversationBar model={model} />
      ) : (
        <Composer
          key={model.key}
          conversationKey={model.key}
          nameOf={nameOf}
          replyingTo={replyingTo}
          onCancelReply={() => setReplyingTo(null)}
          editing={editing}
          onCancelEdit={() => setEditing(null)}
          lastOwnText={lastOwnText}
          onEdit={(view) => {
            setReplyingTo(null)
            setEditing(view)
          }}
          send={actions.send}
          edit={actions.edit}
          sendFile={
            // Media to another person travels by sealed delivery (its key
            // comes from their profile); without it only notes and groups can.
            model.canSendMedia && chat.capabilities?.media && (conversation.kind === 'group' || model.note || chat.capabilities.sealedSender)
              ? actions.sendFile
              : undefined
          }
          mediaLimit={chat.capabilities?.media?.maximumPlaintextBytes ?? 0}
          maxTextBytes={model.group?.currentCryptographicPolicy.maximumApplicationPlaintextBytes}
          onTyping={
            model.canSendTyping
              ? () => void service.sendTyping(conversation, true).catch((error: unknown) => console.warn('chat: typing not sent', error))
              : undefined
          }
        />
      )}

      <DetailsPanel open={details} onClose={() => setDetails(false)} model={model} />

      <ConfirmDestructive
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title={t('chat.mutations.deleteTitle')}
        description={t('chat.mutations.confirmDelete')}
        submit={t('chat.mutations.delete')}
        errorFallback={t('chat.errors.unavailable')}
        onConfirm={() => {
          const target = deleting
          setDeleting(null)
          if (!target) return
          if (editing?.id === target.id) setEditing(null)
          void actions.remove(target.id).catch(() => undefined)
        }}
      />
    </div>
  )
}
