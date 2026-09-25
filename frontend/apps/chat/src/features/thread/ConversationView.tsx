import { ArrowLeft, BarChart3, Check, Info, Loader2, MoreVertical, Phone, Timer, UserPlus, Users, Video } from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { canonicalAccountAddress, withHomeServer } from '@kutup/chat-core/identity'
import { downloadChatMediaToCacheV1, openCachedChatMediaV1 } from '@kutup/chat-core/media'
import type { ChatAttachmentDescriptorV1, ChatCallMedia, ChatGroupCall, ConversationId } from '@kutup/chat-core/types'
import { freshAccessToken } from '@kutup/session/client'
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
import { chatErrorMessage } from '../../lib/errors'
import { callLogText } from '../../lib/callText'
import { groupUpdateSentences } from '../../lib/groupUpdate'
import { callController, groupCallController, useCall, useGroupCall } from '../calls/callStore'
import { personName } from '../../lib/names'
import { formatDayHeader } from '../../lib/time'
import { useNow } from '../../lib/useNow'
import { setOpenConversation } from '../../state/openConversation'
import { useLinkPreviews } from '../../state/prefs'
import { useReadThrough } from '../../state/useAccountState'
import { timelineRows } from '../../state/timeline'
import type { MessageView } from '../../state/views'
import { DetailsPanel } from '../details/DetailsPanel'
import { ConversationMenuItems } from '../list/ConversationMenu'
import { DROPDOWN_PARTS } from '../list/menuParts'
import { useListActions } from '../list/useListActions'
import { AttachmentBody } from '../media/AttachmentBody'
import { ViewedOnce, ViewOnceBody } from '../media/ViewOnceBody'
import { NewPollDialog } from '../polls/NewPollDialog'
import { StickerBody } from '../stickers/StickerBody'
import { stickerFromImage } from '../../lib/stickers'
import { PollBody } from '../polls/PollBody'
import { Composer } from './Composer'
import { DeleteMessageDialog } from './DeleteMessageDialog'
import { ForwardDialog } from './ForwardDialog'
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
  const call = useCall()
  const groupCall = useGroupCall()
  const inAnyCall = call !== null || groupCall !== null
  async function joinGroupCall(target: ChatGroupCall, withVideo: boolean) {
    const controller = groupCallController()
    if (!controller || conversation.kind !== 'group') return
    try {
      await controller.join(conversation.groupId, target, withVideo)
    } catch (error) {
      toast.error(error instanceof DOMException && error.name === 'NotAllowedError'
        ? t('chat.calls.noDevices')
        : t('chat.calls.joinFailed'))
    }
  }
  async function startGroupCall(media: ChatCallMedia) {
    const controller = groupCallController()
    const host = chat.capabilities?.serverName
    if (!controller || conversation.kind !== 'group' || !host) return
    try {
      await controller.start(conversation.groupId, media, host)
    } catch (error) {
      toast.error(error instanceof DOMException && error.name === 'NotAllowedError'
        ? t('chat.calls.noDevices')
        : t('chat.calls.startFailed'))
    }
  }
  async function placeCall(media: ChatCallMedia) {
    const controller = callController()
    const peer = conversation.kind === 'direct' ? conversation.address : null
    if (!controller || !peer) return
    try {
      await controller.start(withHomeServer(peer, chat.capabilities?.serverName), media)
    } catch (error) {
      toast.error(error instanceof DOMException && error.name === 'NotAllowedError'
        ? t('chat.calls.noDevices')
        : t('chat.calls.startFailed'))
    }
  }
  const joinRequests = model.group
    ? chat.snapshot.joinRequests.filter((request) => request.conversationId === model.group!.request.genesis.conversationId).length
    : 0
  const [replyingTo, setReplyingTo] = useState<MessageView | null>(null)
  const [editing, setEditing] = useState<MessageView | null>(null)
  const [deleting, setDeleting] = useState<MessageView | null>(null)
  const [timerBusy, setTimerBusy] = useState(false)
  const [deletingChat, setDeletingChat] = useState(false)
  const [forwarding, setForwarding] = useState<MessageView | null>(null)
  const [newPoll, setNewPoll] = useState(false)

  /** "Save sticker": add a received sticker to this account's collection. */
  async function saveSticker(attachment: ChatAttachmentDescriptorV1) {
    try {
      if (!chat.mediaCache) throw new Error('media cache unavailable')
      await downloadChatMediaToCacheV1(chat.mediaCache, attachment, await freshAccessToken())
      const opened = await openCachedChatMediaV1(chat.mediaCache, attachment)
      await service.saveSticker(await stickerFromImage(opened.blob))
      await refreshChat()
      toast.success(t('chat.stickers.saved'))
    } catch (error) {
      toast.error(chatErrorMessage(error, t))
    }
  }
  const linkPreviewsOn = useLinkPreviews()
  const listActions = useListActions()
  const navigate = useNavigate()
  // The read mark as it was on opening: where "unread messages" goes.
  const readThrough = useReadThrough()
  const [unread] = useState(() => ({ after: readThrough[model.key] ?? 0, openedAt: Date.now() }))
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
  const members = useMemo(
    () =>
      (model.group?.currentRoster ?? [])
        .map((member) => canonicalAccountAddress(member.address))
        .filter((address) => address !== self.address)
        .map((address) => ({ address, name: personName(address, profiles, self.address, t) })),
    [model.group, profiles, self.address, t],
  )
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
          <Avatar name={model.title} image={model.group?.currentGroupInfo?.avatar?.data ?? model.profile?.avatar} contentType={model.group?.currentGroupInfo?.avatar?.contentType ?? model.profile?.avatarContentType} group={conversation.kind === 'group'} size={32} />
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
        {model.groupCall ? (
          <Button variant="default" size="sm" onClick={() => void joinGroupCall(model.groupCall!, false)} disabled={inAnyCall} data-testid="chat-group-call-join">
            <Phone />
            {t('chat.calls.join')}
          </Button>
        ) : model.canStartGroupCall ? (
          <>
            <Button variant="ghost" size="icon" onClick={() => void startGroupCall('audio')} disabled={inAnyCall} aria-label={t('chat.calls.groupVoice')} title={t('chat.calls.groupVoice')} data-testid="chat-group-call-voice">
              <Phone />
            </Button>
            <Button variant="ghost" size="icon" onClick={() => void startGroupCall('video')} disabled={inAnyCall} aria-label={t('chat.calls.groupVideo')} title={t('chat.calls.groupVideo')} data-testid="chat-group-call-video">
              <Video />
            </Button>
          </>
        ) : null}
        {model.canCall ? (
          <>
            <Button variant="ghost" size="icon" onClick={() => void placeCall('audio')} disabled={call !== null} aria-label={t('chat.calls.voice')} title={t('chat.calls.voice')} data-testid="chat-call-voice">
              <Phone />
            </Button>
            <Button variant="ghost" size="icon" onClick={() => void placeCall('video')} disabled={call !== null} aria-label={t('chat.calls.video')} title={t('chat.calls.video')} data-testid="chat-call-video">
              <Video />
            </Button>
          </>
        ) : null}
        <Button variant="ghost" size="icon" onClick={() => setDetails(true)} aria-label={t('chat.details.open')} data-testid={model.group ? 'chat-group-members' : undefined}>
          <Info />
        </Button>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" aria-label={t('chat.thread.more')} data-testid="chat-thread-menu">
              <MoreVertical />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <ConversationMenuItems
              parts={DROPDOWN_PARTS}
              conversation={conversation}
              last={model.views.at(-1)?.entry ?? null}
              unread={false}
              onDelete={() => setDeletingChat(true)}
              onMarkUnread={() => void navigate('/')}
            />
          </DropdownMenuContent>
        </DropdownMenu>
      </header>
      {joinRequests > 0 ? (
        <button
          type="button"
          onClick={() => setDetails(true)}
          className="flex w-full items-center justify-center gap-2 border-b border-border bg-accent/50 px-4 py-2 text-sm hover:bg-accent"
          data-testid="chat-join-requests-banner"
        >
          <UserPlus className="size-4" aria-hidden />
          {t('chat.groupLink.bannerRequests', { count: joinRequests })}
        </button>
      ) : null}

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
          if (row.kind === 'notice' && row.view.pollEnded) {
            return (
              <p key={row.key} className="mx-auto flex max-w-sm items-center justify-center gap-1.5 px-4 py-2.5 text-center text-xs text-muted-foreground" data-testid="chat-poll-ended">
                <BarChart3 className="size-4 shrink-0" aria-hidden />
                {row.view.outgoing
                  ? t('chat.polls.endedNotice_you', { question: row.view.pollEnded.question })
                  : t('chat.polls.endedNotice', { name: nameOf(row.view), question: row.view.pollEnded.question })}
              </p>
            )
          }
          if (row.kind === 'notice' && row.view.callLog) {
            const log = row.view.callLog
            const missed = log.outcome === 'missed'
            return (
              <div key={row.key} className="mx-auto flex max-w-sm items-center justify-center gap-2 px-4 py-2.5 text-center text-xs text-muted-foreground" data-testid="chat-call-notice">
                {log.media === 'video' ? <Video className={cn('size-4 shrink-0', missed && 'text-destructive')} aria-hidden /> : <Phone className={cn('size-4 shrink-0', missed && 'text-destructive')} aria-hidden />}
                <span className={cn(missed && 'text-destructive')}>{callLogText(log, t)}</span>
                {model.canCall ? (
                  <Button variant="link" size="sm" className="h-auto p-0 text-xs" onClick={() => void placeCall(log.media)}>
                    {t('chat.calls.callBack')}
                  </Button>
                ) : null}
              </div>
            )
          }
          if (row.kind === 'notice' && row.view.groupCall) {
            const started = row.view.groupCall
            const live = model.groupCall?.callId === started.callId
            return (
              <div key={row.key} className="mx-auto flex max-w-sm items-center justify-center gap-2 px-4 py-2.5 text-center text-xs text-muted-foreground" data-testid="chat-group-call-notice">
                {started.media === 'video' ? <Video className="size-4 shrink-0" aria-hidden /> : <Phone className="size-4 shrink-0" aria-hidden />}
                <span>
                  {row.view.outgoing
                    ? t('chat.calls.groupStarted_you')
                    : t('chat.calls.groupStarted', { name: nameOf(row.view) })}
                </span>
                {live && !inAnyCall ? (
                  <Button variant="link" size="sm" className="h-auto p-0 text-xs" onClick={() => void joinGroupCall(started, false)}>
                    {t('chat.calls.join')}
                  </Button>
                ) : null}
              </div>
            )
          }
          if (row.kind === 'notice' && row.view.groupUpdate) {
            return (
              <div key={row.key} className="mx-auto flex max-w-md flex-col items-center gap-0.5 px-4 py-2.5 text-center text-xs text-muted-foreground" data-testid="chat-group-notice">
                <Users className="mb-0.5 size-4 shrink-0" aria-hidden />
                {groupUpdateSentences(row.view.groupUpdate, self.address, (address) => personName(address, profiles, self.address, t), t).map((line, i) => (
                  <p key={i}>{line}</p>
                ))}
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
              selfName={chat.snapshot.profile?.displayName}
              onVisible={() => startExpiry(view)}
              attachment={
                view.entry.content.sticker && view.entry.content.attachment ? (
                  <StickerBody
                    attachment={view.entry.content.attachment}
                    accepted={model.contact?.state !== 'pendingIncoming' && model.contact?.state !== 'blocked'}
                  />
                ) : view.poll ? (
                  <PollBody
                    state={view.poll}
                    selfAddress={self.address}
                    outgoing={own}
                    canVote={writable && !view.mutation?.deleted}
                    nameOf={(address) => personName(address, profiles, self.address, t)}
                    onVote={(options) => void actions.votePoll(view.id, options).catch(() => undefined)}
                    onEnd={own && writable ? () => void actions.endPoll(view.id).catch(() => undefined) : undefined}
                  />
                ) : view.viewedOnce ? (
                  <ViewedOnce video={view.viewedOnce.video} />
                ) : view.entry.content.attachment && view.entry.content.viewOnce ? (
                  <ViewOnceBody
                    attachment={view.entry.content.attachment}
                    outgoing={own}
                    accepted={model.contact?.state !== 'pendingIncoming' && model.contact?.state !== 'blocked'}
                    onViewed={() => {
                      const messageId = view.entry.content.messageId
                      if (!messageId) return
                      void service
                        .markViewOnceOpened({
                          conversation,
                          messageId,
                          sender: view.author,
                          timestampMs: view.entry.timestampMs,
                          video: view.entry.content.attachment?.mediaClass === 'video',
                        })
                        .then(() => refreshChat())
                        .catch((error: unknown) => console.warn('chat: view-once not recorded', error))
                    }}
                  />
                ) : view.entry.content.attachment ? (
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
                onDelete: view.entry.content.messageId && !view.viewedOnce ? () => setDeleting(view) : undefined,
                // Voice notes and view-once media stay where they were sent.
                onSaveSticker:
                  view.entry.content.sticker && view.entry.content.attachment && !own
                    ? () => void saveSticker(view.entry.content.attachment!)
                    : undefined,
                onForward:
                  !view.mutation?.deleted &&
                  !view.entry.content.viewOnce &&
                  (view.entry.content.text ||
                    (view.entry.content.attachment && view.entry.content.attachment.durationMs === undefined))
                    ? () => setForwarding(view)
                    : undefined,
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
          members={conversation.kind === 'group' ? members : undefined}
          linkPreviews={linkPreviewsOn && chat.capabilities?.linkPreviews === true}
          onCreatePoll={model.note ? undefined : () => setNewPoll(true)}
          onSendSticker={
            model.canSendMedia && chat.capabilities?.media && (conversation.kind === 'group' || model.note || chat.capabilities.sealedSender)
              ? (sticker) => {
                  const bytes = Uint8Array.from(atob(sticker.data), (c) => c.charCodeAt(0))
                  const file = new File([bytes], sticker.contentType === 'image/png' ? 'sticker.png' : 'sticker.webp', { type: sticker.contentType })
                  void actions
                    .sendFile(file, { extras: { sticker: sticker.emoji ? { emoji: sticker.emoji } : {} } })
                    .catch(() => undefined)
                }
              : undefined
          }
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

      <ForwardDialog view={forwarding} onOpenChange={(open) => !open && setForwarding(null)} />
      <NewPollDialog open={newPoll} onOpenChange={setNewPoll} send={actions.sendPoll} />

      <DeleteMessageDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        forEveryone={deleting !== null && deleting.outgoing && writable && !deleting.mutation?.deleted}
        onDeleteForMe={() => {
          const target = deleting
          setDeleting(null)
          if (!target) return
          if (editing?.id === target.id) setEditing(null)
          if (replyingTo?.id === target.id) setReplyingTo(null)
          void actions.deleteForMe(target.id).catch(() => undefined)
        }}
        onDeleteForEveryone={() => {
          const target = deleting
          setDeleting(null)
          if (!target) return
          if (editing?.id === target.id) setEditing(null)
          void actions.remove(target.id).catch(() => undefined)
        }}
      />

      <ConfirmDestructive
        open={deletingChat}
        onOpenChange={setDeletingChat}
        title={t('chat.list.deleteTitle')}
        description={t('chat.list.deleteDescription')}
        submit={t('chat.list.delete')}
        errorFallback={t('chat.errors.unavailable')}
        onConfirm={() => {
          setDeletingChat(false)
          void navigate('/')
          void listActions.deleteChat(conversation)
        }}
      />
    </div>
  )
}
