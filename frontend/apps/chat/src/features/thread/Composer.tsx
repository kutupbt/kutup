import { BarChart3, Camera, Check, Loader2, MapPin, Mic, Paperclip, Pencil, Reply, SendHorizontal, Square, Trash2, X } from 'lucide-react'
import { useEffect, useLayoutEffect, useRef, useState, type KeyboardEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { formatVoiceNoteElapsed } from '@kutup/chat-core/voice-note'
import { Button } from '@kutup/ui/components/button'
import { cn } from '@kutup/ui/lib/cn'
import type { ChatLinkPreviewV1, ChatMessageExtras, ChatStickerV1 } from '@kutup/chat-core/types'
import { StickerPicker } from '../stickers/StickerPicker'
import { ComposerLinkPreview } from '../linkPreview/LinkPreviewCard'
import { buildLinkPreview, firstPreviewableLink } from '../../lib/linkPreview'
import { useVoiceRecorder } from '../media/useVoiceRecorder'
import { ViewOnceIcon } from '../media/ViewOnceBody'
import { useChat } from '../../app/chatStore'
import { Avatar } from '@kutup/ui/components/avatar'
import { getDraft, setDraft } from '../../lib/drafts'
import { insertMention, mentionQuery, resolveMentions, type MentionPick } from '../../lib/mentions'
import { messagePreview } from '../../lib/names'
import type { MessageView } from '../../state/views'

/** Drafts survive switching conversations (not reloads), as in Signal. */

/** Someone a group message can mention. */
export interface MentionCandidate {
  address: string
  name: string
}

const TYPING_EVERY_MS = 4_000

export interface ComposerProps {
  conversationKey: string
  /** Who a reply quotes, by name. */
  nameOf: (view: MessageView) => string
  replyingTo: MessageView | null
  onCancelReply: () => void
  editing: MessageView | null
  onCancelEdit: () => void
  /** The newest own text message (Arrow Up edits it). */
  lastOwnText: MessageView | null
  onEdit: (view: MessageView) => void
  send: (text: string, replyTo?: string, extras?: ChatMessageExtras) => Promise<void>
  /** A group's other members, for @mentions. */
  members?: readonly MentionCandidate[]
  /** Build previews of links in the text (server offers it, setting on). */
  linkPreviews?: boolean
  /** Open "New poll". */
  onCreatePoll?: () => void
  /** Open "Send a location". */
  onShareLocation?: () => void
  /** Send one of this account's stickers (absent where media cannot go). */
  onSendSticker?: (sticker: ChatStickerV1) => void
  edit: (messageId: string, text: string) => Promise<void>
  /** Absent when files cannot be sent here. */
  sendFile?: (
    file: File,
    options?: { durationMs?: number; withoutPreview?: boolean; extras?: ChatMessageExtras },
  ) => Promise<void>
  mediaLimit: number
  /** Group messages have a size limit (UTF-8 bytes). */
  maxTextBytes?: number
  /** What to say when the text is over `maxTextBytes` (the group's rule by default). */
  tooLongText?: string
  onTyping?: () => void
}

/**
 * The message box, Signal style: attach on the left, the growing text box,
 * then send (or the microphone while it is empty). Enter sends, Shift+Enter
 * adds a line, Escape drops a reply or edit, Arrow Up in an empty box edits
 * your last message.
 */
export function Composer(props: ComposerProps) {
  const { t } = useTranslation()
  const { conversationKey, replyingTo, editing, sendFile } = props
  const account = useChat().self?.address ?? ''
  const [text, setText] = useState(() => getDraft(account, conversationKey)?.text ?? '')
  const [picks, setPicks] = useState<MentionPick[]>(() => getDraft(account, conversationKey)?.picks ?? [])
  const [mention, setMention] = useState<{ start: number; query: string } | null>(null)
  const [highlighted, setHighlighted] = useState(0)
  const [preview, setPreview] = useState<
    { status: 'loading'; url: string } | { status: 'ready'; url: string; preview: ChatLinkPreviewV1 } | null
  >(null)
  const dismissed = useRef(new Set<string>())
  /** The next photos or videos go as view-once (Signal's "1" switch). */
  const [viewOnce, setViewOnce] = useState(false)
  const [busy, setBusy] = useState(false)
  const box = useRef<HTMLTextAreaElement>(null)
  const files = useRef<HTMLInputElement>(null)
  const camera = useRef<HTMLInputElement>(null)
  const typingSent = useRef(0)
  const voice = useVoiceRecorder({
    maxBytes: props.mediaLimit,
    onRecorded: async (file, durationMs) => {
      await sendFile?.(file, { durationMs })
    },
  })

  // An edit in progress is not a draft of a new message.
  useEffect(() => {
    if (!editing && account) setDraft(account, conversationKey, { text, picks })
  }, [account, conversationKey, text, picks, editing])

  const matches =
    mention && props.members
      ? props.members
          .filter((member) => {
            const query = mention.query.toLocaleLowerCase()
            return member.name.toLocaleLowerCase().includes(query) || member.address.toLocaleLowerCase().startsWith(query)
          })
          .slice(0, 6)
      : []

  function choose(member: MentionCandidate) {
    const element = box.current
    if (!mention || !element) return
    const label = `@${member.name}`
    const next = insertMention(text, mention.start, element.selectionStart, label)
    pendingCaret.current = next.caret
    setText(next.text)
    setPicks((current) => [...current, { label, member: member.address }])
    setMention(null)
  }

  // Put the caret after an inserted mention before the next keystroke can
  // land (a frame later would be too late for fast typing).
  const pendingCaret = useRef<number | null>(null)
  useLayoutEffect(() => {
    const caret = pendingCaret.current
    const element = box.current
    if (caret === null || !element) return
    pendingCaret.current = null
    element.focus()
    element.setSelectionRange(caret, caret)
  }, [text])

  // Editing puts the message's text in the box; leaving the edit empties it.
  useEffect(() => {
    if (!editing) return
    setText(editing.mutation?.editedText ?? editing.entry.content.text ?? '')
    box.current?.focus()
  }, [editing])
  useEffect(() => {
    if (replyingTo) box.current?.focus()
  }, [replyingTo])

  // A link in the text gets a preview, fetched once typing pauses.
  const link = props.linkPreviews && !editing ? firstPreviewableLink(text) : null
  useEffect(() => {
    if (!link || dismissed.current.has(link)) {
      setPreview(null)
      return
    }
    if (preview?.url === link) return
    const controller = new AbortController()
    const timer = window.setTimeout(() => {
      setPreview({ status: 'loading', url: link })
      buildLinkPreview(link, controller.signal)
        .then((built) => setPreview(built ? { status: 'ready', url: link, preview: built } : null))
        .catch(() => {
          if (!controller.signal.aborted) setPreview(null)
        })
    }, 600)
    return () => {
      window.clearTimeout(timer)
      controller.abort()
    }
    // Refetch only when the link changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [link])

  // Grow with the text up to about six lines, then scroll.
  useLayoutEffect(() => {
    const element = box.current
    if (!element) return
    element.style.height = 'auto'
    element.style.height = `${Math.min(element.scrollHeight, 144)}px`
  }, [text])

  const trimmed = text.trim()
  const tooLong =
    props.maxTextBytes !== undefined && new TextEncoder().encode(trimmed).byteLength > props.maxTextBytes

  async function submit() {
    if (!trimmed || busy || tooLong) return
    setBusy(true)
    try {
      if (editing) {
        await props.edit(editing.id, trimmed)
        props.onCancelEdit()
        setText('')
      } else {
        const mentions = resolveMentions(trimmed, picks)
        const linkPreview = preview?.status === 'ready' && trimmed.includes(preview.url) ? preview.preview : undefined
        const extras: ChatMessageExtras = {
          ...(mentions.length > 0 ? { mentions } : {}),
          ...(linkPreview ? { linkPreview } : {}),
        }
        const sentPreview = preview
        setText('')
        setPicks([])
        setPreview(null)
        try {
          await props.send(trimmed, replyingTo?.id, Object.keys(extras).length > 0 ? extras : undefined)
          props.onCancelReply()
          dismissed.current.clear()
        } catch (error) {
          setText(trimmed)
          setPicks(picks)
          setPreview(sentPreview)
          throw error
        }
      }
    } catch {
      // The action already said what went wrong.
    } finally {
      setBusy(false)
      box.current?.focus()
    }
  }

  function onKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (matches.length > 0) {
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault()
        const step = event.key === 'ArrowDown' ? 1 : -1
        setHighlighted((index) => (index + step + matches.length) % matches.length)
        return
      }
      if ((event.key === 'Enter' || event.key === 'Tab') && !event.shiftKey && !event.nativeEvent.isComposing) {
        event.preventDefault()
        choose(matches[Math.min(highlighted, matches.length - 1)])
        return
      }
      if (event.key === 'Escape') {
        event.preventDefault()
        setMention(null)
        return
      }
    }
    if (event.key === 'Enter' && !event.shiftKey && !event.nativeEvent.isComposing) {
      event.preventDefault()
      void submit()
    } else if (event.key === 'Escape' && (editing || replyingTo)) {
      event.preventDefault()
      if (editing) {
        props.onCancelEdit()
        setText('')
      } else props.onCancelReply()
    } else if (event.key === 'ArrowUp' && !text && props.lastOwnText) {
      event.preventDefault()
      props.onEdit(props.lastOwnText)
    }
  }

  function typed(value: string, caret: number) {
    setText(value)
    if (props.members?.length) {
      const next = mentionQuery(value, caret)
      setMention(next)
      if (next?.query !== mention?.query) setHighlighted(0)
    }
    const now = Date.now()
    if (value.trim() && props.onTyping && now - typingSent.current >= TYPING_EVERY_MS) {
      typingSent.current = now
      props.onTyping()
    }
  }

  async function pick(list: FileList | null, input: HTMLInputElement | null) {
    const chosen = Array.from(list ?? [])
    if (input) input.value = ''
    if (!sendFile || chosen.length === 0) return
    setBusy(true)
    try {
      for (const file of chosen) {
        const media = file.type.startsWith('image/') || file.type.startsWith('video/')
        await sendFile(file, viewOnce && media ? { withoutPreview: true, extras: { viewOnce: true } } : undefined)
      }
      setViewOnce(false)
    } catch {
      // Said already.
    } finally {
      setBusy(false)
    }
  }

  if (voice.state === 'recording' || voice.state === 'sending') {
    return (
      <div className="flex items-center gap-3 border-t border-border px-3 py-2.5" data-testid="chat-voice-recording">
        <span className="flex size-9 items-center justify-center">
          {voice.state === 'sending' ? (
            <Loader2 className="size-5 animate-spin text-muted-foreground" aria-hidden />
          ) : (
            <span className="size-3 animate-pulse rounded-full bg-destructive" aria-hidden />
          )}
        </span>
        <span className="flex-1 text-sm tabular-nums" aria-live="polite">
          {voice.state === 'sending' ? t('chat.voice.sending') : t('chat.voice.recording', { time: formatVoiceNoteElapsed(voice.elapsedMs) })}
        </span>
        <Button type="button" variant="ghost" size="icon" onClick={voice.cancel} disabled={voice.state === 'sending'} aria-label={t('chat.voice.cancel')} data-testid="chat-voice-cancel">
          <Trash2 />
        </Button>
        <Button type="button" size="icon" className="rounded-full" onClick={voice.stop} disabled={voice.state === 'sending'} aria-label={t('chat.voice.stop')} data-testid="chat-voice-stop">
          <Square className="fill-current" />
        </Button>
      </div>
    )
  }

  return (
    <div className="border-t border-border px-3 pb-3 pt-2">
      {replyingTo || editing ? (
        <div
          className="mb-2 flex items-start gap-2 rounded-lg border-l-4 border-primary bg-muted px-3 py-2 text-sm"
          data-testid={editing ? 'chat-edit-composer' : 'chat-reply-composer'}
        >
          {editing ? <Pencil className="mt-0.5 size-4 shrink-0 text-primary" aria-hidden /> : <Reply className="mt-0.5 size-4 shrink-0 text-primary" aria-hidden />}
          <span className="min-w-0 flex-1">
            <span className="block text-xs font-semibold text-primary">
              {editing ? t('chat.mutations.editing') : t('chat.replies.replyingTo', { name: props.nameOf(replyingTo!) })}
            </span>
            <span className="line-clamp-2 text-muted-foreground">
              {messagePreview((editing ?? replyingTo)!.entry, (editing ?? replyingTo)!.mutation, t)}
            </span>
          </span>
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="size-7"
            onClick={() => {
              if (editing) {
                props.onCancelEdit()
                setText('')
              } else props.onCancelReply()
            }}
            aria-label={editing ? t('chat.mutations.cancelEdit') : t('chat.replies.cancel')}
          >
            <X />
          </Button>
        </div>
      ) : null}

      {preview && !editing ? (
        <ComposerLinkPreview
          state={preview}
          onDismiss={() => {
            dismissed.current.add(preview.url)
            setPreview(null)
          }}
        />
      ) : null}

      {matches.length > 0 ? (
        <ul
          id="chat-mention-list"
          role="listbox"
          aria-label={t('chat.mentions.list')}
          className="mb-2 max-h-60 overflow-y-auto rounded-lg border border-border bg-popover p-1 shadow-md"
          data-testid="chat-mention-list"
        >
          {matches.map((member, index) => (
            <li
              key={member.address}
              id={`chat-mention-${index}`}
              role="option"
              aria-selected={index === highlighted}
              // Keep the text box focused: choose on mouse down.
              onMouseDown={(event) => {
                event.preventDefault()
                choose(member)
              }}
              onMouseEnter={() => setHighlighted(index)}
              className={cn(
                'flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm',
                index === highlighted && 'bg-accent text-accent-foreground',
              )}
            >
              <Avatar name={member.name} size={28} />
              <span className="min-w-0 flex-1 truncate">{member.name}</span>
              {member.name !== member.address ? <span className="truncate text-xs text-muted-foreground">{member.address}</span> : null}
            </li>
          ))}
        </ul>
      ) : null}

      <div className="flex items-end gap-1.5">
        {sendFile && !editing ? (
          <>
            <input ref={files} type="file" multiple hidden onChange={(e) => void pick(e.target.files, e.target)} data-testid="chat-attachment-input" />
            <input ref={camera} type="file" accept="image/*,video/*" capture="environment" hidden onChange={(e) => void pick(e.target.files, e.target)} data-testid="chat-capture-input" />
            <Button type="button" variant="ghost" size="icon" className="size-9 shrink-0 rounded-full" disabled={busy} onClick={() => files.current?.click()} aria-label={t('chat.attachments.attach')} data-testid="chat-attachment-button">
              <Paperclip />
            </Button>
            <Button type="button" variant="ghost" size="icon" className="size-9 shrink-0 rounded-full md:hidden" disabled={busy} onClick={() => camera.current?.click()} aria-label={t('chat.attachments.capture')} data-testid="chat-capture-button">
              <Camera />
            </Button>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className={cn('size-9 shrink-0 rounded-full', viewOnce && 'bg-accent text-primary')}
              disabled={busy}
              onClick={() => setViewOnce((on) => !on)}
              aria-pressed={viewOnce}
              aria-label={viewOnce ? t('chat.viewOnce.on') : t('chat.viewOnce.off')}
              title={viewOnce ? t('chat.viewOnce.on') : t('chat.viewOnce.off')}
              data-testid="chat-view-once-toggle"
            >
              <ViewOnceIcon />
            </Button>
          </>
        ) : null}
        {props.onSendSticker && !editing ? <StickerPicker onSend={props.onSendSticker} disabled={busy} /> : null}
        {props.onCreatePoll && !editing ? (
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="size-9 shrink-0 rounded-full"
            disabled={busy}
            onClick={props.onCreatePoll}
            aria-label={t('chat.polls.create')}
            title={t('chat.polls.create')}
            data-testid="chat-poll-button"
          >
            <BarChart3 />
          </Button>
        ) : null}
        {props.onShareLocation && !editing ? (
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="size-9 shrink-0 rounded-full"
            disabled={busy}
            onClick={props.onShareLocation}
            aria-label={t('chat.location.button')}
            title={t('chat.location.button')}
            data-testid="chat-location-button"
          >
            <MapPin />
          </Button>
        ) : null}
        <label className="min-w-0 flex-1">
          <span className="sr-only">{t('chat.composer.label')}</span>
          <textarea
            ref={box}
            rows={1}
            value={text}
            onChange={(e) => typed(e.target.value, e.target.selectionStart)}
            onBlur={() => setMention(null)}
            aria-autocomplete={props.members?.length ? 'list' : undefined}
            aria-controls={matches.length > 0 ? 'chat-mention-list' : undefined}
            aria-activedescendant={matches.length > 0 ? `chat-mention-${highlighted}` : undefined}
            onKeyDown={onKeyDown}
            placeholder={t('chat.composer.placeholder')}
            aria-invalid={tooLong}
            className={cn(
              'block max-h-36 min-h-9 w-full resize-none rounded-[18px] border border-input bg-background px-3.5 py-[0.4375rem] text-sm leading-5 outline-none transition-colors',
              'placeholder:text-muted-foreground focus:border-primary',
              tooLong && 'border-destructive focus:border-destructive',
            )}
          />
        </label>
        {editing ? (
          <Button type="button" size="icon" className="size-9 shrink-0 rounded-full" onClick={() => void submit()} disabled={!trimmed || busy || tooLong} aria-label={t('chat.mutations.save')}>
            {busy ? <Loader2 className="animate-spin" /> : <Check />}
          </Button>
        ) : trimmed || !sendFile ? (
          <Button type="button" size="icon" className="size-9 shrink-0 rounded-full" onClick={() => void submit()} disabled={!trimmed || busy || tooLong} aria-label={t('chat.send')}>
            {busy ? <Loader2 className="animate-spin" /> : <SendHorizontal />}
          </Button>
        ) : (
          <Button type="button" variant="ghost" size="icon" className="size-9 shrink-0 rounded-full" onClick={() => void voice.start()} disabled={busy || voice.state === 'starting'} aria-label={t('chat.voice.record')} data-testid="chat-voice-button">
            {voice.state === 'starting' ? <Loader2 className="animate-spin" /> : <Mic />}
          </Button>
        )}
      </div>
      {tooLong ? <p className="mt-1 px-2 text-xs text-destructive">{props.tooLongText ?? t('chat.composer.tooLong')}</p> : null}
    </div>
  )
}
