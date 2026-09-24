import { Camera, Check, Loader2, Mic, Paperclip, Pencil, Reply, SendHorizontal, Square, Trash2, X } from 'lucide-react'
import { useEffect, useLayoutEffect, useRef, useState, type KeyboardEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { formatVoiceNoteElapsed } from '@kutup/chat-core/voice-note'
import { Button } from '@kutup/ui/components/button'
import { cn } from '@kutup/ui/lib/cn'
import { useVoiceRecorder } from '../media/useVoiceRecorder'
import { messagePreview } from '../../lib/names'
import type { MessageView } from '../../state/views'

/** Drafts survive switching conversations (not reloads), as in Signal. */
const drafts = new Map<string, string>()

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
  send: (text: string, replyTo?: string) => Promise<void>
  edit: (messageId: string, text: string) => Promise<void>
  /** Absent when files cannot be sent here. */
  sendFile?: (file: File, options?: { durationMs?: number }) => Promise<void>
  mediaLimit: number
  /** Group messages have a size limit (UTF-8 bytes). */
  maxTextBytes?: number
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
  const [text, setText] = useState(() => drafts.get(conversationKey) ?? '')
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

  useEffect(() => {
    drafts.set(conversationKey, text)
  }, [conversationKey, text])

  // Editing puts the message's text in the box; leaving the edit empties it.
  useEffect(() => {
    if (!editing) return
    setText(editing.mutation?.editedText ?? editing.entry.content.text ?? '')
    box.current?.focus()
  }, [editing])
  useEffect(() => {
    if (replyingTo) box.current?.focus()
  }, [replyingTo])

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
        setText('')
        try {
          await props.send(trimmed, replyingTo?.id)
          props.onCancelReply()
        } catch (error) {
          setText(trimmed)
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

  function typed(value: string) {
    setText(value)
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
      for (const file of chosen) await sendFile(file)
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
          </>
        ) : null}
        <label className="min-w-0 flex-1">
          <span className="sr-only">{t('chat.composer.label')}</span>
          <textarea
            ref={box}
            rows={1}
            value={text}
            onChange={(e) => typed(e.target.value)}
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
      {tooLong ? <p className="mt-1 px-2 text-xs text-destructive">{t('chat.composer.tooLong')}</p> : null}
    </div>
  )
}
