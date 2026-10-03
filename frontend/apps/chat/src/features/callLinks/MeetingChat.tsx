import { SendHorizontal } from 'lucide-react'
import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { cn } from '@kutup/ui/lib/cn'
import type { LinkCallMessage } from '../calls/linkCallController'

/** The longest message the form sends (the sealed message holds 4000 bytes). */
const MAX_LENGTH = 1000

/**
 * The meeting's chat: what the people in it wrote since this browser joined.
 * It is sealed under a key from the link, passes through the call server
 * unread, and is kept nowhere: it is gone when the meeting is left.
 */
export function MeetingChat({ messages, onSend }: { messages: LinkCallMessage[]; onSend: (text: string) => Promise<void> }) {
  const { t, i18n } = useTranslation()
  const [text, setText] = useState('')
  const [failed, setFailed] = useState(false)
  const end = useRef<HTMLDivElement>(null)

  useEffect(() => {
    end.current?.scrollIntoView({ block: 'end' })
  }, [messages.length])

  async function submit(event: FormEvent) {
    event.preventDefault()
    const trimmed = text.trim()
    if (!trimmed) return
    setFailed(false)
    try {
      await onSend(trimmed)
      setText('')
    } catch {
      setFailed(true)
    }
  }

  return (
    <div className="flex h-full min-h-0 flex-col" data-testid="chat-meeting-chat">
      <div className="min-h-0 flex-1 space-y-3 overflow-y-auto p-3" role="log" aria-live="polite">
        <p className="rounded-md bg-muted px-3 py-2 text-center text-xs text-muted-foreground">{t('chat.meetings.chatNotice')}</p>
        {messages.map((message) => (
          <div key={`${message.identity}:${message.id}`} className={cn('flex flex-col gap-0.5', message.own && 'items-end')} data-testid="chat-meeting-message">
            <span className="text-xs text-muted-foreground">
              {message.own ? t('chat.you') : (message.name ?? t('chat.callLinks.unnamed'))}
              {' · '}
              {new Date(message.sentAtMs).toLocaleTimeString(i18n.language, { hour: 'numeric', minute: '2-digit' })}
            </span>
            <p
              className={cn(
                'max-w-[85%] whitespace-pre-wrap break-words rounded-2xl px-3 py-1.5 text-sm',
                message.own ? 'bg-primary text-primary-foreground' : 'bg-muted text-foreground',
              )}
            >
              {message.text}
            </p>
          </div>
        ))}
        <div ref={end} />
      </div>
      {failed ? <p className="px-3 pb-1 text-xs text-destructive">{t('chat.meetings.chatFailed')}</p> : null}
      <form onSubmit={(event) => void submit(event)} className="flex shrink-0 items-center gap-2 border-t border-border p-2">
        <input
          value={text}
          onChange={(event) => setText(event.target.value)}
          maxLength={MAX_LENGTH}
          placeholder={t('chat.meetings.chatPlaceholder')}
          aria-label={t('chat.meetings.chatPlaceholder')}
          className="h-9 min-w-0 flex-1 rounded-full border border-input bg-background px-3 text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring"
          data-testid="chat-meeting-chat-input"
        />
        <Button type="submit" size="icon" className="size-9 shrink-0 rounded-full" disabled={!text.trim()} aria-label={t('chat.send')}>
          <SendHorizontal />
        </Button>
      </form>
    </div>
  )
}
