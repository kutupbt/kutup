import { cn } from '@kutup/ui/lib/cn'
import { linkify } from './linkify'

/** A message's text: line breaks kept, long words wrapped, web links clickable. */
export function MessageText({ text, outgoing }: { text: string; outgoing: boolean }) {
  return (
    <p className="whitespace-pre-wrap break-words [overflow-wrap:anywhere]">
      {linkify(text).map((part, index) =>
        part.kind === 'link' ? (
          <a
            key={index}
            href={part.href}
            target="_blank"
            rel="noopener noreferrer nofollow"
            className={cn('underline underline-offset-2', outgoing ? 'decoration-primary-foreground/60' : 'text-primary')}
          >
            {part.value}
          </a>
        ) : (
          <span key={index}>{part.value}</span>
        ),
      )}
    </p>
  )
}
