import type { ChatMentionV1 } from '@kutup/chat-core/types'
import { groupLinkFragmentFromUrl } from '../../lib/chatGroupLink'
import { cn } from '@kutup/ui/lib/cn'
import { useGroupLinksEnabled } from '../../app/chatStore'
import { openJoinLink } from '../../lib/joinLink'
import { splitMentions } from '../../lib/mentions'
import { linkify } from './linkify'

/**
 * A message's text: line breaks kept, long words wrapped, web links
 * clickable, mentions shown as "@" and the member's current name (as
 * Signal does, whatever the sender typed), yours stronger.
 */
export function MessageText({
  text,
  outgoing,
  mentions,
  nameOf,
  selfKey,
}: {
  text: string
  outgoing: boolean
  mentions?: readonly ChatMentionV1[]
  nameOf?: (address: string) => string
  selfKey?: string
}) {
  // Without groups a group link is only text: there is nothing to join.
  const groups = useGroupLinksEnabled()
  return (
    <p className="whitespace-pre-wrap break-words [overflow-wrap:anywhere]">
      {splitMentions(text, mentions).map((part, index) =>
        part.kind === 'mention' ? (
          <span
            key={index}
            className={cn(
              'rounded px-0.5 font-semibold',
              part.member === selfKey
                ? outgoing
                  ? 'bg-primary-foreground/25'
                  : 'bg-primary/20 text-primary'
                : outgoing
                  ? 'bg-primary-foreground/15'
                  : 'bg-foreground/10',
            )}
            data-testid="chat-mention"
            data-member={part.member}
          >
            @{nameOf?.(part.member) ?? part.value.replace(/^@/u, '')}
          </span>
        ) : (
          linkify(part.value).map((piece, pieceIndex) =>
            piece.kind === 'link' && (groups || !groupLinkFragmentFromUrl(piece.href)) ? (
              <a
                key={`${index}:${pieceIndex}`}
                href={piece.href}
                target="_blank"
                rel="noopener noreferrer nofollow"
                onClick={(event) => {
                  // A group link opens here, whichever server's app it names.
                  if (groupLinkFragmentFromUrl(piece.href)) {
                    event.preventDefault()
                    openJoinLink(piece.href)
                  }
                }}
                className={cn('underline underline-offset-2', outgoing ? 'decoration-primary-foreground/60' : 'text-primary')}
              >
                {piece.value}
              </a>
            ) : (
              <span key={`${index}:${pieceIndex}`}>{piece.value}</span>
            ),
          )
        ),
      )}
    </p>
  )
}
