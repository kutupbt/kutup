import { isVisibleChatMessage } from '@kutup/chat-core/disappearing'
import { conversationKey } from '@kutup/chat-core/identity'
import type { ChatHistoryEntry, ChatReactionV1 } from '@kutup/chat-core/types'
import { isMuted, type ListState } from './accountState'
import { messageActor, messageIdOf } from './views'

// Which newly arrived entries deserve a notification, as Signal decides:
// messages and reactions to your own messages; not from blocked people,
// not in a chat already read on another device or open in front of you,
// and not in a muted chat unless the message mentions you.

export interface NotifyContext {
  selfAddress: string
  nowMs: number
  lists: ReadonlyMap<string, ListState>
  readThrough: Readonly<Record<string, number>>
  /** Blocked people (canonical addresses). */
  blocked: ReadonlySet<string>
  /** The conversation someone is looking at in a focused tab, if any. */
  focusedKey: string | null
}

export type Notice =
  | { kind: 'message'; key: string; entry: ChatHistoryEntry; sender: string; mention: boolean }
  | { kind: 'reaction'; key: string; entry: ChatHistoryEntry; sender: string; emoji: ChatReactionV1['emoji']; target: ChatHistoryEntry }

export function noticesFor(
  fresh: readonly ChatHistoryEntry[],
  history: readonly ChatHistoryEntry[],
  context: NotifyContext,
): Notice[] {
  const notices: Notice[] = []
  let byId: Map<string, ChatHistoryEntry> | null = null
  for (const entry of fresh) {
    if (entry.direction !== 'incoming') continue
    const key = conversationKey(entry.conversation)
    const sender = messageActor(entry, context.selfAddress)
    if (!sender || context.blocked.has(sender) || key === context.focusedKey) continue
    const muted = isMuted(context.lists.get(key), context.nowMs)
    const reaction = entry.content.reaction
    if (reaction) {
      if (!reaction.active || muted) continue
      byId ??= new Map(history.map((message) => [messageIdOf(message), message]))
      const target = byId.get(reaction.targetMessageId)
      if (!target || target.direction !== 'outgoing' || conversationKey(target.conversation) !== key) continue
      notices.push({ kind: 'reaction', key, entry, sender, emoji: reaction.emoji, target })
      continue
    }
    // "Alice started a group call" notifies like a message.
    const callStart = entry.content.groupCall?.event === 'started'
    if (!callStart && !isVisibleChatMessage(entry, context.nowMs)) continue
    if (entry.timestampMs <= (context.readThrough[key] ?? 0)) continue
    const mention = entry.content.mentions?.some((item) => item.member === context.selfAddress) ?? false
    if (muted && !mention) continue
    notices.push({ kind: 'message', key, entry, sender, mention })
  }
  return notices
}
