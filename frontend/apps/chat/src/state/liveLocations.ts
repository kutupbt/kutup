import { conversationKey } from '@kutup/chat-core/identity'
import type { ChatHistoryEntry, ChatLiveLocationV1 } from '@kutup/chat-core/types'

/** A live location as its first message shows it: the latest stream, and whether it ended. */
export interface LiveShareState {
  shareId: string
  /** The newest generation's stream and key. */
  latest: ChatLiveLocationV1
  /** When the sharer stopped it early, if they did. */
  stoppedAtMs: number | null
  /** The sharer (canonical address). */
  author: string
}

/** Whether a share is over at `nowMs`. */
export function liveShareEnded(state: LiveShareState, nowMs: number): boolean {
  return state.stoppedAtMs !== null || nowMs >= state.latest.untilMs
}

/**
 * Live locations in one conversation's `history`, keyed by the message id of
 * the generation-1 message that starts each. Later generations and the stop
 * count only from the same sharer in the same conversation, and a later
 * generation never extends the share past the first one's end.
 */
export function foldLiveLocations(
  history: readonly ChatHistoryEntry[],
  actorOf: (message: ChatHistoryEntry) => string | null,
): Map<string, LiveShareState> {
  const starts = new Map<string, { messageId: string; state: LiveShareState; conversation: string }>()
  for (const message of history) {
    const live = message.content.liveLocation
    const author = actorOf(message)
    if (!live || live.generation !== 1 || !message.content.messageId || !author) continue
    const key = `${conversationKey(message.conversation)}\u0000${author}\u0000${live.shareId}`
    if (starts.has(key)) continue
    starts.set(key, {
      messageId: message.content.messageId,
      conversation: conversationKey(message.conversation),
      state: { shareId: live.shareId, latest: live, stoppedAtMs: null, author },
    })
  }
  for (const message of history) {
    const author = actorOf(message)
    if (!author) continue
    const shareId = message.content.liveLocation?.shareId ?? message.content.liveLocationStop?.shareId
    if (!shareId) continue
    const start = starts.get(`${conversationKey(message.conversation)}\u0000${author}\u0000${shareId}`)
    if (!start) continue
    const live = message.content.liveLocation
    if (live && live.generation > start.state.latest.generation) {
      start.state.latest = { ...live, untilMs: Math.min(live.untilMs, start.state.latest.untilMs) }
    }
    if (message.content.liveLocationStop) {
      start.state.stoppedAtMs = Math.min(start.state.stoppedAtMs ?? Infinity, message.timestampMs)
    }
  }
  return new Map([...starts.values()].map((start) => [start.messageId, start.state]))
}
