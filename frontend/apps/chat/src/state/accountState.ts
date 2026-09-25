import { conversationKey, directAddress } from '@kutup/chat-core/identity'
import type { ChatConversationStateV1, ChatHistoryEntry, ConversationId } from '@kutup/chat-core/types'
import { messageIdOf } from './views'

// What this account's devices told each other about its conversations
// (pinned, archived, muted, marked unread; how far each was read). They
// travel as hidden Note to Self messages from this account, so only those
// count: nobody else can pin or read for you.

/** At most this many pinned conversations, as in Signal. */
export const MAX_PINNED = 4

export interface ListState {
  pinned: boolean
  /** Archived as stored, before a new message brings it back. */
  archived: boolean
  mutedUntilMs?: number
  markedUnread: boolean
  /** Of the record in force; the next change uses one more. */
  revision: number
  updatedAtMs: number
}

export const DEFAULT_LIST_STATE: ListState = {
  pinned: false,
  archived: false,
  markedUnread: false,
  revision: 0,
  updatedAtMs: 0,
}

export interface AccountState {
  /** Per conversation key. */
  lists: Map<string, ListState>
  /** Per conversation key: read up to this time (on this device's clock). */
  readThrough: Map<string, number>
}

function isOwnControl(message: ChatHistoryEntry, selfAddress: string): boolean {
  return (
    message.direction === 'outgoing' &&
    message.conversation.kind === 'direct' &&
    directAddress(message.conversation) === selfAddress
  )
}

function newer(a: ChatConversationStateV1, b: ChatConversationStateV1): boolean {
  return a.revision !== b.revision ? a.revision > b.revision : a.sourceDeviceId > b.sourceDeviceId
}

export function foldAccountState(history: readonly ChatHistoryEntry[], selfAddress: string): AccountState {
  const states = new Map<string, ChatConversationStateV1>()
  const positions: Array<{ key: string; anchor: string; fallback: number }> = []
  const localTime = new Map<string, number>()
  for (const message of history) {
    localTime.set(messageIdOf(message), message.timestampMs)
    if (!isOwnControl(message, selfAddress)) continue
    const state = message.content.conversationState
    if (state) {
      const key = conversationKey(state.conversation)
      const current = states.get(key)
      if (!current || newer(state, current)) states.set(key, state)
    }
    const position = message.content.readPosition
    if (position) {
      positions.push({
        key: conversationKey(position.conversation),
        anchor: position.throughMessageId,
        fallback: position.readThroughMs,
      })
    }
  }
  const lists = new Map<string, ListState>()
  for (const [key, state] of states) {
    lists.set(key, {
      pinned: state.pinned,
      archived: state.archived,
      mutedUntilMs: state.mutedUntilMs,
      markedUnread: state.markedUnread,
      revision: state.revision,
      updatedAtMs: state.updatedAtMs,
    })
  }
  const readThrough = new Map<string, number>()
  for (const position of positions) {
    // The anchor as it arrived here; its time on the reading device when it
    // has not (yet), or is gone.
    const at = localTime.get(position.anchor) ?? position.fallback
    readThrough.set(position.key, Math.max(readThrough.get(position.key) ?? 0, at))
  }
  return { lists, readThrough }
}

export function isMuted(state: ListState | undefined, nowMs: number): boolean {
  return state?.mutedUntilMs !== undefined && state.mutedUntilMs > nowMs
}

/**
 * Archived, unless a message came in after it was archived and it is not
 * muted: then it is back in the list, as Signal does.
 */
export function isArchived(state: ListState | undefined, last: ChatHistoryEntry | null, nowMs: number): boolean {
  if (!state?.archived) return false
  const newIncoming = last !== null && last.direction === 'incoming' && last.timestampMs > state.updatedAtMs
  return !newIncoming || isMuted(state, nowMs)
}

/** How far each conversation is read: this device's marks or another device's, whichever is further. */
export function mergeReadMarks(
  local: Readonly<Record<string, number>>,
  synced: ReadonlyMap<string, number>,
): Record<string, number> {
  const merged: Record<string, number> = { ...local }
  for (const [key, at] of synced) merged[key] = Math.max(merged[key] ?? 0, at)
  return merged
}

/** The next record for `conversation`: the one in force with `patch` applied. */
export function nextListState(
  conversation: ConversationId,
  current: ListState | undefined,
  patch: Partial<Pick<ListState, 'pinned' | 'archived' | 'mutedUntilMs' | 'markedUnread'>>,
): Omit<ChatConversationStateV1, 'sourceDeviceId' | 'updatedAtMs'> {
  const base = current ?? DEFAULT_LIST_STATE
  const next = { ...base, ...patch }
  return {
    conversation,
    revision: base.revision + 1,
    pinned: next.pinned,
    archived: next.archived,
    ...(next.mutedUntilMs !== undefined ? { mutedUntilMs: next.mutedUntilMs } : {}),
    markedUnread: next.markedUnread,
  }
}
