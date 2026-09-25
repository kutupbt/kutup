import { conversationKey } from './identity'
import { compareContentOperations } from './ordering'
import type { ChatHistoryEntry } from './types'

export interface ActiveDisappearingTimer {
  message: ChatHistoryEntry
  durationSeconds?: number
}

export function reduceDisappearingTimers(
  history: ChatHistoryEntry[],
): Map<string, ActiveDisappearingTimer> {
  const timers = new Map<string, ActiveDisappearingTimer>()
  for (const message of history) {
    const timer = message.content.disappearingTimer
    if (!timer) continue
    const key = conversationKey(message.conversation)
    const previous = timers.get(key)
    if (!previous || compareContentOperations(previous.message, message) < 0) {
      timers.set(key, { message, durationSeconds: timer.durationSeconds })
    }
  }
  return timers
}

export function isVisibleChatMessage(message: ChatHistoryEntry, nowMs: number): boolean {
  if (message.content.reaction || message.content.mutation || message.content.receipt
      || message.content.disappearingTimer || isAccountControl(message)) return false
  const expiresAt = disappearingMessageExpiresAt(message)
  return expiresAt === undefined || nowMs < expiresAt
}

/** This account's own list state, read positions and deletions: never shown. */
export function isAccountControl(message: ChatHistoryEntry): boolean {
  const kind = message.content.kind
  return kind === 'conversationState' || kind === 'readPosition' || kind === 'deleteForMe'
}

export function disappearingMessageExpiresAt(message: ChatHistoryEntry): number | undefined {
  return message.content.expiresAtMs
}

export function formatRemainingTime(milliseconds: number): string {
  const seconds = Math.max(0, Math.ceil(milliseconds / 1_000))
  if (seconds < 60) return `${seconds}s`
  const minutes = Math.ceil(seconds / 60)
  if (minutes < 60) return `${minutes}m`
  const hours = Math.ceil(minutes / 60)
  if (hours < 24) return `${hours}h`
  return `${Math.ceil(hours / 24)}d`
}
