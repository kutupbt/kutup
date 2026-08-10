import { conversationKey } from './identity'
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
      || message.content.disappearingTimer) return false
  const expiresAt = disappearingMessageExpiresAt(message)
  return expiresAt === undefined || nowMs < expiresAt
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

function compareContentOperations(left: ChatHistoryEntry, right: ChatHistoryEntry): number {
  if (left.timestampMs !== right.timestampMs) return left.timestampMs - right.timestampMs
  const sequence = compareDecimalStrings(left.content.seq, right.content.seq)
  if (sequence !== 0) return sequence
  const device = (left.senderDeviceId ?? 0) - (right.senderDeviceId ?? 0)
  return device !== 0 ? device : left.id.localeCompare(right.id)
}

function compareDecimalStrings(left: string, right: string): number {
  const normalizedLeft = left.replace(/^0+(?=\d)/u, '')
  const normalizedRight = right.replace(/^0+(?=\d)/u, '')
  if (normalizedLeft.length !== normalizedRight.length) {
    return normalizedLeft.length - normalizedRight.length
  }
  return normalizedLeft.localeCompare(normalizedRight)
}
