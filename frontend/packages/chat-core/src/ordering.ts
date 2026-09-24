import type { ChatHistoryEntry } from './types'

/**
 * The order two history entries were written in: time, then the sender's
 * sequence, then device, then id. Last-writer-wins registers (edits,
 * reactions, timers) use it so every client agrees on the winner.
 */
export function compareContentOperations(left: ChatHistoryEntry, right: ChatHistoryEntry): number {
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
