import type { ChatHistoryEntry, ChatReactionV1 } from './types'

export const CHAT_REACTION_EMOJIS = ['👍', '❤️', '😂', '😮', '😢', '🙏'] as const

export type ChatReactionEmoji = ChatReactionV1['emoji']

export interface ReactionAggregate {
  emoji: ChatReactionEmoji
  count: number
  reactedBySelf: boolean
  reactors: string[]
}

export interface ReactionOperation {
  message: ChatHistoryEntry
  reaction: ChatReactionV1
  reactor: string
}

/** One last-writer-wins reaction register per message and reactor account. */
export function aggregateLatestReactions(
  operations: readonly ReactionOperation[],
  targetMessageIds: ReadonlySet<string>,
  selfAddress: string,
): Map<string, ReactionAggregate[]> {
  const latestByTargetAndReactor = new Map<string, ReactionOperation>()
  for (const operation of operations) {
    if (!targetMessageIds.has(operation.reaction.targetMessageId)) continue
    const key = `${operation.reaction.targetMessageId}\u0000${operation.reactor}`
    const previous = latestByTargetAndReactor.get(key)
    if (!previous || compareReactionOperations(previous.message, operation.message) < 0) {
      latestByTargetAndReactor.set(key, operation)
    }
  }

  const reactorsByTargetEmoji = new Map<string, Set<string>>()
  for (const { reaction, reactor } of latestByTargetAndReactor.values()) {
    if (!reaction.active) continue
    const key = `${reaction.targetMessageId}\u0000${reaction.emoji}`
    const reactors = reactorsByTargetEmoji.get(key) ?? new Set<string>()
    reactors.add(reactor)
    reactorsByTargetEmoji.set(key, reactors)
  }

  const result = new Map<string, ReactionAggregate[]>()
  for (const targetMessageId of targetMessageIds) {
    const aggregates = CHAT_REACTION_EMOJIS.flatMap(emoji => {
      const reactors = reactorsByTargetEmoji.get(`${targetMessageId}\u0000${emoji}`)
      return reactors?.size
        ? [{
            emoji,
            count: reactors.size,
            reactedBySelf: reactors.has(selfAddress),
            reactors: Array.from(reactors).sort(),
          }]
        : []
    })
    if (aggregates.length > 0) result.set(targetMessageId, aggregates)
  }
  return result
}

function compareReactionOperations(left: ChatHistoryEntry, right: ChatHistoryEntry): number {
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
