import { describe, expect, it } from 'vitest'
import type { ChatHistoryEntry, ChatReactionV1 } from './types'
import { aggregateLatestReactions, type ReactionOperation } from './reactions'

const targetMessageId = '11111111-1111-4111-8111-111111111111'

function operation(
  reactor: string,
  emoji: ChatReactionV1['emoji'],
  active: boolean,
  timestampMs: number,
  seq: string,
  senderDeviceId = 1,
): ReactionOperation {
  const reaction = { targetMessageId, emoji, active }
  const message: ChatHistoryEntry = {
    id: `${reactor}-${timestampMs}-${seq}-${senderDeviceId}`,
    conversation: { kind: 'direct', account: { server: 'b.test', accountId: '00000000-0000-4000-8000-81b637d8fcd2' } },
    sender: 'aci:00000000-0000-4000-8000-81b637d8fcd2@b.test',
    direction: reactor === 'aci:00000000-0000-4000-8000-2bd806c97f0e@a.test' ? 'outgoing' : 'incoming',
    senderDeviceId,
    timestampMs,
    delivered: true,
    deduplicated: false,
    content: {
      version: 2,
      kind: 'reaction',
      sentAt: new Date(timestampMs).toISOString(),
      seq,
      messageId: `${reactor}-${timestampMs}-${seq}-${senderDeviceId}`,
      body: reaction,
      reaction,
    },
  }
  return { message, reaction, reactor }
}

describe('aggregateLatestReactions', () => {
  it('keeps only each person’s latest emoji on a message', () => {
    const result = aggregateLatestReactions([
      operation('aci:00000000-0000-4000-8000-2bd806c97f0e@a.test', '👍', true, 1_000, '1'),
      operation('aci:00000000-0000-4000-8000-81b637d8fcd2@b.test', '👍', true, 1_100, '1'),
      operation('aci:00000000-0000-4000-8000-2bd806c97f0e@a.test', '❤️', true, 1_200, '2'),
    ], new Set([targetMessageId]), 'aci:00000000-0000-4000-8000-2bd806c97f0e@a.test')

    expect(result.get(targetMessageId)).toEqual([
      { emoji: '👍', count: 1, reactedBySelf: false, reactors: ['aci:00000000-0000-4000-8000-81b637d8fcd2@b.test'] },
      { emoji: '❤️', count: 1, reactedBySelf: true, reactors: ['aci:00000000-0000-4000-8000-2bd806c97f0e@a.test'] },
    ])
  })

  it('uses a newer inactive operation to remove the person’s current reaction', () => {
    const result = aggregateLatestReactions([
      operation('aci:00000000-0000-4000-8000-2bd806c97f0e@a.test', '👍', true, 1_000, '1'),
      operation('aci:00000000-0000-4000-8000-2bd806c97f0e@a.test', '❤️', true, 1_100, '2'),
      operation('aci:00000000-0000-4000-8000-2bd806c97f0e@a.test', '❤️', false, 1_200, '3'),
    ], new Set([targetMessageId]), 'aci:00000000-0000-4000-8000-2bd806c97f0e@a.test')

    expect(result.has(targetMessageId)).toBe(false)
  })

  it('resolves linked-device ties deterministically', () => {
    const result = aggregateLatestReactions([
      operation('aci:00000000-0000-4000-8000-2bd806c97f0e@a.test', '👍', true, 1_000, '7', 1),
      operation('aci:00000000-0000-4000-8000-2bd806c97f0e@a.test', '😂', true, 1_000, '7', 2),
    ], new Set([targetMessageId]), 'aci:00000000-0000-4000-8000-2bd806c97f0e@a.test')

    expect(result.get(targetMessageId)?.map(reaction => reaction.emoji)).toEqual(['😂'])
  })
})
