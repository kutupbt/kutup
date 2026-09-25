import { describe, expect, it } from 'vitest'
import type { ChatContentView, ChatConversationStateV1, ChatHistoryEntry, ConversationId } from '@kutup/chat-core/types'
import { conversationKey } from '@kutup/chat-core/identity'
import { DEFAULT_LIST_STATE, foldAccountState, isArchived, mergeReadMarks, nextListState } from './accountState'
import { conversationList } from './views'

const SELF = 'me@a.test'
const bob: ConversationId = { kind: 'direct', address: { username: 'bob', server: 'a.test' } }
const note: ConversationId = { kind: 'direct', address: { username: 'me', server: 'a.test' } }
const BOB = conversationKey(bob)

let seq = 0
function entry(
  conversation: ConversationId,
  direction: 'incoming' | 'outgoing',
  at: number,
  content: Partial<ChatContentView>,
): ChatHistoryEntry {
  seq += 1
  return {
    id: `e${seq}`,
    conversation,
    peer: conversation.kind === 'direct' ? `${conversation.address.username}@${conversation.address.server}` : 'dan@a.test',
    direction,
    senderDeviceId: 1,
    timestampMs: at,
    delivered: true,
    deduplicated: false,
    content: { version: 1, kind: 'text', sentAt: '', seq: String(seq), body: null, messageId: `m${seq}`, ...content },
  }
}

function state(patch: Partial<ChatConversationStateV1>): ChatConversationStateV1 {
  return {
    conversation: bob,
    revision: 1,
    sourceDeviceId: 1,
    updatedAtMs: 50,
    pinned: false,
    archived: false,
    markedUnread: false,
    ...patch,
  }
}

describe('foldAccountState', () => {
  it('keeps the highest revision, then device, per conversation', () => {
    const history = [
      entry(note, 'outgoing', 1, { kind: 'conversationState', conversationState: state({ revision: 2, pinned: true }) }),
      entry(note, 'outgoing', 2, { kind: 'conversationState', conversationState: state({ revision: 1, archived: true }) }),
      entry(note, 'outgoing', 3, { kind: 'conversationState', conversationState: state({ revision: 2, sourceDeviceId: 3, markedUnread: true }) }),
    ]
    const list = foldAccountState(history, SELF).lists.get(BOB)
    expect(list).toMatchObject({ pinned: false, archived: false, markedUnread: true, revision: 2 })
  })

  it('ignores controls that are not this account’s own notes', () => {
    const history = [
      entry(bob, 'incoming', 1, { kind: 'conversationState', conversationState: state({ pinned: true }) }),
      entry(bob, 'outgoing', 2, { kind: 'conversationState', conversationState: state({ pinned: true }) }),
    ]
    expect(foldAccountState(history, SELF).lists.size).toBe(0)
  })

  it('places a read position at its anchor here, or at the reading device’s time without one', () => {
    const early = entry(bob, 'incoming', 100, { text: 'a' })
    const late = entry(bob, 'incoming', 300, { text: 'b' })
    const history = [
      early,
      late,
      entry(note, 'outgoing', 400, {
        kind: 'readPosition',
        readPosition: { conversation: bob, throughMessageId: early.content.messageId!, readThroughMs: 999 },
      }),
    ]
    expect(foldAccountState(history, SELF).readThrough.get(BOB)).toBe(100)
    const unknownAnchor = [
      ...history,
      entry(note, 'outgoing', 500, {
        kind: 'readPosition',
        readPosition: { conversation: bob, throughMessageId: '0b0f6a8e-35f5-4a8e-9f5a-0a8f3c2d1e4b', readThroughMs: 250 },
      }),
    ]
    expect(foldAccountState(unknownAnchor, SELF).readThrough.get(BOB)).toBe(250)
  })
})

describe('list state rules', () => {
  it('brings an archived chat back when a message comes in after archiving, unless muted', () => {
    const archived = { ...DEFAULT_LIST_STATE, archived: true, updatedAtMs: 50 }
    const old = entry(bob, 'incoming', 40, { text: 'old' })
    const fresh = entry(bob, 'incoming', 60, { text: 'new' })
    const mine = entry(bob, 'outgoing', 60, { text: 'mine' })
    expect(isArchived(archived, old, 0)).toBe(true)
    expect(isArchived(archived, mine, 0)).toBe(true)
    expect(isArchived(archived, fresh, 0)).toBe(false)
    expect(isArchived({ ...archived, mutedUntilMs: 1_000 }, fresh, 0)).toBe(true)
    expect(isArchived({ ...archived, mutedUntilMs: 1_000 }, fresh, 2_000)).toBe(false)
  })

  it('reads as far as either this device or another one got', () => {
    expect(mergeReadMarks({ a: 10, b: 30 }, new Map([['b', 20], ['c', 5]]))).toEqual({ a: 10, b: 30, c: 5 })
  })

  it('builds the next record from the one in force', () => {
    expect(nextListState(bob, { ...DEFAULT_LIST_STATE, revision: 4, pinned: true }, { archived: true })).toEqual({
      conversation: bob,
      revision: 5,
      pinned: true,
      archived: true,
      markedUnread: false,
    })
  })

  it('keeps controls out of the conversation list', () => {
    const history = [
      entry(note, 'outgoing', 1, { kind: 'conversationState', conversationState: state({ pinned: true }) }),
      entry(note, 'outgoing', 2, {
        kind: 'deleteForMe',
        deleteForMe: { conversation: bob, messageIds: ['0b0f6a8e-35f5-4a8e-9f5a-0a8f3c2d1e4b'] },
      }),
    ]
    expect(conversationList({ history, contacts: [], profiles: [], groups: [] }, SELF, 10)).toEqual([])
  })
})
