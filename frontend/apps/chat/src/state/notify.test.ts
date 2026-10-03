import { describe, expect, it } from 'vitest'
import { conversationKey } from '@kutup/chat-core/identity'
import type { ChatContentView, ChatHistoryEntry, ConversationId } from '@kutup/chat-core/types'
import { DEFAULT_LIST_STATE } from './accountState'
import { noticesFor, type NotifyContext } from './notify'

const SELF = 'me@a.test'
const bob: ConversationId = { kind: 'direct', address: { username: 'bob', server: 'a.test' } }
const group: ConversationId = { kind: 'group', groupId: 'g-1234567890' }
const BOB = conversationKey(bob)
const GROUP = conversationKey(group)

let seq = 0
function entry(
  conversation: ConversationId,
  direction: 'incoming' | 'outgoing',
  content: Partial<ChatContentView>,
  peer = 'bob@a.test',
): ChatHistoryEntry {
  seq += 1
  return {
    id: `e${seq}`,
    conversation,
    peer,
    direction,
    senderDeviceId: 1,
    timestampMs: 1000 + seq,
    delivered: true,
    deduplicated: false,
    content: { version: 1, kind: 'text', sentAt: '', seq: String(seq), body: null, messageId: `m${seq}`, ...content },
  }
}

function context(patch: Partial<NotifyContext> = {}): NotifyContext {
  return {
    selfAddress: SELF,
    nowMs: 5000,
    lists: new Map(),
    readThrough: {},
    blocked: new Set(),
    focusedKey: null,
    ...patch,
  }
}

describe('noticesFor', () => {
  it('notifies incoming messages, not own ones or controls', () => {
    const fresh = [
      entry(bob, 'incoming', { text: 'hi' }),
      entry(bob, 'outgoing', { text: 'yo' }),
      entry(bob, 'incoming', { kind: 'receipt', receipt: { state: 'read', targetMessageIds: ['m1'] } as never }),
    ]
    expect(noticesFor(fresh, fresh, context()).map((n) => n.entry.content.text)).toEqual(['hi'])
  })

  it('skips blocked people, read chats and the chat in front of you', () => {
    const message = entry(bob, 'incoming', { text: 'hi' })
    expect(noticesFor([message], [message], context({ blocked: new Set(['bob@a.test']) }))).toEqual([])
    expect(noticesFor([message], [message], context({ readThrough: { [BOB]: message.timestampMs } }))).toEqual([])
    expect(noticesFor([message], [message], context({ focusedKey: BOB }))).toEqual([])
  })

  it('muted chats notify only mentions', () => {
    const lists = new Map([[GROUP, { ...DEFAULT_LIST_STATE, mutedUntilMs: 10_000 }]])
    const plain = entry(group, 'incoming', { text: 'hello all' }, 'dan@d.test')
    const mention = entry(group, 'incoming', {
      text: '@me look',
      mentions: [{ start: 0, length: 3, member: SELF }],
    }, 'dan@d.test')
    const notices = noticesFor([plain, mention], [plain, mention], context({ lists }))
    expect(notices).toHaveLength(1)
    expect(notices[0]).toMatchObject({ kind: 'message', mention: true, sender: 'dan@d.test' })
  })

  it('notifies reactions to your own messages only', () => {
    const mine = entry(bob, 'outgoing', { text: 'photo?' })
    const theirs = entry(bob, 'incoming', { text: 'sure' })
    const onMine = entry(bob, 'incoming', {
      kind: 'reaction',
      reaction: { targetMessageId: mine.content.messageId!, emoji: '❤️', active: true },
    })
    const onTheirs = entry(bob, 'incoming', {
      kind: 'reaction',
      reaction: { targetMessageId: theirs.content.messageId!, emoji: '👍', active: true },
    })
    const removed = entry(bob, 'incoming', {
      kind: 'reaction',
      reaction: { targetMessageId: mine.content.messageId!, emoji: '❤️', active: false },
    })
    const history = [mine, theirs, onMine, onTheirs, removed]
    const notices = noticesFor([onMine, onTheirs, removed], history, context())
    expect(notices).toEqual([expect.objectContaining({ kind: 'reaction', emoji: '❤️', target: mine })])
  })
})
