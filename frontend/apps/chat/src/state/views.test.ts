import { describe, expect, it } from 'vitest'
import type { ChatContentView, ChatHistoryEntry, ContactRecord, ConversationId } from '@kutup/chat-core/types'
import { conversationList, foldMutations, foldPolls, foldReceipts, messageRequests, threadView, unreadCounts, type ChatData } from './views'

const SELF = 'me@a.test'
const bob: ConversationId = { kind: 'direct', address: { username: 'bob', server: 'a.test' } }
const carol: ConversationId = { kind: 'direct', address: { username: 'carol', server: 'b.test' } }
const note: ConversationId = { kind: 'direct', address: { username: 'me', server: 'a.test' } }
const group: ConversationId = { kind: 'group', groupId: 'g1' }

let seq = 0
function entry(
  conversation: ConversationId,
  direction: 'incoming' | 'outgoing',
  at: number,
  content: Partial<ChatContentView>,
  peer = conversation.kind === 'direct' ? `${conversation.address.username}@${conversation.address.server}` : 'dan@a.test',
): ChatHistoryEntry {
  seq += 1
  return {
    id: `e${seq}`,
    conversation,
    peer,
    direction,
    senderDeviceId: 1,
    timestampMs: at,
    delivered: true,
    deduplicated: false,
    content: { version: 1, kind: 'text', sentAt: '', seq: String(seq), body: null, ...content },
  }
}

function contact(peer: string, state: ContactRecord['state'], updatedAtMs = 0): ContactRecord {
  return { peer, state, revision: '1', sourceDeviceId: 1, updatedAtMs, syncPending: false }
}

function data(history: ChatHistoryEntry[], contacts: ContactRecord[] = []): ChatData {
  return { history, contacts, profiles: [], groups: [] }
}

describe('conversationList', () => {
  it('lists direct chats, requests and the note to self, newest first', () => {
    const history = [
      entry(bob, 'incoming', 10, { messageId: 'b1', text: 'hi' }),
      entry(note, 'outgoing', 30, { messageId: 'n1', text: 'todo' }),
      entry(carol, 'incoming', 20, { messageId: 'c1', text: 'hello?' }),
    ]
    const list = conversationList(data(history, [contact('carol@b.test', 'pendingIncoming')]), SELF, 100)
    expect(list.map((c) => [c.key, c.kind, c.contact?.state])).toEqual([
      ['direct:me@a.test', 'note', undefined],
      ['direct:carol@b.test', 'direct', 'pendingIncoming'],
      ['direct:bob@a.test', 'direct', undefined],
    ])
    const rejected = conversationList(data(history, [contact('carol@b.test', 'rejected')]), SELF, 100)
    expect(rejected.map((c) => c.key)).not.toContain('direct:carol@b.test')
  })

  it('keeps a group whose live record is gone as protected history', () => {
    const list = conversationList(data([entry(group, 'incoming', 5, { messageId: 'g', text: 'x' })]), SELF, 100)
    expect(list[0]).toMatchObject({ key: 'group:g1', kind: 'history' })
  })

  it('does not count reactions or receipts as the latest message', () => {
    const history = [
      entry(bob, 'incoming', 10, { messageId: 'b1', text: 'hi' }),
      entry(bob, 'outgoing', 50, { reaction: { targetMessageId: 'b1', emoji: '👍', active: true } }),
    ]
    expect(conversationList(data(history), SELF, 100)[0]?.last?.content.text).toBe('hi')
  })
})

describe('messageRequests', () => {
  it('lists pending incoming contacts with their latest message', () => {
    const history = [entry(carol, 'incoming', 20, { messageId: 'c1', text: 'hello?' })]
    const requests = messageRequests(data(history, [contact('carol@b.test', 'pendingIncoming', 20)]), 100)
    expect(requests).toHaveLength(1)
    expect(requests[0]).toMatchObject({ address: 'carol@b.test', key: 'direct:carol@b.test' })
    expect(requests[0]?.last?.content.text).toBe('hello?')
  })
})

describe('foldMutations', () => {
  it('applies only the author’s latest edit, and a delete over any edit', () => {
    const original = entry(bob, 'incoming', 1, { messageId: 'm1', text: 'first' })
    const history = [
      original,
      entry(bob, 'incoming', 2, { mutation: { targetMessageId: 'm1', operation: 'edit', replacementText: 'second' } }),
      entry(bob, 'incoming', 3, { mutation: { targetMessageId: 'm1', operation: 'edit', replacementText: 'third' } }),
      // Someone else's edit of Bob's message does not count.
      entry(bob, 'outgoing', 4, { mutation: { targetMessageId: 'm1', operation: 'edit', replacementText: 'forged' } }),
    ]
    expect(foldMutations(history, SELF).get('m1')).toEqual({ editedText: 'third', deleted: false })
    history.push(entry(bob, 'incoming', 5, { mutation: { targetMessageId: 'm1', operation: 'delete' } }))
    expect(foldMutations(history, SELF).get('m1')?.deleted).toBe(true)
  })
})

describe('foldReceipts', () => {
  it('counts delivery and reading per person, read winning over delivered', () => {
    const history = [
      entry(bob, 'outgoing', 1, { messageId: 'o1', text: 'hey' }),
      entry(bob, 'incoming', 2, { receipt: { messageIds: ['o1'], state: 'delivered' } }),
      entry(bob, 'incoming', 3, { receipt: { messageIds: ['o1'], state: 'read' } }),
    ]
    expect(foldReceipts(history, SELF).get('o1')).toEqual({ delivered: 1, read: 1 })
  })
})

describe('threadView', () => {
  it('folds replies, reactions and timer notices into one timeline', () => {
    const history = [
      entry(bob, 'incoming', 1, { messageId: 'm1', text: 'question' }),
      entry(bob, 'outgoing', 2, { messageId: 'm2', text: 'answer', replyTo: 'm1' }),
      entry(bob, 'incoming', 3, { reaction: { targetMessageId: 'm2', emoji: '❤️', active: true } }),
      entry(bob, 'outgoing', 4, { disappearingTimer: { durationSeconds: 3600 } }),
      entry(bob, 'incoming', 5, { messageId: 'gone', text: 'expired', expiresAtMs: 50 }),
    ]
    const view = threadView(history, 'direct:bob@a.test', SELF, 100)
    expect(view.map((m) => m.id)).toEqual(['m1', 'm2', history[3].id])
    expect(view[1]?.replyTo?.content.text).toBe('question')
    expect(view[1]?.reactions[0]).toMatchObject({ emoji: '❤️', count: 1 })
    expect(view[2]?.timerChange).toEqual({ seconds: 3600 })
    expect(view[0]?.author).toBe('bob@a.test')
    expect(view[1]?.author).toBe(SELF)
  })
})

describe('unreadCounts', () => {
  it('counts incoming messages after the read mark, not reactions or own messages', () => {
    const history = [
      entry(bob, 'incoming', 10, { messageId: 'a', text: 'old' }),
      entry(bob, 'incoming', 20, { messageId: 'b', text: 'new' }),
      entry(bob, 'incoming', 21, { reaction: { targetMessageId: 'b', emoji: '👍', active: true } }),
      entry(bob, 'outgoing', 22, { messageId: 'c', text: 'mine' }),
    ]
    expect(unreadCounts(history, { 'direct:bob@a.test': 10 }, 100).get('direct:bob@a.test')).toBe(1)
    expect(unreadCounts(history, {}, 100).get('direct:bob@a.test')).toBe(2)
  })
})

describe('foldPolls', () => {
  const poll = { question: 'Lunch?', options: ['Pizza', 'Kebab', 'Sushi'] }
  it("counts each voter's latest valid vote until the author ends it", () => {
    const history = [
      entry(group, 'outgoing', 10, { kind: 'poll', messageId: 'p1', poll }),
      entry(group, 'incoming', 20, { kind: 'pollVote', seq: '1', pollVote: { targetMessageId: 'p1', options: [0] } }, 'bob@a.test'),
      entry(group, 'incoming', 30, { kind: 'pollVote', seq: '2', pollVote: { targetMessageId: 'p1', options: [2] } }, 'bob@a.test'),
      // Two answers in a single-choice poll, or a missing option: ignored.
      entry(group, 'incoming', 31, { kind: 'pollVote', pollVote: { targetMessageId: 'p1', options: [0, 1] } }, 'carol@b.test'),
      entry(group, 'incoming', 32, { kind: 'pollVote', pollVote: { targetMessageId: 'p1', options: [7] } }, 'dan@a.test'),
      entry(group, 'outgoing', 40, { kind: 'pollVote', pollVote: { targetMessageId: 'p1', options: [2] } }),
      // Someone else cannot end it; its author can.
      entry(group, 'incoming', 45, { kind: 'pollTerminate', pollTerminate: { targetMessageId: 'p1' } }, 'bob@a.test'),
      entry(group, 'outgoing', 50, { kind: 'pollTerminate', pollTerminate: { targetMessageId: 'p1' } }),
      entry(group, 'incoming', 60, { kind: 'pollVote', seq: '3', pollVote: { targetMessageId: 'p1', options: [1] } }, 'bob@a.test'),
    ]
    const state = foldPolls(history, SELF).get('p1')!
    expect(state.ended).toBe(true)
    expect(Object.fromEntries(state.votes)).toEqual({ 'bob@a.test': [2], [SELF]: [2] })
  })

  it('takes a vote back with an empty choice', () => {
    const history = [
      entry(group, 'outgoing', 10, { kind: 'poll', messageId: 'p2', poll: { ...poll, allowMultiple: true } }),
      entry(group, 'incoming', 20, { kind: 'pollVote', seq: '1', pollVote: { targetMessageId: 'p2', options: [0, 1] } }, 'bob@a.test'),
      entry(group, 'incoming', 30, { kind: 'pollVote', seq: '2', pollVote: { targetMessageId: 'p2', options: [] } }, 'bob@a.test'),
    ]
    expect(foldPolls(history, SELF).get('p2')!.votes.size).toBe(0)
  })
})
