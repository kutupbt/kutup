import { describe, expect, it } from 'vitest'
import type { ChatHistoryEntry } from '@kutup/chat-core/types'
import { timelineRows } from './timeline'
import type { MessageView } from './views'

const DAY = 24 * 60 * 60_000
// Noon, so a few minutes either way stays on the same day in any time zone offset used by tests.
const T0 = new Date(2026, 8, 20, 12, 0).getTime()

function view(id: string, at: number, author: string, extra: Partial<MessageView> = {}): MessageView {
  const outgoing = author === 'me'
  return {
    entry: { id, timestampMs: at, direction: outgoing ? 'outgoing' : 'incoming' } as ChatHistoryEntry,
    id,
    author,
    outgoing,
    mutation: null,
    replyTo: null,
    replyToMutation: null,
    reactions: [],
    receipt: null,
    timerChange: null,
    groupUpdate: null,
    callLog: null,
    undecryptable: false,
    groupCall: null,
    viewedOnce: null,
    poll: null,
    pollEnded: null,
    liveLocation: null,
    ...extra,
  }
}

const kinds = (rows: ReturnType<typeof timelineRows>) =>
  rows.map((r) => (r.kind === 'message' ? `${r.view.id}${r.joinedAbove ? '^' : ''}${r.joinedBelow ? 'v' : ''}` : r.kind))

describe('timelineRows', () => {
  it('groups one author’s messages within three minutes', () => {
    const rows = timelineRows(
      [view('a', T0, 'bob'), view('b', T0 + 60_000, 'bob'), view('c', T0 + 5 * 60_000, 'bob'), view('d', T0 + 5 * 60_000 + 1, 'me')],
      null,
    )
    expect(kinds(rows)).toEqual(['day', 'av', 'b^', 'c', 'd'])
  })

  it('puts a heading where the day changes and breaks the group there', () => {
    const rows = timelineRows([view('a', T0, 'bob'), view('b', T0 + DAY, 'bob')], null)
    expect(kinds(rows)).toEqual(['day', 'a', 'day', 'b'])
  })

  it('marks the first unread incoming message and counts the rest', () => {
    const rows = timelineRows(
      [view('a', T0, 'bob'), view('b', T0 + 1_000, 'bob'), view('c', T0 + 2_000, 'me'), view('d', T0 + 3_000, 'bob')],
      { after: T0, openedAt: T0 + 3_000 },
    )
    expect(kinds(rows)).toEqual(['day', 'a', 'unread', 'b', 'c', 'd'])
    expect(rows.find((r) => r.kind === 'unread')).toMatchObject({ count: 2 })
  })

  it('gives no marker to what arrives while the conversation is open', () => {
    const rows = timelineRows([view('a', T0, 'bob'), view('b', T0 + 5_000, 'bob')], { after: T0, openedAt: T0 + 1_000 })
    expect(kinds(rows)).not.toContain('unread')
  })

  it('keeps notices out of groups and reactions end a group', () => {
    const rows = timelineRows(
      [
        view('a', T0, 'bob', { reactions: [{ emoji: '👍', count: 1, reactedBySelf: false, reactors: ['x'] }] }),
        view('b', T0 + 1_000, 'bob'),
        view('t', T0 + 2_000, 'me', { timerChange: { seconds: 60 } }),
        view('c', T0 + 3_000, 'bob'),
      ],
      null,
    )
    expect(kinds(rows)).toEqual(['day', 'a', 'b', 'notice', 'c'])
  })

  it('puts a group change on its own row, never joined or counted unread', () => {
    const rows = timelineRows(
      [
        view('a', T0, 'bob'),
        view('n', T0 + 1_000, 'bob', { groupUpdate: { actor: 'bob', changes: [{ type: 'nameChanged', name: 'X' }] } }),
        view('b', T0 + 2_000, 'bob'),
      ],
      { after: T0 - 1, openedAt: T0 + 10_000 },
    )
    expect(kinds(rows)).toEqual(['day', 'unread', 'a', 'notice', 'b'])
    expect(rows.find((r) => r.kind === 'unread')).toMatchObject({ count: 2 })
  })
})
