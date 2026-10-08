import { describe, expect, it, vi } from 'vitest'
import { LiveTimeline, windowHistory, type CoreConversationSummary, type LiveTimelineCore } from './liveTimeline'
import type { ChatHistoryEntry, ConversationId } from './types'

function entry(id: string, groupId: string, timestampMs: number): ChatHistoryEntry {
  return {
    id,
    conversation: { kind: 'group', groupId },
    peer: '',
    direction: 'incoming',
    timestampMs,
    delivered: true,
    deduplicated: false,
    content: { version: 1, kind: 'text', sentAt: '', seq: '1', body: {}, text: id },
  } as ChatHistoryEntry
}

function summary(groupId: string, ...entries: ChatHistoryEntry[]): CoreConversationSummary {
  return { key: `core:${groupId}`, conversation: { kind: 'group', groupId }, latestMs: 1, unread: 0, recent: entries }
}

function setup() {
  let commits = 0
  let keys: string[] | null = null
  const store = new Map<string, CoreConversationSummary>([
    ['core:a', summary('a', entry('a1', 'a', 1))],
    ['core:b', summary('b', entry('b1', 'b', 2))],
    ['core:self', summary('self')],
  ])
  const core = {
    changes: vi.fn(async () => ({ commits, keys })),
    accountControls: vi.fn(async () => [] as ChatHistoryEntry[]),
    summaries: vi.fn(async (_readThrough: Record<string, number>, _recent: number, wanted?: string[]) =>
      [...store.values()].filter((value) => !wanted || wanted.includes(value.key))),
    page: vi.fn(),
  } satisfies LiveTimelineCore
  const timeline = new LiveTimeline(
    core,
    (value) => value,
    (conversation: ConversationId) => ({
      key: conversation.kind === 'group' ? `group:${conversation.groupId}` : 'direct',
      conversation,
    }),
    'group:self',
  )
  return {
    core,
    store,
    timeline,
    commit: (touched: string[] | null) => {
      commits += 1
      keys = touched
    },
  }
}

describe('LiveTimeline', () => {
  it('reads everything first, then only the conversations a change touched', async () => {
    const { core, store, timeline, commit } = setup()
    const first = await timeline.refresh(() => ({}))
    expect(first.summaries.map((value) => value.key).sort()).toEqual(['group:a', 'group:b', 'group:self'])
    expect(core.summaries).toHaveBeenLastCalledWith({}, 30, undefined)
    expect(core.accountControls).toHaveBeenCalledTimes(1)

    store.set('core:a', summary('a', entry('a2', 'a', 3), entry('a1', 'a', 1)))
    commit(['core:a'])
    const second = await timeline.refresh(() => ({ 'group:a': 1 }))
    expect(core.summaries).toHaveBeenLastCalledWith({ 'core:a': 1 }, 30, ['core:a'])
    expect(core.accountControls).toHaveBeenCalledTimes(1)
    expect(windowHistory(second).map((value) => value.id)).toEqual(['a1', 'b1', 'a2'])

    commit(['core:self'])
    await timeline.refresh(() => ({}))
    expect(core.accountControls).toHaveBeenCalledTimes(2)
  })

  it('reads nothing when nothing changed, and drops a conversation that is gone', async () => {
    const { core, store, timeline, commit } = setup()
    await timeline.refresh(() => ({}))
    commit([])
    await timeline.refresh(() => ({}))
    expect(core.summaries).toHaveBeenCalledTimes(1)

    store.delete('core:b')
    commit(['core:b'])
    const after = await timeline.refresh(() => ({}))
    expect(after.summaries.map((value) => value.key).sort()).toEqual(['group:a', 'group:self'])
  })

  it('reads everything again after another tab wrote or when the journal cannot tell', async () => {
    const { core, timeline, commit } = setup()
    await timeline.refresh(() => ({}))
    timeline.invalidateAll()
    commit([])
    await timeline.refresh(() => ({}))
    expect(core.summaries).toHaveBeenLastCalledWith({}, 30, undefined)

    commit(null)
    await timeline.refresh(() => ({}))
    expect(core.summaries).toHaveBeenCalledTimes(3)
    expect(core.summaries).toHaveBeenLastCalledWith({}, 30, undefined)
  })
})
