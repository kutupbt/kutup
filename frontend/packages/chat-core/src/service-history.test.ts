import { afterEach, describe, expect, it, vi } from 'vitest'
import { ChatService } from './service'
import type { ChatHistoryEntry } from './types'

vi.mock('@kutup/session/client', () => ({ default: { post: vi.fn(), get: vi.fn() } }))

function entry(id: string, expiresAtMs?: number): ChatHistoryEntry {
  return {
    id,
    conversation: { kind: 'group', groupId: 'g1' },
    peer: '',
    direction: 'incoming',
    timestampMs: 1,
    delivered: true,
    deduplicated: false,
    content: { version: 1, kind: 'text', sentAt: '', seq: '1', body: {}, text: id, expiresAtMs },
  } as ChatHistoryEntry
}

function service(history: () => ChatHistoryEntry[], commits: () => number = () => 0) {
  const client = {
    purgeExpiredMessages: vi.fn().mockResolvedValue({ expiredMessages: 0, expiredAttachmentIds: [] }),
    history: vi.fn(async () => history()),
    reconcile: vi.fn().mockResolvedValue({ messages: [] }),
    storeCommits: vi.fn(commits),
  }
  const updates = vi.fn()
  const svc = Object.create(ChatService.prototype) as ChatService
  Object.assign(svc, {
    client,
    revision: 0,
    historyCache: new Map(),
    capabilities: { serverName: 'kutup.test' },
    backup: null,
    attachmentLedger: null,
    listeners: new Set([updates]),
    channel: { postMessage: vi.fn() },
    reconcilePromise: null,
    reportedSendFailures: new Set(),
    withLock: (work: () => Promise<unknown>) => work(),
    withMlsWorkflow: (work: () => Promise<unknown>) => work(),
    mls: null,
  })
  return { svc, client, updates }
}

describe('ChatService history', () => {
  afterEach(() => vi.useRealTimers())

  it('loads the history once per change, however many ask for it', async () => {
    let rows = [entry('a')]
    const { svc, client } = service(() => rows)
    const [first, second] = await Promise.all([svc.history(), svc.history()])
    expect(first).toBe(second)
    await svc.history()
    expect(client.history).toHaveBeenCalledTimes(1)

    rows = [entry('a'), entry('b')]
    ;(svc as unknown as { emitUpdate(): void }).emitUpdate()
    expect((await svc.history()).map((e) => e.id)).toEqual(['a', 'b'])
    expect(client.history).toHaveBeenCalledTimes(2)
  })

  it('loads again once a disappearing message is due', async () => {
    vi.useFakeTimers({ now: 1_000 })
    const { svc, client } = service(() => [entry('a', 5_000)])
    await svc.history()
    await svc.history()
    expect(client.history).toHaveBeenCalledTimes(1)
    vi.setSystemTime(5_000)
    await svc.history()
    expect(client.history).toHaveBeenCalledTimes(2)
  })

  it('tells nobody about a reconcile that wrote nothing', async () => {
    let commits = 4
    const { svc, updates } = service(() => [], () => commits)
    await svc.reconcile()
    expect(updates).not.toHaveBeenCalled()

    const client = (svc as unknown as { client: { reconcile: ReturnType<typeof vi.fn> } }).client
    client.reconcile.mockImplementationOnce(async () => {
      commits += 1
      return { messages: [] }
    })
    await svc.reconcile()
    expect(updates).toHaveBeenCalledTimes(1)
  })
})
