import { afterEach, describe, expect, it, vi } from 'vitest'
import { ChatService } from './service'
import type { ChatHistoryEntry } from './types'
import api from '@kutup/session/client'

vi.mock('@kutup/session/client', () => ({ default: { post: vi.fn(), get: vi.fn(), delete: vi.fn() } }))

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
  } as Record<string, ReturnType<typeof vi.fn>>
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
    ledgerMark: null,
    remoteWrites: 0,
    pendingAttachments: new Map(),
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

  it('enters attachments from the conversations that changed, and retries what could not be entered', async () => {
    const attachment = (id: string, attachmentId: string): ChatHistoryEntry => {
      const value = entry(id)
      value.content = {
        ...value.content,
        kind: 'attachment',
        messageId: id,
        attachment: { attachmentId, ciphertextBytes: 10, ciphertextSha256: 'h' },
      } as ChatHistoryEntry['content']
      return value
    }
    let commits = 0
    let changed: string[] | null = []
    const { svc, client } = service(() => [attachment('m1', 'att-1')], () => commits)
    Object.assign(client, {
      changedConversations: vi.fn(() => changed),
      conversationHistory: vi.fn(async () => ({ entries: [attachment('m2', 'att-2')] })),
      contacts: vi.fn().mockResolvedValue([]),
    })
    const entered = new Set<string>()
    Object.assign(svc, {
      attachmentLedger: {
        sync: vi.fn(),
        entries: () => [],
        hasAttachment: (_message: string, id: string) => entered.has(id),
      },
      withAttachmentLedgerLock: (work: () => Promise<unknown>) => work(),
      deleteAttachmentReference: vi.fn(),
      createAttachmentLedgerEntry: vi.fn(async (_c: unknown, _m: string, descriptor: { attachmentId: string }) => {
        entered.add(descriptor.attachmentId)
      }),
      username: 'me',
      capabilities: { serverName: 'kutup.test' },
    })
    const reference = (id: string) => ({ data: { attachmentId: id, storageReferenceId: 'r', ciphertextBytes: 10, ciphertextSha256: 'h' } })
    const notFound = Object.assign(new Error('missing'), { response: { status: 404 } })
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url.includes('att-2') && !entered.has('retry')) {
        entered.add('retry')
        throw notFound
      }
      return reference(url.split('/').at(-1)!)
    })
    const pass = () => (svc as unknown as { reconcileAttachmentLedger(): Promise<void> }).reconcileAttachmentLedger()

    // The first pass looks at the whole history.
    await pass()
    expect(client.history).toHaveBeenCalledTimes(1)
    expect(entered.has('att-1')).toBe(true)

    // Then only the conversation that changed: its attachment is not there yet.
    commits = 1
    changed = ['group:g1']
    await pass()
    expect(client.history).toHaveBeenCalledTimes(1)
    expect(client.conversationHistory).toHaveBeenCalledTimes(1)
    expect(entered.has('att-2')).toBe(false)

    // Nothing changed since, but the waiting attachment is tried again.
    changed = []
    await pass()
    expect(client.conversationHistory).toHaveBeenCalledTimes(1)
    expect(entered.has('att-2')).toBe(true)
    expect((svc as unknown as { pendingAttachments: Map<string, unknown> }).pendingAttachments.size).toBe(0)
  })
})
