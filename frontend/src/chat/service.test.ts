import { afterEach, describe, expect, it, vi } from 'vitest'
import api from '@/api/client'
import { ChatService } from './service'

vi.mock('@/api/client', () => ({
  default: {
    delete: vi.fn(),
    get: vi.fn(),
  },
}))

function installQueuedWebLocks() {
  const tails = new Map<string, Promise<void>>()
  const request = vi.fn(<T>(
    name: string,
    _options: LockOptions,
    callback: () => Promise<T>,
  ): Promise<T> => {
    const previous = tails.get(name) ?? Promise.resolve()
    const result = previous.then(callback)
    tails.set(name, result.then(() => undefined, () => undefined))
    return result
  })
  Object.defineProperty(navigator, 'locks', {
    configurable: true,
    value: { request },
  })
  return request
}

function deferred() {
  let resolve!: () => void
  const promise = new Promise<void>((done) => {
    resolve = done
  })
  return { promise, resolve }
}

describe('ChatService MLS workflow coordination', () => {
  afterEach(() => {
    vi.restoreAllMocks()
    Reflect.deleteProperty(navigator, 'locks')
  })

  it('does not interleave an authority change with background reconciliation', async () => {
    const requestLock = installQueuedWebLocks()
    const reconciliationStarted = deferred()
    const finishReconciliation = deferred()
    const mls = {
      reconcile: vi.fn(async () => {
        reconciliationStarted.resolve()
        await finishReconciliation.promise
      }),
      setAuthorities: vi.fn().mockResolvedValue(undefined),
    }
    const service = Object.create(ChatService.prototype) as ChatService
    Object.assign(service, {
      client: {
        purgeExpiredMessages: vi.fn().mockResolvedValue({
          expiredMessages: 0,
          expiredAttachmentIds: [],
        }),
        reconcile: vi.fn().mockResolvedValue({ received: 0 }),
      },
      lockName: 'kutup-chat-engine:test',
      mlsWorkflowLockName: 'kutup-chat-engine:test:mls-workflow',
      mls,
      channel: { postMessage: vi.fn() },
      listeners: new Set(),
      reconcilePromise: null,
    })

    const reconciliation = service.reconcile()
    await reconciliationStarted.promise
    const authorityChange = service.setGroupAuthorities(
      '11111111-1111-4111-8111-111111111111',
      ['alpha.example'],
    )
    await Promise.resolve()

    expect(mls.setAuthorities).not.toHaveBeenCalled()

    finishReconciliation.resolve()
    await Promise.all([reconciliation, authorityChange])

    expect(mls.setAuthorities).toHaveBeenCalledOnce()
    expect(requestLock.mock.calls.filter(([name]) =>
      name === 'kutup-chat-engine:test:mls-workflow')).toHaveLength(2)
  })

  it('refuses to revoke the current browser device', async () => {
    const transport = {
      revokeDevice: vi.fn(),
      listDevices: vi.fn(),
    }
    const service = Object.create(ChatService.prototype) as ChatService
    Object.assign(service, { deviceId: 2, transport })

    await expect(service.revokeDevice(2)).rejects.toThrow(
      'the current Chat device cannot revoke itself',
    )
    expect(transport.revokeDevice).not.toHaveBeenCalled()
  })

  it('keeps a Direct Chat reply target inside the WASM content call', async () => {
    installQueuedWebLocks()
    const sendId = '22222222-2222-4222-8222-222222222222'
    const replyTo = '11111111-1111-4111-8111-111111111111'
    vi.stubGlobal('crypto', { randomUUID: () => sendId })
    const summary = {
      delivered: true,
      deduplicated: false,
      attempts: 1,
      safetyNumberChanges: [],
      content: [],
      ciphertext: [],
    }
    const client = { sendText: vi.fn(async () => summary) }
    const service = Object.create(ChatService.prototype) as ChatService
    Object.assign(service, {
      client,
      username: 'alice',
      capabilities: { serverName: 'a.test' },
      lockName: 'kutup-chat-engine:test',
      channel: { postMessage: vi.fn() },
      listeners: new Set(),
      mls: null,
    })

    await expect(service.send(
      { kind: 'direct', address: { username: 'bob', server: 'b.test' } },
      'quoted reply',
      replyTo,
    )).resolves.toEqual(summary)

    expect(client.sendText).toHaveBeenCalledWith(
      sendId,
      'bob@b.test',
      expect.any(String),
      'quoted reply',
      replyTo,
      undefined,
    )
  })

  it('authenticates the active disappearing duration on Direct messages', async () => {
    installQueuedWebLocks()
    const sendId = '77777777-7777-4777-8777-777777777777'
    vi.stubGlobal('crypto', { randomUUID: () => sendId })
    const summary = {
      delivered: true,
      deduplicated: false,
      attempts: 1,
      safetyNumberChanges: [],
    }
    const client = { sendText: vi.fn(async () => summary) }
    const service = Object.create(ChatService.prototype) as ChatService
    Object.assign(service, {
      client,
      username: 'alice',
      capabilities: { serverName: 'a.test' },
      lockName: 'kutup-chat-engine:test',
      channel: { postMessage: vi.fn() },
      listeners: new Set(),
      mls: null,
    })

    await service.send(
      { kind: 'direct', address: { username: 'bob', server: 'b.test' } },
      'temporary',
      undefined,
      30,
    )

    expect(client.sendText).toHaveBeenCalledWith(
      sendId,
      'bob@b.test',
      expect.any(String),
      'temporary',
      undefined,
      30,
    )
  })

  it('keeps a Direct Chat reaction target and state inside the WASM content call', async () => {
    installQueuedWebLocks()
    const sendId = '33333333-3333-4333-8333-333333333333'
    const targetMessageId = '11111111-1111-4111-8111-111111111111'
    vi.stubGlobal('crypto', { randomUUID: () => sendId })
    const summary = {
      delivered: true,
      deduplicated: false,
      attempts: 1,
      safetyNumberChanges: [],
      content: [],
      ciphertext: [],
    }
    const client = { sendReaction: vi.fn(async () => summary) }
    const service = Object.create(ChatService.prototype) as ChatService
    Object.assign(service, {
      client,
      username: 'alice',
      capabilities: { serverName: 'a.test' },
      lockName: 'kutup-chat-engine:test',
      channel: { postMessage: vi.fn() },
      listeners: new Set(),
      mls: null,
    })

    await expect(service.sendReaction(
      { kind: 'direct', address: { username: 'bob', server: 'b.test' } },
      targetMessageId,
      '👍',
      false,
    )).resolves.toEqual(summary)

    expect(client.sendReaction).toHaveBeenCalledWith(
      sendId,
      'bob@b.test',
      expect.any(String),
      targetMessageId,
      '👍',
      false,
    )
  })

  it('keeps a Direct Chat edit target and replacement inside the WASM content call', async () => {
    installQueuedWebLocks()
    const sendId = '44444444-4444-4444-8444-444444444444'
    const targetMessageId = '11111111-1111-4111-8111-111111111111'
    vi.stubGlobal('crypto', { randomUUID: () => sendId })
    const summary = {
      delivered: true,
      deduplicated: false,
      attempts: 1,
      safetyNumberChanges: [],
      content: [],
      ciphertext: [],
    }
    const client = { sendMessageMutation: vi.fn(async () => summary) }
    const service = Object.create(ChatService.prototype) as ChatService
    Object.assign(service, {
      client,
      username: 'alice',
      capabilities: { serverName: 'a.test' },
      lockName: 'kutup-chat-engine:test',
      channel: { postMessage: vi.fn() },
      listeners: new Set(),
      mls: null,
    })

    await expect(service.mutateMessage(
      { kind: 'direct', address: { username: 'bob', server: 'b.test' } },
      targetMessageId,
      'edit',
      'corrected',
    )).resolves.toEqual(summary)

    expect(client.sendMessageMutation).toHaveBeenCalledWith(
      sendId,
      'bob@b.test',
      expect.any(String),
      targetMessageId,
      'edit',
      'corrected',
    )
  })

  it('batches Direct delivery receipts only inside the WASM content call', async () => {
    installQueuedWebLocks()
    const sendId = '55555555-5555-4555-8555-555555555555'
    const messageIds = [
      '11111111-1111-4111-8111-111111111111',
      '22222222-2222-4222-8222-222222222222',
    ]
    vi.stubGlobal('crypto', { randomUUID: () => sendId })
    const summary = {
      delivered: true,
      deduplicated: false,
      attempts: 1,
      safetyNumberChanges: [],
      content: [],
      ciphertext: [],
    }
    const client = { sendReceipt: vi.fn(async () => summary) }
    const service = Object.create(ChatService.prototype) as ChatService
    Object.assign(service, {
      client,
      username: 'alice',
      capabilities: { serverName: 'a.test' },
      lockName: 'kutup-chat-engine:test',
      channel: { postMessage: vi.fn() },
      listeners: new Set(),
      mls: null,
    })

    await expect(service.sendReceipt(
      { kind: 'direct', address: { username: 'bob', server: 'b.test' } },
      messageIds,
      'delivered',
    )).resolves.toEqual(summary)

    expect(client.sendReceipt).toHaveBeenCalledWith(
      sendId,
      'bob@b.test',
      expect.any(String),
      messageIds,
      'delivered',
    )
  })

  it('sends Direct typing only as an ephemeral WASM control', async () => {
    installQueuedWebLocks()
    const sendId = '55555555-5555-4555-8555-555555555555'
    vi.stubGlobal('crypto', { randomUUID: () => sendId })
    const client = { sendTyping: vi.fn().mockResolvedValue({ delivered: true }) }
    const service = Object.create(ChatService.prototype) as ChatService
    Object.assign(service, {
      client,
      username: 'alice',
      capabilities: { serverName: 'a.test' },
      lockName: 'kutup-chat-engine:test',
      mls: null,
    })

    await expect(service.sendTyping(
      { kind: 'direct', address: { username: 'bob', server: 'b.test' } },
      true,
    )).resolves.toBeUndefined()

    expect(client.sendTyping).toHaveBeenCalledWith(
      sendId,
      'bob@b.test',
      expect.any(String),
      true,
    )
  })

  it('sends a Direct disappearing timer as encrypted durable conversation state', async () => {
    installQueuedWebLocks()
    const sendId = '66666666-6666-4666-8666-666666666666'
    vi.stubGlobal('crypto', { randomUUID: () => sendId })
    const summary = {
      delivered: true,
      deduplicated: false,
      attempts: 1,
      safetyNumberChanges: [],
    }
    const client = { sendDisappearingTimer: vi.fn().mockResolvedValue(summary) }
    const channel = { postMessage: vi.fn() }
    const service = Object.create(ChatService.prototype) as ChatService
    Object.assign(service, {
      client,
      username: 'alice',
      capabilities: { serverName: 'a.test' },
      lockName: 'kutup-chat-engine:test',
      mls: null,
      channel,
      listeners: new Set(),
    })

    await expect(service.sendDisappearingTimer(
      { kind: 'direct', address: { username: 'bob', server: 'b.test' } },
      86_400,
    )).resolves.toEqual(summary)

    expect(client.sendDisappearingTimer).toHaveBeenCalledWith(
      sendId,
      'bob@b.test',
      expect.any(String),
      86_400,
    )
    expect(channel.postMessage).toHaveBeenCalledWith({ type: 'updated' })
  })

  it('synchronizes a recipient first-view deadline through the encrypted account path', async () => {
    installQueuedWebLocks()
    const sendId = '99999999-9999-4999-8999-999999999999'
    const targetMessageId = '88888888-8888-4888-8888-888888888888'
    const startedAtMs = 1_786_315_200_000
    const conversation = {
      kind: 'direct' as const,
      address: { username: 'bob', server: 'b.test' },
    }
    vi.stubGlobal('crypto', { randomUUID: () => sendId })
    const summary = {
      delivered: true,
      deduplicated: false,
      attempts: 1,
      safetyNumberChanges: [],
    }
    const client = { startDisappearingExpiry: vi.fn().mockResolvedValue(summary) }
    const channel = { postMessage: vi.fn() }
    const service = Object.create(ChatService.prototype) as ChatService
    Object.assign(service, {
      client,
      lockName: 'kutup-chat-engine:test',
      channel,
      listeners: new Set(),
      mls: null,
    })

    await expect(service.startDisappearingExpiry(
      conversation,
      targetMessageId,
      startedAtMs,
    )).resolves.toEqual(summary)

    expect(client.startDisappearingExpiry).toHaveBeenCalledWith(
      sendId,
      new Date(startedAtMs).toISOString(),
      conversation,
      targetMessageId,
      String(startedAtMs),
    )
    expect(channel.postMessage).toHaveBeenCalledWith({ type: 'updated' })
  })

  it('durably expires attachment accounting before deletion and retries after failure', async () => {
    installQueuedWebLocks()
    const entry = {
      entityId: 'ledger-entity',
      entry: {
        attachmentId: 'temporary-attachment',
        state: 'active',
      },
    }
    const attachmentLedger = {
      sync: vi.fn().mockResolvedValue(undefined),
      entries: vi.fn(() => [entry]),
      activeEntries: vi.fn(() => entry.entry.state === 'active' ? [entry] : []),
      markExpired: vi.fn(async () => { entry.entry.state = 'expired' }),
    }
    const client = {
      purgeExpiredMessages: vi.fn()
        .mockResolvedValueOnce({
          expiredMessages: 1,
          expiredAttachmentIds: ['temporary-attachment'],
        })
        .mockResolvedValue({ expiredMessages: 0, expiredAttachmentIds: [] }),
      history: vi.fn().mockResolvedValue([]),
      contacts: vi.fn().mockResolvedValue([]),
    }
    vi.mocked(api.delete)
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValue({} as never)
    const service = Object.create(ChatService.prototype) as ChatService
    Object.assign(service, {
      client,
      attachmentLedger,
      username: 'alice',
      capabilities: { serverName: 'a.test' },
      lockName: 'kutup-chat-engine:test',
    })

    await expect(service.history()).rejects.toThrow('offline')
    expect(attachmentLedger.markExpired).toHaveBeenCalledOnce()
    expect(entry.entry.state).toBe('expired')
    expect(attachmentLedger.markExpired.mock.invocationCallOrder[0])
      .toBeLessThan(vi.mocked(api.delete).mock.invocationCallOrder[0])

    await (service as unknown as {
      reconcileAttachmentLedger(): Promise<void>
    }).reconcileAttachmentLedger()

    expect(api.delete).toHaveBeenCalledTimes(2)
    expect(api.delete).toHaveBeenLastCalledWith(
      '/chat/media/references/temporary-attachment',
    )
  })

  it('notifies local-cache expiry listeners even when media accounting is unavailable', async () => {
    installQueuedWebLocks()
    const purgeLocal = vi.fn().mockResolvedValue(undefined)
    const service = Object.create(ChatService.prototype) as ChatService
    Object.assign(service, {
      client: {
        purgeExpiredMessages: vi.fn().mockResolvedValue({
          expiredMessages: 1,
          expiredAttachmentIds: ['temporary-attachment'],
        }),
        history: vi.fn().mockResolvedValue([]),
      },
      attachmentLedger: null,
      attachmentExpiryListeners: new Set([purgeLocal]),
      lockName: 'kutup-chat-engine:test',
    })
    await expect(service.history()).resolves.toEqual([])
    expect(purgeLocal).toHaveBeenCalledWith(['temporary-attachment'])
  })

  it('repairs the signed manifest and MLS membership after revocation', async () => {
    installQueuedWebLocks()
    const calls: string[] = []
    const remainingDevices = [{
      deviceId: 2,
      suite: 1,
      name: 'Current browser',
      createdAt: '2026-08-09T10:00:00Z',
      lastSeenAt: null,
    }]
    const transport = {
      revokeDevice: vi.fn(async () => { calls.push('revoke') }),
      listDevices: vi.fn(async () => remainingDevices),
    }
    const client = {
      syncManifest: vi.fn(async () => {
        calls.push('manifest')
        return {
          sequence: 3,
          devices: [
            { deviceId: 2, mls: {} },
            { deviceId: 3 },
          ],
        }
      }),
    }
    const mls = {
      maintainKeyPackages: vi.fn(async () => { calls.push('packages') }),
      reconcileLinkedDevices: vi.fn(async () => { calls.push('mls') }),
    }
    const channel = { postMessage: vi.fn() }
    const service = Object.create(ChatService.prototype) as ChatService
    Object.assign(service, {
      deviceId: 2,
      transport,
      client,
      mls,
      lockName: 'kutup-chat-engine:test',
      mlsWorkflowLockName: 'kutup-chat-engine:test:mls-workflow',
      channel,
      listeners: new Set(),
    })

    await expect(service.revokeDevice(1)).resolves.toEqual(remainingDevices)

    expect(calls).toEqual(['revoke', 'manifest', 'packages', 'mls'])
    expect(mls.maintainKeyPackages).toHaveBeenCalledWith(3)
    expect(mls.reconcileLinkedDevices).toHaveBeenCalledWith([2])
    expect(channel.postMessage).toHaveBeenCalledWith({ type: 'updated' })
    expect(transport.listDevices).toHaveBeenCalledOnce()
  })

  it('serializes history recovery through the engine lock and refreshes peers', async () => {
    const requestLock = installQueuedWebLocks()
    const request = {
      version: 1,
      transferId: '11111111-1111-4111-8111-111111111111',
      account: 'alice@a.test',
      requestingDeviceId: 2,
      createdAtUnix: 1,
      expiresAtUnix: 2,
    }
    const client = {
      requestHistoryTransfer: vi.fn(async () => request),
      listHistoryTransfers: vi.fn(async () => ({ transfers: [] })),
      approveHistoryTransfer: vi.fn(async () => new Map<string, unknown>([
        ['acceptance', {}],
        ['frameCount', 3],
      ])),
      downloadHistoryTransfer: vi.fn(async () => new Map<string, unknown>([
        ['ready', true],
        ['frameCount', 3],
        ['importedCount', 1],
      ])),
    }
    const channel = { postMessage: vi.fn() }
    const service = Object.create(ChatService.prototype) as ChatService
    Object.assign(service, {
      client,
      lockName: 'kutup-chat-engine:test',
      channel,
      listeners: new Set(),
    })

    await expect(service.requestHistoryTransfer()).resolves.toEqual(request)
    await expect(service.historyTransfers()).resolves.toEqual({ transfers: [] })
    await expect(service.approveHistoryTransfer(request)).resolves.toEqual({
      acceptance: {},
      frameCount: 3,
    })
    await expect(service.downloadHistoryTransfer(request.transferId)).resolves.toEqual({
      ready: true,
      frameCount: 3,
      importedCount: 1,
    })

    expect(client.approveHistoryTransfer).toHaveBeenCalledWith(
      request,
      100_000,
      '268435456',
    )
    expect(requestLock.mock.calls.every(([name]) =>
      name === 'kutup-chat-engine:test')).toBe(true)
    expect(channel.postMessage).toHaveBeenCalledTimes(3)
  })
})
