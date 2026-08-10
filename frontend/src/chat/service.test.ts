import { afterEach, describe, expect, it, vi } from 'vitest'
import { ChatService } from './service'

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
      client: { reconcile: vi.fn().mockResolvedValue({ received: 0 }) },
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
        return { sequence: 3, devices: [{ deviceId: 2, mls: {} }] }
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
