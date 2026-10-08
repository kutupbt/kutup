// @vitest-environment node
import 'fake-indexeddb/auto'
import { afterEach, describe, expect, it, vi } from 'vitest'

vi.mock('@kutup/crypto/accountEnvelope', () => ({
  ACCOUNT_ENVELOPE_PURPOSE: { chatBackupRoot: 4 },
  openAccountEnvelope: vi.fn(async () => new Uint8Array(32).fill(7)),
  sealAccountEnvelope: vi.fn(async () => 'sealed-root'),
}))

vi.mock('@kutup/crypto/identity', () => ({
  deriveAccountIdentityKeys: vi.fn(async () => ({
    incarnationId: '11111111-1111-4111-8111-111111111111',
  })),
}))

const jsonBytes = (value: unknown) => new TextEncoder().encode(JSON.stringify(value))
const bytesJson = (bytes: Uint8Array) => JSON.parse(new TextDecoder().decode(bytes))
const bytesBase64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64')
const base64Bytes = (value: string) => new Uint8Array(Buffer.from(value, 'base64'))

vi.mock('@kutup/crypto/rustWasm', () => ({
  getCryptoWasm: vi.fn(async () => ({
    verifyChatBackupMetadata: (_authorization: unknown, manifest?: { baseCiphertextSha256: string }) => ({
      signerAuthorizationDigest: '1'.repeat(64),
      manifestDigest: manifest?.baseCiphertextSha256,
    }),
    encodeChatBackupPlaintext: (value: unknown) => jsonBytes(value),
    decodeChatBackupPlaintext: (value: string) => bytesJson(base64Bytes(value)),
    sealChatBackupObject: (plaintext: Uint8Array) => bytesBase64(plaintext),
    openChatBackupObject: (ciphertext: string) => ciphertext,
    signChatBackupManifest: (manifest: unknown) => manifest,
  })),
}))

import {
  ChatBackupCoordinator,
  type BackupStatusResponse,
  type ChatBackupRuntime,
  type ChatBackupTransport,
  type SegmentPage,
} from './backup'
import { getAll, openBackupStore, putValue, type BackupOutboxEntry } from './backup-store'
import type { ChatHistoryEntry } from './types'

const zeroDigest = '0'.repeat(64)
const openCoordinators: ChatBackupCoordinator[] = []
const databaseNames: string[] = []

const authorization = {
  version: 1,
  backupIncarnationId: '22222222-2222-4222-8222-222222222222',
  accountIncarnationId: '11111111-1111-4111-8111-111111111111',
  suite: 1,
  protectionDomain: 1,
  manifestSigningPublicKey: 'public',
  accountAuthorityKeyId: 'authority',
  createdAtUnix: 1_700_000_000,
  accountAuthoritySignature: 'signature',
}

function storage() {
  return {
    quotaBytes: 1_000_000,
    usedBytes: 0,
    messageBytes: 0,
    deliveryMediaBytes: 0,
    historyMediaBytes: 0,
  }
}

class ScriptedTransport implements ChatBackupTransport {
  readonly appendRequests: Parameters<ChatBackupTransport['appendSegment']>[0][] = []
  readonly reconciliationRequests: Parameters<ChatBackupTransport['reconcileMedia']>[0][] = []
  readonly segments: SegmentPage['segments'] = []
  ambiguousOnce = false
  statusOverride?: BackupStatusResponse
  manifest?: NonNullable<BackupStatusResponse['manifest']>
  stagedBase?: Uint8Array
  private cursor = 0

  /** Behave like the server: report each device's chain and enforce it. */
  enforceDeviceChains = false

  private deviceHead(deviceId: number) {
    const last = this.segments.filter(segment => segment.sourceDeviceId === deviceId).at(-1)
    return { sequence: last?.deviceSequence ?? 0, digest: last?.ciphertextSha256 ?? zeroDigest }
  }

  async status(): Promise<BackupStatusResponse> {
    if (this.statusOverride) return structuredClone(this.statusOverride)
    return {
      provisioned: true,
      rootEnvelope: 'sealed-root',
      signerAuthorization: authorization,
      manifest: this.manifest,
      currentCursor: this.cursor,
      latestProtectedAtUnix: this.cursor > 0 ? 1_700_000_100 : undefined,
      storage: storage(),
      ...(this.enforceDeviceChains
        ? {
            deviceHeads: [...new Set(this.segments.map(segment => segment.sourceDeviceId))]
              .map(deviceId => ({ deviceId, ...this.deviceHead(deviceId) })),
          }
        : {}),
    }
  }

  async provision(): Promise<BackupStatusResponse> {
    throw new Error('already provisioned')
  }

  async appendSegment(request: Parameters<ChatBackupTransport['appendSegment']>[0]) {
    this.appendRequests.push(structuredClone(request))
    // The test runtime hands every coordinator the same ids, so an operation
    // is the same one only when it is also the same device and sequence.
    const existing = this.segments.find(segment =>
      segment.operationId === request.operationId
      && segment.sourceDeviceId === request.sourceDeviceId
      && segment.deviceSequence === request.deviceSequence)
    if (!existing && this.enforceDeviceChains) {
      const head = this.deviceHead(request.sourceDeviceId)
      if (request.deviceSequence !== head.sequence + 1 || request.previousSegmentDigest !== head.digest) {
        throw Object.assign(new Error('backup device segment chain is not contiguous'), { response: { status: 409 } })
      }
    }
    if (!existing) {
      this.cursor += 1
      this.segments.push({
        ...request,
        cursor: this.cursor,
        acknowledgedAtUnix: 1_700_000_100,
      })
    }
    if (this.ambiguousOnce) {
      this.ambiguousOnce = false
      throw new Error('connection closed after commit')
    }
    const committed = this.segments.find(segment =>
      segment.operationId === request.operationId
      && segment.sourceDeviceId === request.sourceDeviceId
      && segment.deviceSequence === request.deviceSequence)!
    return { cursor: committed.cursor, acknowledgedAtUnix: committed.acknowledgedAtUnix }
  }

  async listSegments(after: number): Promise<SegmentPage> {
    return {
      segments: this.segments.filter(segment => segment.cursor > after),
      currentCursor: this.cursor,
      more: false,
    }
  }

  async stageBase(
    _metadata: Parameters<ChatBackupTransport['stageBase']>[0],
    ciphertext: Uint8Array,
  ): Promise<void> { this.stagedBase = ciphertext.slice() }
  async downloadBase(): Promise<Uint8Array> {
    if (!this.stagedBase) throw new Error('no base')
    return this.stagedBase.slice()
  }
  async copyMedia(): Promise<void> {}
  async uploadMedia(): Promise<void> {}
  async downloadMedia(): Promise<never> { throw new Error('no media') }
  async reconcileMedia(
    request: Parameters<ChatBackupTransport['reconcileMedia']>[0],
  ): Promise<void> { this.reconciliationRequests.push(structuredClone(request)) }
  async compareAndSwapManifest(
    request: Parameters<ChatBackupTransport['compareAndSwapManifest']>[0],
  ): Promise<void> { this.manifest = structuredClone(request.manifest) }
}

function historyEntry(): ChatHistoryEntry {
  return {
    id: '33333333-3333-4333-8333-333333333333',
    conversation: { kind: 'direct', address: { username: 'user', server: 'kutup.dev' } },
    peer: 'user@kutup.dev',
    direction: 'outgoing',
    senderDeviceId: 9,
    timestampMs: 1_700_000_000_000,
    delivered: true,
    deduplicated: false,
    content: {
      version: 1,
      kind: 'text',
      sentAt: '1700000000',
      seq: '1',
      messageId: '44444444-4444-4444-8444-444444444444',
      body: { text: 'durable' },
      text: 'durable',
    },
  }
}

function mediaHistoryEntry(): ChatHistoryEntry {
  const entry = historyEntry()
  return {
    ...entry,
    content: {
      ...entry.content,
      attachment: {
        version: 1,
        suite: 1,
        attachmentId: '55555555-5555-4555-8555-555555555555',
        originDomain: 'kutup.dev',
        retrievalToken: 'opaque-token',
        ciphertextBytes: 128,
        ciphertextSha256: 'a'.repeat(64),
        attachmentKey: Buffer.alloc(32, 6).toString('base64'),
        plaintextBytes: 7,
        filename: 'protected.txt',
        mimeType: 'text/plain',
        mediaClass: 'file',
        backupMediaId: 'b'.repeat(64),
        backupMediaReferenceId: '66666666-6666-4666-8666-666666666666',
      },
    },
  }
}

function runtime(
  transport: ChatBackupTransport,
  checkpoint?: ChatBackupRuntime['checkpoint'],
): ChatBackupRuntime {
  let id = 10
  return {
    transport,
    connectivity: { isOnline: () => true },
    clock: { now: () => 1_700_000_000_000 },
    scheduler: {
      schedule: (_delay, callback) => ({ callback }),
      cancel: () => undefined,
    },
    ids: {
      randomUuid: () => `00000000-0000-4000-8000-${(id++).toString().padStart(12, '0')}`,
      randomBytes: length => new Uint8Array(length).fill(5),
    },
    checkpoint,
  }
}

async function open(
  transport: ScriptedTransport,
  databaseName: string,
  history: () => Promise<ChatHistoryEntry[]> = async () => [historyEntry()],
  checkpoint?: ChatBackupRuntime['checkpoint'],
  deviceId = 9,
) {
  const coordinator = await ChatBackupCoordinator.open({
    databaseName,
    email: 'user@kutup.dev',
    username: 'user',
    serverName: 'kutup.dev',
    masterKey: new Uint8Array(32).fill(3),
    deviceId,
    history,
    manifestSequence: async () => 1,
    mediaSources: () => [],
    localMediaCiphertext: async function* () {},
  }, runtime(transport, checkpoint))
  openCoordinators.push(coordinator)
  return coordinator
}

afterEach(async () => {
  for (const coordinator of openCoordinators.splice(0)) coordinator.dispose()
  await Promise.all(databaseNames.splice(0).map(name => new Promise<void>((resolve, reject) => {
    const request = indexedDB.deleteDatabase(`${name}:continuous-backup`)
    request.onsuccess = () => resolve()
    request.onerror = () => reject(request.error)
  })))
})

describe('ChatBackupCoordinator durable retry', () => {
  it('merges one exact record copy from each independent device chain', async () => {
    const transport = new ScriptedTransport()
    const sourceDatabase = `backup-multi-device-source:${crypto.randomUUID()}`
    const restoredDatabase = `backup-multi-device-restored:${crypto.randomUUID()}`
    databaseNames.push(sourceDatabase, restoredDatabase)
    const source = await open(transport, sourceDatabase)
    await source.settled()
    source.dispose()
    openCoordinators.splice(openCoordinators.indexOf(source), 1)

    const first = transport.appendRequests[0]
    await transport.appendSegment({
      ...structuredClone(first),
      operationId: '77777777-7777-4777-8777-777777777777',
      sourceDeviceId: 10,
      deviceSequence: 1,
      previousSegmentDigest: zeroDigest,
    })

    const restored = await open(transport, restoredDatabase, async () => [])
    await restored.settled()
    expect(await restored.restoredHistoryAsync()).toHaveLength(1)
  })

  it('preserves one authenticated outgoing origin across linked devices', async () => {
    const firstTransport = new ScriptedTransport()
    const secondTransport = new ScriptedTransport()
    const firstDatabase = `backup-linked-first:${crypto.randomUUID()}`
    const secondDatabase = `backup-linked-second:${crypto.randomUUID()}`
    const restoredDatabase = `backup-linked-restored:${crypto.randomUUID()}`
    databaseNames.push(firstDatabase, secondDatabase, restoredDatabase)
    const firstHistory = async () => [historyEntry()]
    const linkedHistory = async () => [{ ...historyEntry(), delivered: false }]

    const first = await open(firstTransport, firstDatabase, firstHistory, undefined, 9)
    const second = await open(secondTransport, secondDatabase, linkedHistory, undefined, 10)
    await Promise.all([first.settled(), second.settled()])

    const secondSegment = secondTransport.appendRequests[0]
    await firstTransport.appendSegment({
      ...structuredClone(secondSegment),
      operationId: '99999999-9999-4999-8999-999999999999',
      sourceDeviceId: 10,
      deviceSequence: 1,
      previousSegmentDigest: zeroDigest,
    })

    const restored = await open(firstTransport, restoredDatabase, async () => [])
    await restored.settled()
    const history = await restored.restoredHistoryAsync()
    expect(history).toHaveLength(1)
    expect(history[0].senderDeviceId).toBe(9)
    expect(history[0].delivered).toBe(true)
  })

  it('accepts a second device deleting a record another device already deleted', async () => {
    // Both of an account's devices prune the same superseded control (or
    // purge the same deleted-for-me message): each emits a tombstone, the
    // second one first seeing the record at the first device's sequence.
    const transport = new ScriptedTransport()
    const sourceDatabase = `backup-double-delete-source:${crypto.randomUUID()}`
    const restoredDatabase = `backup-double-delete-restored:${crypto.randomUUID()}`
    databaseNames.push(sourceDatabase, restoredDatabase)
    let history = [historyEntry()]
    const source = await open(transport, sourceDatabase, async () => history)
    await source.settled()
    history = []
    await source.flushNow()
    await source.settled()
    source.dispose()
    openCoordinators.splice(openCoordinators.indexOf(source), 1)
    expect(transport.appendRequests).toHaveLength(2)

    const tombstone = transport.appendRequests[1]
    await transport.appendSegment({
      ...structuredClone(tombstone),
      operationId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      sourceDeviceId: 10,
      deviceSequence: 1,
      previousSegmentDigest: zeroDigest,
    })

    const restored = await open(transport, restoredDatabase, async () => [])
    await restored.settled()
    expect(await restored.restoredHistoryAsync()).toHaveLength(0)
  })

  it('accepts two devices changing the same record from the same state', async () => {
    // Both of an account's devices apply the same change (a group closing,
    // an edit synced to both): each continues the sequence it saw, so the
    // second device's first mutation repeats the first device's number.
    const transport = new ScriptedTransport()
    const sourceDatabase = `backup-concurrent-source:${crypto.randomUUID()}`
    const restoredDatabase = `backup-concurrent-restored:${crypto.randomUUID()}`
    databaseNames.push(sourceDatabase, restoredDatabase)
    let history = [historyEntry()]
    const source = await open(transport, sourceDatabase, async () => history)
    await source.settled()
    const edited = historyEntry()
    history = [{ ...edited, content: { ...edited.content, body: { text: 'edited' }, text: 'edited' } }]
    await source.flushNow()
    await source.settled()
    source.dispose()
    openCoordinators.splice(openCoordinators.indexOf(source), 1)
    expect(transport.appendRequests).toHaveLength(2)

    const change = transport.appendRequests[1]
    await transport.appendSegment({
      ...structuredClone(change),
      operationId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      sourceDeviceId: 10,
      deviceSequence: 1,
      previousSegmentDigest: zeroDigest,
    })

    const restored = await open(transport, restoredDatabase, async () => [])
    await restored.settled()
    const restoredHistory = await restored.restoredHistoryAsync()
    expect(restoredHistory).toHaveLength(1)
    expect(restoredHistory[0].content.text).toBe('edited')
  })

  it('accepts a device continuing a record another device moved on', async () => {
    // A device numbers a change one past the record's state in its own
    // store. After it merges the account's other devices (every start does),
    // that state is the reduced one, so its next number jumps past its own
    // previous one. Rejecting that made Chat refuse to open on every device.
    const transport = new ScriptedTransport()
    const sourceDatabase = `backup-merged-source:${crypto.randomUUID()}`
    const restoredDatabase = `backup-merged-restored:${crypto.randomUUID()}`
    databaseNames.push(sourceDatabase, restoredDatabase)
    const original = historyEntry()
    let history = [original]
    const source = await open(transport, sourceDatabase, async () => history)
    await source.settled()
    for (const text of ['second', 'third', 'fourth']) {
      history = [{ ...original, content: { ...original.content, body: { text }, text } }]
      await source.flushNow()
      await source.settled()
    }
    source.dispose()
    openCoordinators.splice(openCoordinators.indexOf(source), 1)
    expect(transport.segments).toHaveLength(4)

    // The same four mutations (1, 2, 3, 4) as the server would hold them had
    // a second device made the middle two: this device wrote 1, merged the
    // other device's 2 and 3, then wrote 4.
    const [first, second, third, fourth] = transport.segments
    Object.assign(second, { sourceDeviceId: 10, deviceSequence: 1, previousSegmentDigest: zeroDigest })
    Object.assign(third, { sourceDeviceId: 10, deviceSequence: 2, previousSegmentDigest: second.ciphertextSha256 })
    Object.assign(fourth, { deviceSequence: 2, previousSegmentDigest: first.ciphertextSha256 })

    const restored = await open(transport, restoredDatabase, async () => [])
    await restored.settled()
    const restoredHistory = await restored.restoredHistoryAsync()
    expect(restoredHistory).toHaveLength(1)
    expect(restoredHistory[0].content.text).toBe('fourth')
  })

  it('rejects a mutation numbered past anything the record has reached', async () => {
    const transport = new ScriptedTransport()
    const sourceDatabase = `backup-gap-source:${crypto.randomUUID()}`
    const restoredDatabase = `backup-gap-restored:${crypto.randomUUID()}`
    databaseNames.push(sourceDatabase, restoredDatabase)
    const original = historyEntry()
    let history = [original]
    const source = await open(transport, sourceDatabase, async () => history)
    await source.settled()
    for (const text of ['second', 'third']) {
      history = [{ ...original, content: { ...original.content, body: { text }, text } }]
      await source.flushNow()
      await source.settled()
    }
    source.dispose()
    openCoordinators.splice(openCoordinators.indexOf(source), 1)
    expect(transport.segments).toHaveLength(3)

    // A second device writes mutation 3 while the record has only reached 1.
    const [, second, third] = transport.segments
    const sealed = (segment: typeof second) => ({
      operationId: segment.operationId,
      ciphertext: segment.ciphertext,
      ciphertextBytes: segment.ciphertextBytes,
      ciphertextSha256: segment.ciphertextSha256,
    })
    const [two, three] = [sealed(second), sealed(third)]
    Object.assign(second, three, { sourceDeviceId: 10, deviceSequence: 1, previousSegmentDigest: zeroDigest })
    Object.assign(third, two, { sourceDeviceId: 10, deviceSequence: 2, previousSegmentDigest: three.ciphertextSha256 })

    await expect(open(transport, restoredDatabase, async () => []))
      .rejects.toThrow('Chat backup record mutation sequence is invalid')
  })

  it('waits for routine compaction when only superseded controls were removed', async () => {
    const transport = new ScriptedTransport()
    const database = `backup-control-prune:${crypto.randomUUID()}`
    databaseNames.push(database)
    const control = {
      ...historyEntry(),
      content: { ...historyEntry().content, kind: 'readPosition', text: undefined, body: {} },
    }
    let history: ChatHistoryEntry[] = [historyEntry(), control]
    const coordinator = await open(transport, database, async () => history)
    await coordinator.settled()
    const basesBefore = transport.stagedBase
    history = [historyEntry()]
    await coordinator.flushNow()
    await coordinator.settled()
    // The tombstone was appended, but no new base was staged for it.
    expect(transport.appendRequests.length).toBeGreaterThan(1)
    expect(transport.stagedBase).toBe(basesBefore)
  })

  it('leaves compaction for the next cycle when another device keeps winning', async () => {
    const transport = new ScriptedTransport()
    const database = `backup-compaction-lost:${crypto.randomUUID()}`
    databaseNames.push(database)
    let stages = 0
    transport.stageBase = async () => {
      stages += 1
      throw Object.assign(new Error('stale base'), { response: { status: 409 } })
    }
    let history = [historyEntry()]
    const coordinator = await open(transport, database, async () => history)
    await coordinator.settled()
    history = []
    await expect(coordinator.flushNow()).resolves.toBeUndefined()
    expect(stages).toBe(3)
  })

  it('opens when the history moves under a restore, and gives up when it never settles', async () => {
    const transport = new ScriptedTransport()
    const first = `backup-moved-writer:${crypto.randomUUID()}`
    databaseNames.push(first)
    await (await open(transport, first)).settled()
    expect(transport.segments.length).toBeGreaterThan(0)

    // Another device commits (or compacts) between the reads: the page ends
    // short of the cursor reported with it, then starts past a gap.
    const list = transport.listSegments.bind(transport)
    let glitches = 2
    transport.listSegments = async (after: number) => {
      const page = await list(after)
      if (glitches === 2) { glitches--; return { ...page, segments: [], currentCursor: page.currentCursor + 1 } }
      if (glitches === 1) { glitches--; return { ...page, segments: page.segments.map(segment => ({ ...segment, cursor: segment.cursor + 1 })) } }
      return page
    }
    const status = vi.spyOn(transport, 'status')
    const second = `backup-moved-reader:${crypto.randomUUID()}`
    databaseNames.push(second)
    await expect(open(transport, second, async () => [], undefined, 10)).resolves.toBeDefined()
    expect(glitches).toBe(0)
    expect(status.mock.calls.length).toBeGreaterThanOrEqual(3)

    // A server that never settles is an integrity failure, not a retry loop.
    transport.listSegments = async (after: number) => ({ ...(await list(after)), segments: [] })
    const third = `backup-moved-never:${crypto.randomUUID()}`
    databaseNames.push(third)
    await expect(open(transport, third, async () => [], undefined, 11)).rejects.toThrow('stopped before its cursor')
  })

  it('starts its own chain when a repaired browser keeps the old device\'s bookkeeping', async () => {
    // "Repair this browser" keeps the backup database and registers a new
    // device. Continuing the old device's sequence under the new number is
    // refused by the server on every upload.
    const transport = new ScriptedTransport()
    transport.enforceDeviceChains = true
    const database = `backup-repaired:${crypto.randomUUID()}`
    databaseNames.push(database)
    let history = [historyEntry()]
    const before = await open(transport, database, async () => history, undefined, 1)
    await before.settled()
    before.dispose()
    openCoordinators.splice(openCoordinators.indexOf(before), 1)
    expect(transport.segments.map(segment => [segment.sourceDeviceId, segment.deviceSequence])).toEqual([[1, 1]])

    const edited = historyEntry()
    history = [{ ...edited, content: { ...edited.content, body: { text: 'after repair' }, text: 'after repair' } }]
    const repaired = await open(transport, database, async () => history, undefined, 2)
    await repaired.settled()
    expect(transport.segments.map(segment => [segment.sourceDeviceId, segment.deviceSequence]))
      .toEqual([[1, 1], [2, 1]])
    expect(transport.segments[1].previousSegmentDigest).toBe(zeroDigest)
    expect(repaired.view().state).toBe('protected')
  })

  it('continues the server\'s chain when a device number is given out again', async () => {
    const transport = new ScriptedTransport()
    transport.enforceDeviceChains = true
    const first = `backup-number-first:${crypto.randomUUID()}`
    const second = `backup-number-second:${crypto.randomUUID()}`
    databaseNames.push(first, second)
    const earlier = await open(transport, first, async () => [historyEntry()], undefined, 1)
    await earlier.settled()
    earlier.dispose()
    openCoordinators.splice(openCoordinators.indexOf(earlier), 1)

    // A new browser, with nothing of its own, is given number 1 again.
    const edited = historyEntry()
    const later = await open(
      transport,
      second,
      async () => [{ ...edited, content: { ...edited.content, body: { text: 'new device' }, text: 'new device' } }],
      undefined,
      1,
    )
    await later.settled()
    expect(transport.segments.map(segment => [segment.sourceDeviceId, segment.deviceSequence]))
      .toEqual([[1, 1], [1, 2]])
    expect(transport.segments[1].previousSegmentDigest).toBe(transport.segments[0].ciphertextSha256)
    expect(later.view().state).toBe('protected')
  })

  it('rejects an exact duplicate record repeated by the same device chain', async () => {
    const transport = new ScriptedTransport()
    const sourceDatabase = `backup-duplicate-source:${crypto.randomUUID()}`
    const restoredDatabase = `backup-duplicate-restored:${crypto.randomUUID()}`
    databaseNames.push(sourceDatabase, restoredDatabase)
    const source = await open(transport, sourceDatabase)
    await source.settled()
    source.dispose()
    openCoordinators.splice(openCoordinators.indexOf(source), 1)

    const first = transport.appendRequests[0]
    await transport.appendSegment({
      ...structuredClone(first),
      operationId: '88888888-8888-4888-8888-888888888888',
      deviceSequence: 2,
      previousSegmentDigest: first.ciphertextSha256,
    })

    await expect(open(transport, restoredDatabase, async () => []))
      .rejects.toThrow('Chat backup record mutation sequence is invalid')
  })

  it('reuses the exact sealed operation after an ambiguous committed response and reload', async () => {
    const transport = new ScriptedTransport()
    transport.ambiguousOnce = true
    const databaseName = `backup-coordinator:${crypto.randomUUID()}`
    databaseNames.push(databaseName)
    const first = await open(transport, databaseName)
    await first.settled()
    expect(transport.segments).toHaveLength(1)

    first.dispose()
    openCoordinators.splice(openCoordinators.indexOf(first), 1)
    const db = await openBackupStore(databaseName)
    const pending = await getAll<BackupOutboxEntry>(db, 'outbox')
    expect(pending).toHaveLength(1)
    db.close()

    const second = await open(transport, databaseName)
    await second.settled()
    expect(transport.appendRequests).toHaveLength(2)
    expect(transport.appendRequests[1]).toEqual(transport.appendRequests[0])

    const verified = await openBackupStore(databaseName)
    expect(await getAll(verified, 'outbox')).toEqual([])
    verified.close()
    expect(second.view()).toMatchObject({ state: 'protected', pendingEvents: 0 })
  })

  it('returns one promise for overlapping manual flush triggers', async () => {
    const transport = new ScriptedTransport()
    const databaseName = `backup-coordinator:${crypto.randomUUID()}`
    databaseNames.push(databaseName)
    const coordinator = await open(transport, databaseName)
    await coordinator.settled()

    const first = coordinator.flushNow()
    const second = coordinator.flushNow()
    expect(second).toBe(first)
    await first
    expect(transport.segments).toHaveLength(1)
  })

  it('does not reconcile restored protected media away before local history exists', async () => {
    const transport = new ScriptedTransport()
    const sourceDatabase = `backup-media-source:${crypto.randomUUID()}`
    const restoredDatabase = `backup-media-restored:${crypto.randomUUID()}`
    databaseNames.push(sourceDatabase, restoredDatabase)
    const source = await open(transport, sourceDatabase, async () => [mediaHistoryEntry()])
    await source.settled()
    source.dispose()
    openCoordinators.splice(openCoordinators.indexOf(source), 1)

    const restored = await open(transport, restoredDatabase, async () => [])
    await restored.settled()
    expect(await restored.restoredHistoryAsync()).toHaveLength(1)
    expect((await restored.restoredHistoryAsync())[0].content.attachment).toMatchObject({
      backupMediaId: 'b'.repeat(64),
      backupMediaReferenceId: '66666666-6666-4666-8666-666666666666',
    })
    expect(transport.reconciliationRequests).toEqual([])
  })

  it.each([
    ['lower cursor', 9, undefined],
    ['conflicting digest at the pinned generation', 10, {
      version: 1,
      backupIncarnationId: authorization.backupIncarnationId,
      suite: 1,
      protectionDomain: 1,
      generation: 2,
      previousManifestDigest: '8'.repeat(64),
      baseObjectId: '55555555-5555-4555-8555-555555555555',
      baseCiphertextBytes: 100,
      baseCiphertextSha256: 'b'.repeat(64),
      coveredCursor: 10,
      mediaReferenceSetDigest: '6'.repeat(64),
      signerAuthorizationDigest: '1'.repeat(64),
      createdAtUnix: 1_700_000_000,
      signature: 'signature',
    }],
  ] as const)('rejects server rollback: %s', async (_label, cursor, manifest) => {
    const databaseName = `backup-coordinator:${crypto.randomUUID()}`
    databaseNames.push(databaseName)
    const db = await openBackupStore(databaseName)
    await putValue(db, 'meta', {
      key: 'state',
      deviceSequence: 0,
      lastSegmentDigest: zeroDigest,
      restoredCursor: 0,
      acknowledgedEvents: 0,
      acknowledgedBytes: 0,
      lastCompactedAt: 1_700_000_000_000,
      highestGeneration: manifest ? 2 : 0,
      highestCursor: 10,
      highestManifestDigest: manifest ? 'a'.repeat(64) : zeroDigest,
    })
    db.close()
    const transport = new ScriptedTransport()
    transport.statusOverride = {
      provisioned: true,
      rootEnvelope: 'sealed-root',
      signerAuthorization: authorization,
      manifest,
      currentCursor: cursor,
      storage: storage(),
    }
    await expect(open(transport, databaseName)).rejects.toThrow('Chat backup rollback detected')
  })

  it('crosses every named durable compaction checkpoint in order', async () => {
    const transport = new ScriptedTransport()
    const databaseName = `backup-coordinator:${crypto.randomUUID()}`
    databaseNames.push(databaseName)
    let history = [historyEntry()]
    const checkpoints: string[] = []
    const coordinator = await open(
      transport,
      databaseName,
      async () => history,
      checkpoint => { checkpoints.push(checkpoint) },
    )
    await coordinator.settled()

    history = []
    await coordinator.flushNow()

    expect(checkpoints).toEqual([
      'current-base-and-tail-verified',
      'replacement-base-encrypted',
      'base-upload-acknowledged',
      'media-reconciliation-acknowledged',
      'manifest-cas-acknowledged',
      'local-generation-cursor-pin-persisted',
    ])
    expect(transport.manifest).toMatchObject({ generation: 1, coveredCursor: 2 })
    expect(transport.stagedBase?.length).toBeGreaterThan(0)
  })

  it('preserves a valid restore point across 100 deterministic crash/reopen repetitions', async () => {
    const boundaries = [
      'current-base-and-tail-verified',
      'replacement-base-encrypted',
      'base-upload-acknowledged',
      'media-reconciliation-acknowledged',
      'manifest-cas-acknowledged',
      'local-generation-cursor-pin-persisted',
    ] as const
    for (let repetition = 0; repetition < 100; repetition++) {
      const target = boundaries[(repetition * 17) % boundaries.length]
      const transport = new ScriptedTransport()
      const databaseName = `backup-crash:${repetition}:${crypto.randomUUID()}`
      databaseNames.push(databaseName)
      let history = [historyEntry()]
      const crashing = await open(
        transport,
        databaseName,
        async () => history,
        checkpoint => {
          if (checkpoint === target) throw new Error(`simulated crash at ${checkpoint}`)
        },
      )
      await crashing.settled()
      history = []
      await expect(crashing.flushNow()).rejects.toThrow(`simulated crash at ${target}`)
      crashing.dispose()
      openCoordinators.splice(openCoordinators.indexOf(crashing), 1)

      const reopened = await open(transport, databaseName, async () => history)
      await reopened.settled()
      expect(await reopened.restoredHistoryAsync()).toEqual([])
      expect(reopened.view().pendingEvents).toBe(0)
      reopened.dispose()
      openCoordinators.splice(openCoordinators.indexOf(reopened), 1)
    }
  }, 30_000)
})
