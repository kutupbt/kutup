// @vitest-environment node
import 'fake-indexeddb/auto'
import { afterEach, describe, expect, it, vi } from 'vitest'

vi.mock('@/crypto/accountEnvelope', () => ({
  ACCOUNT_ENVELOPE_PURPOSE: { chatBackupRoot: 4 },
  openAccountEnvelope: vi.fn(async () => new Uint8Array(32).fill(7)),
  sealAccountEnvelope: vi.fn(async () => 'sealed-root'),
}))

vi.mock('@/crypto/identity', () => ({
  deriveAccountIdentityKeys: vi.fn(async () => ({
    incarnationId: '11111111-1111-4111-8111-111111111111',
  })),
}))

const jsonBytes = (value: unknown) => new TextEncoder().encode(JSON.stringify(value))
const bytesJson = (bytes: Uint8Array) => JSON.parse(new TextDecoder().decode(bytes))
const bytesBase64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64')
const base64Bytes = (value: string) => new Uint8Array(Buffer.from(value, 'base64'))

vi.mock('@/crypto/rustWasm', () => ({
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
    }
  }

  async provision(): Promise<BackupStatusResponse> {
    throw new Error('already provisioned')
  }

  async appendSegment(request: Parameters<ChatBackupTransport['appendSegment']>[0]) {
    this.appendRequests.push(structuredClone(request))
    const existing = this.segments.find(segment => segment.operationId === request.operationId)
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
    const committed = this.segments.find(segment => segment.operationId === request.operationId)!
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
) {
  const coordinator = await ChatBackupCoordinator.open({
    databaseName,
    email: 'user@kutup.dev',
    username: 'user',
    serverName: 'kutup.dev',
    masterKey: new Uint8Array(32).fill(3),
    deviceId: 9,
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
