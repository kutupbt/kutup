// @vitest-environment node
import 'fake-indexeddb/auto'
import { afterEach, describe, expect, it } from 'vitest'
import {
  acknowledgeBackupEntry,
  commitBackupQueue,
  getAll,
  loadBackupState,
  openBackupStore,
  replaceBackupMedia,
  replaceRestoredRecords,
  type BackupLocalState,
  type BackupOutboxEntry,
  type StoredBackupRecord,
} from './backup-store'

const databases: string[] = []
const zeroDigest = '0'.repeat(64)

function databaseName(label: string): string {
  const name = `backup-store-test:${label}:${crypto.randomUUID()}`
  databases.push(`${name}:continuous-backup`)
  return name
}

function state(now = 1_700_000_000_000): BackupLocalState {
  return {
    key: 'state',
    deviceSequence: 2,
    lastSegmentDigest: 'b'.repeat(64),
    restoredCursor: 0,
    acknowledgedEvents: 0,
    acknowledgedBytes: 0,
    lastCompactedAt: now,
    highestGeneration: 0,
    highestCursor: 0,
    highestManifestDigest: zeroDigest,
  }
}

function entry(sequence: number): BackupOutboxEntry {
  return {
    deviceSequence: sequence,
    operationId: `00000000-0000-4000-8000-${sequence.toString().padStart(12, '0')}`,
    previousSegmentDigest: sequence === 1 ? zeroDigest : 'a'.repeat(64),
    ciphertext: `ciphertext-${sequence}`,
    ciphertextBytes: 100 + sequence,
    ciphertextSha256: sequence === 1 ? 'a'.repeat(64) : 'b'.repeat(64),
    recordCount: sequence,
  }
}

afterEach(async () => {
  await Promise.all(databases.splice(0).map(name => new Promise<void>((resolve, reject) => {
    const request = indexedDB.deleteDatabase(name)
    request.onsuccess = () => resolve()
    request.onerror = () => reject(request.error)
  })))
})

describe('ChatBackupStore durable transactions', () => {
  it('uses the injected time when creating deterministic local state', async () => {
    const db = await openBackupStore(databaseName('clock'))
    expect(await loadBackupState(db, 123_456)).toMatchObject({
      lastCompactedAt: 123_456,
      deviceSequence: 0,
      highestManifestDigest: zeroDigest,
    })
    db.close()
  })

  it('commits records, exact outbox identity, and the chain head atomically across reopen', async () => {
    const name = databaseName('reopen')
    let db = await openBackupStore(name)
    const records: Array<StoredBackupRecord<{ value: string }>> = [{
      id: 'record-1',
      fingerprint: 'fingerprint-1',
      record: { value: 'durable' },
      local: true,
    }]
    const outbox = [entry(1), entry(2)]
    await commitBackupQueue(db, records, outbox, state())
    db.close()

    db = await openBackupStore(name)
    expect(await getAll(db, 'records')).toEqual(records)
    expect(await getAll(db, 'outbox')).toEqual(outbox)
    expect(await loadBackupState(db)).toMatchObject({
      deviceSequence: 2,
      lastSegmentDigest: 'b'.repeat(64),
    })
    db.close()
  })

  it('acknowledges only the exact entry and advances pins in the same transaction', async () => {
    const db = await openBackupStore(databaseName('ack'))
    const first = entry(1)
    const second = entry(2)
    await commitBackupQueue(db, [], [first, second], state())

    await acknowledgeBackupEntry(db, first, 7, 1_700_000_123_000, 1_700_000_000_000)

    expect(await getAll(db, 'outbox')).toEqual([second])
    expect(await loadBackupState(db)).toMatchObject({
      restoredCursor: 7,
      highestCursor: 7,
      latestProtectedAt: 1_700_000_123_000,
      acknowledgedEvents: first.recordCount,
      acknowledgedBytes: first.ciphertextBytes,
    })
    db.close()
  })

  it('publishes a restored archive with its cursor only after one replacement transaction', async () => {
    const db = await openBackupStore(databaseName('restore'))
    const oldRecord = {
      id: 'old', fingerprint: 'old', record: { value: 'old' }, local: false,
    }
    await commitBackupQueue(db, [oldRecord], [], state())
    const restored = [
      { id: 'new-1', fingerprint: 'one', record: { value: 'one' }, local: false },
      { id: 'new-2', fingerprint: 'two', record: { value: 'two' }, local: false },
    ]

    await replaceRestoredRecords(db, restored, 19, 1_700_000_000_000)

    expect(await getAll(db, 'records')).toEqual(restored)
    expect(await loadBackupState(db)).toMatchObject({ restoredCursor: 19 })
    db.close()
  })

  it('persists protected media reconciliation identity across browser reload', async () => {
    const name = databaseName('media')
    let db = await openBackupStore(name)
    const media = [{
      attachmentId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      referenceId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      mediaId: 'c'.repeat(64),
      ciphertextBytes: 4096,
      protected: true,
      needsAttention: false,
      storageFull: false,
    }]
    await replaceBackupMedia(db, media)
    db.close()

    db = await openBackupStore(name)
    expect(await getAll(db, 'media')).toEqual(media)
    db.close()
  })
})
