import { describe, it, expect, vi } from 'vitest'
import * as Y from 'yjs'
import { SnapshotTrigger } from './snapshot'

// Mock the api client. We can't unit-test the real network calls.
vi.mock('../api/client', () => ({ default: { post: vi.fn().mockResolvedValue({ data: { storagePath: 'p', s3VersionId: 'v' } }) } }))

describe('SnapshotTrigger', () => {
  it('does not snapshot when no updates have arrived', async () => {
    const ydoc = new Y.Doc()
    const encrypt = vi.fn()
    const t = new SnapshotTrigger({ fileId: 'f1', ydoc, encryptSnapshot: encrypt, getSeq: () => 0 })
    // forceSave with no updates and no label is a no-op
    await t.forceSave()
    expect(encrypt).not.toHaveBeenCalled()
    t.destroy()
  })

  it('forceSave with explicit label always snapshots', async () => {
    const ydoc = new Y.Doc()
    const encrypt = vi.fn().mockResolvedValue({
      ciphertext: new Uint8Array([1, 2, 3]),
      storageHints: { docKeyId: 1, sizeBytes: 3 },
    })
    const t = new SnapshotTrigger({ fileId: 'f1', ydoc, encryptSnapshot: encrypt, getSeq: () => 5 })
    await t.forceSave('checkpoint-1', true)
    expect(encrypt).toHaveBeenCalledTimes(1)
    t.destroy()
  })

  it('hard ceiling of 200 updates triggers a snapshot', async () => {
    const ydoc = new Y.Doc()
    const ytext = ydoc.getText('content')
    const encrypt = vi.fn().mockResolvedValue({
      ciphertext: new Uint8Array([1]),
      storageHints: { docKeyId: 1, sizeBytes: 1 },
    })
    const t = new SnapshotTrigger({ fileId: 'f1', ydoc, encryptSnapshot: encrypt, getSeq: () => 0 })
    // Fire 201 distinct updates.
    for (let i = 0; i < 201; i++) {
      ytext.insert(0, 'x')
    }
    // The hard-ceiling branch fires .snapshot() synchronously (no setTimeout). Wait a tick.
    await new Promise(r => setTimeout(r, 50))
    expect(encrypt).toHaveBeenCalled()
    t.destroy()
  })
})
