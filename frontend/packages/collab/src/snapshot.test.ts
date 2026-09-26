import { describe, it, expect, vi } from 'vitest'
import * as Y from 'yjs'
import { SnapshotTrigger } from './snapshot'
import { QuotaExceededError } from '@kutup/session/errors'

// Mock the version API — the typed wrappers SnapshotTrigger uses.
// Default: storing succeeds; the file has no versions yet. Tests override per-case.
const recordSnapshotMock = vi.fn().mockResolvedValue({ id: 'v1' })
const listVersionsMock = vi.fn().mockResolvedValue([])
const patchVersionMock = vi.fn().mockResolvedValue({})
vi.mock('./api', () => ({
  createVersion: (...args: unknown[]) => recordSnapshotMock(...args),
  listVersions: (...args: unknown[]) => listVersionsMock(...args),
  patchVersion: (...args: unknown[]) => patchVersionMock(...args),
}))

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

  it('forceSave on QuotaExceededError calls onError + disarms the trigger', async () => {
    const ydoc = new Y.Doc()
    const encrypt = vi.fn().mockResolvedValue({
      ciphertext: new Uint8Array([1, 2, 3]),
      storageHints: { docKeyId: 1, sizeBytes: 3 },
    })
    const onError = vi.fn()

    // First call to recordSnapshot: 413. Subsequent calls would succeed,
    // but the trigger should disarm after the 413 and never call again.
    recordSnapshotMock.mockReset()
    recordSnapshotMock.mockRejectedValueOnce(new QuotaExceededError())

    const t = new SnapshotTrigger({
      fileId: 'f1', ydoc,
      encryptSnapshot: encrypt,
      getSeq: () => 0,
      onError,
    })
    await t.forceSave('checkpoint-1', false)
    expect(onError).toHaveBeenCalledTimes(1)
    expect(onError.mock.calls[0][0]).toBeInstanceOf(QuotaExceededError)

    // Subsequent edits must NOT trigger another autosave attempt.
    encrypt.mockClear()
    const ytext = ydoc.getText('c')
    ytext.insert(0, 'x')
    // Wait > IDLE_MS would time out the test; instead we inspect that no
    // setTimeout-driven call has fired by checking the encrypt mock and
    // recordSnapshot mock — if disarmed, both stay clean.
    await new Promise(r => setTimeout(r, 100))
    expect(recordSnapshotMock).toHaveBeenCalledTimes(1) // still just the 413 call
    t.destroy()
  })

  it('forceSave re-throws non-413 errors', async () => {
    const ydoc = new Y.Doc()
    const encrypt = vi.fn().mockResolvedValue({
      ciphertext: new Uint8Array([1, 2, 3]),
      storageHints: { docKeyId: 1, sizeBytes: 3 },
    })
    const onError = vi.fn()

    recordSnapshotMock.mockReset()
    recordSnapshotMock.mockRejectedValueOnce(new Error('boom'))

    const t = new SnapshotTrigger({
      fileId: 'f1', ydoc,
      encryptSnapshot: encrypt,
      getSeq: () => 0,
      onError,
    })
    await expect(t.forceSave('checkpoint-1', false)).rejects.toThrow('boom')
    expect(onError).toHaveBeenCalledTimes(1)
    t.destroy()
  })

  it('naming unchanged content names the latest version instead of storing a copy', async () => {
    const ydoc = new Y.Doc()
    const encrypt = vi.fn()
    const onSnapshot = vi.fn()
    listVersionsMock.mockResolvedValueOnce([{ id: 'latest' }, { id: 'older' }])
    patchVersionMock.mockClear()
    const t = new SnapshotTrigger({ fileId: 'f1', ydoc, encryptSnapshot: encrypt, getSeq: () => 0, onSnapshot })
    await t.forceSave('Milestone', true)
    expect(encrypt).not.toHaveBeenCalled()
    // Here (no base): the local routes.
    expect(patchVersionMock).toHaveBeenCalledWith('f1', 'latest', { label: 'Milestone', keepForever: true }, undefined)
    expect(onSnapshot).toHaveBeenCalledWith('latest', true)
    t.destroy()
  })

  it('stores each version with its kind and sequence in one request', async () => {
    const ydoc = new Y.Doc()
    const encrypt = vi.fn().mockResolvedValue({ ciphertext: new Uint8Array([9]), storageHints: { docKeyId: 4, sizeBytes: 1 } })
    recordSnapshotMock.mockReset()
    recordSnapshotMock.mockResolvedValue({ id: 'v9' })
    const t = new SnapshotTrigger({ fileId: 'f1', ydoc, encryptSnapshot: encrypt, getSeq: () => 12 })
    ydoc.getText('content').insert(0, 'hello')
    await t.forceSave()
    expect(recordSnapshotMock).toHaveBeenCalledWith('f1', new Uint8Array([9]), {
      kind: 'yjs', seqAtSnapshot: 12, docKeyId: 4, label: null, keepForever: false,
    }, undefined)
    t.destroy()
  })

  it('saves a file on another server through its route here', async () => {
    const ydoc = new Y.Doc()
    const encrypt = vi.fn().mockResolvedValue({ ciphertext: new Uint8Array([7]), storageHints: { docKeyId: 1, sizeBytes: 1 } })
    recordSnapshotMock.mockReset()
    recordSnapshotMock.mockResolvedValue({ id: 'v1' })
    const base = '/drive/federation/file-shares/s1'
    const t = new SnapshotTrigger({ fileId: 'f1', base, ydoc, encryptSnapshot: encrypt, getSeq: () => 3 })
    ydoc.getText('content').insert(0, 'x')
    await t.forceSave()
    expect(recordSnapshotMock).toHaveBeenCalledWith('f1', new Uint8Array([7]), expect.objectContaining({ seqAtSnapshot: 3 }), base)
    t.destroy()
  })
})
