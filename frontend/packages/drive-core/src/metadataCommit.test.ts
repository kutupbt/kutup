import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MetadataConflictError } from '@kutup/session/errors'
import type { FileMetadataV2 } from '@kutup/crypto'

const sealed = vi.hoisted(() => ({ opened: new Map<string, FileMetadataV2>(), seen: 0 }))

vi.mock('@kutup/crypto', () => ({
  // The metadata "sealed" as JSON at its revision: enough to see what each save sends.
  renameFileRecordV1: vi.fn((row: { metadataRevision: number }, _key: Uint8Array, metadata: FileMetadataV2) =>
    Promise.resolve({ metadataEnvelope: JSON.stringify(metadata), metadataRevision: row.metadataRevision + 1 }),
  ),
  openFileMetadataV1: vi.fn((row: { metadataEnvelope: string }) => Promise.resolve(JSON.parse(row.metadataEnvelope) as FileMetadataV2)),
}))
vi.mock('./metadataGuard', () => ({
  acceptFileMetadata: vi.fn((_fileId: string, revision: number) => {
    if (revision < sealed.seen) return Promise.reject(new Error('older than seen'))
    sealed.seen = revision
    return Promise.resolve()
  }),
}))

import { commitNextMetadata, stateCommitter, type MetadataTarget } from './metadataCommit'

const content = { revisionId: 'c1', manifestSha256: 'AAAA' }
const base: FileMetadataV2 = { name: 'notes.md', mimeType: 'text/markdown', size: 5, content, originalRevisionId: 'c1' }

function target(): MetadataTarget {
  return { fileKey: new Uint8Array(32), context: { fileId: 'f', generation: 1 }, file: { collectionId: 'c', metadataRevision: 3, metadata: base } }
}

describe("a save's next metadata", () => {
  beforeEach(() => {
    sealed.seen = 0
  })

  it('names a saved state, keeping everything else (the original upload too)', async () => {
    const t = target()
    const store = vi.fn((m: { metadataEnvelope: string; metadataRevision: number }) => Promise.resolve(m))
    const sent = await stateCommitter(t)('s1', store)
    expect(sent.metadataRevision).toBe(4)
    expect(JSON.parse(sent.metadataEnvelope)).toEqual({ ...base, stateRevisionId: 's1' })
    // The target moved on: the next save seals on top of this one.
    expect(t.file.metadataRevision).toBe(4)
    expect(t.file.metadata?.stateRevisionId).toBe('s1')
  })

  it("seals on top of someone else's metadata when theirs landed first, once", async () => {
    const t = target()
    const theirs = { ...base, name: 'renamed.md', stateRevisionId: 's0' }
    const store = vi
      .fn<(m: { metadataEnvelope: string; metadataRevision: number }) => Promise<string>>()
      .mockRejectedValueOnce(new MetadataConflictError({ metadataRevision: 6, metadataEnvelope: JSON.stringify(theirs) }))
      .mockResolvedValueOnce('stored')
    expect(await stateCommitter(t)('s1', store)).toBe('stored')
    const second = store.mock.calls[1][0]
    expect(second.metadataRevision).toBe(7)
    expect(JSON.parse(second.metadataEnvelope)).toEqual({ ...theirs, stateRevisionId: 's1' })
    // A second conflict is thrown as it came.
    store.mockReset()
    store.mockRejectedValue(new MetadataConflictError({ metadataRevision: 9, metadataEnvelope: JSON.stringify(theirs) }))
    await expect(stateCommitter(t)('s2', store)).rejects.toBeInstanceOf(MetadataConflictError)
  })

  it('reads the file again when the conflict carries no metadata, and refuses older metadata than seen', async () => {
    const t = { ...target(), reread: vi.fn(() => Promise.resolve({ metadataRevision: 5, metadataEnvelope: JSON.stringify(base), keyGeneration: 1 })) }
    const store = vi
      .fn<(m: { metadataEnvelope: string; metadataRevision: number }) => Promise<number>>()
      .mockRejectedValueOnce(new MetadataConflictError(null))
      .mockImplementation((m) => Promise.resolve(m.metadataRevision))
    expect(await commitNextMetadata(t, (m) => m, store)).toBe(6)
    sealed.seen = 10
    const stale = vi.fn().mockRejectedValueOnce(new MetadataConflictError({ metadataRevision: 5, metadataEnvelope: JSON.stringify(base) }))
    await expect(commitNextMetadata(target(), (m) => m, stale)).rejects.toThrow('older than seen')
  })

  it('throws anything else as it came, and nothing without open metadata', async () => {
    await expect(commitNextMetadata(target(), (m) => m, () => Promise.reject(new Error('offline')))).rejects.toThrow('offline')
    const closed = { ...target(), file: { collectionId: 'c', metadataRevision: 3, metadata: null } }
    await expect(commitNextMetadata(closed, (m) => m, vi.fn())).rejects.toThrow('file is not open')
  })
})
