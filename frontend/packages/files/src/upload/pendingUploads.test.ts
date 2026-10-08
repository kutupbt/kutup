// @vitest-environment jsdom
import 'fake-indexeddb/auto'
import { describe, expect, it } from 'vitest'
import { PENDING_UPLOAD_LIFETIME_MS, pendingUploads, type PendingUpload } from './pendingUploads'

function upload(fileId: string, owner: string, startedAt: number, updatedAt = startedAt): PendingUpload {
  return {
    fileId, owner, uploadUrl: `https://drive.test/api/uploads/${fileId}`, size: 10, lastModified: 1,
    collectionId: 'c', keyEpoch: 1, fileKeyEnvelope: 'k', metadataEnvelope: 'm', prefix: 'p', startedAt, updatedAt,
  }
}

describe('pendingUploads', () => {
  it("lists one account's uploads, newest first, and forgets the server's reaped ones", async () => {
    const now = 10 * PENDING_UPLOAD_LIFETIME_MS
    await pendingUploads.put(upload('a', 'alice', now - 3000))
    await pendingUploads.put(upload('b', 'alice', now - 1000))
    await pendingUploads.put(upload('c', 'bob', now - 2000))
    await pendingUploads.put(upload('old', 'alice', now - 2 * PENDING_UPLOAD_LIFETIME_MS, now - PENDING_UPLOAD_LIFETIME_MS))
    expect((await pendingUploads.list('alice', now)).map((u) => u.fileId)).toEqual(['b', 'a'])
    expect((await pendingUploads.list('bob', now)).map((u) => u.fileId)).toEqual(['c'])

    // The reaped one is gone for good, and a finished one can be removed.
    await pendingUploads.remove('a')
    expect((await pendingUploads.list('alice', 0)).map((u) => u.fileId)).toEqual(['b'])
  })
})
