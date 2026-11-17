// @vitest-environment jsdom
import 'fake-indexeddb/auto'
import { describe, expect, it } from 'vitest'
import { IndexedDbCiphertextCacheBackendV1 } from './mediaCache/indexedDbBackend'
import { opaqueAccountScopeV1, type CiphertextCacheEntryV1 } from './mediaCache/types'
import { forgetFilesForAccount } from './signOutCleanup'
import { pendingUploads, type PendingUpload } from './upload/pendingUploads'

function upload(fileId: string, owner: string): PendingUpload {
  return {
    fileId,
    owner,
    uploadUrl: `/api/v1/drive/uploads/${fileId}`,
    size: 1,
    lastModified: 0,
    collectionId: 'c',
    keyEpoch: 1,
    fileKeyEnvelope: 'k',
    revisionId: 'r',
    draftEnvelope: 'd',
    startedAt: Date.now(),
    updatedAt: Date.now(),
  } as PendingUpload
}

async function entry(accountId: string, cacheId: string): Promise<CiphertextCacheEntryV1> {
  return {
    version: 1,
    accountScope: await opaqueAccountScopeV1(accountId),
    cacheId,
    bindingKey: `binding-${cacheId}`,
    state: 'verified',
    chunkCount: 1,
    receivedBytes: 1,
    createdAtMs: 0,
    lastAccessMs: 0,
    pinned: false,
    product: 'drive',
    suite: 1,
    objectId: cacheId,
    ciphertextBytes: 1,
    ciphertextSha256: 'h',
  }
}

describe("a sign-out's Drive files part", () => {
  it("drops the account's interrupted uploads and cached ciphertext, and only those", async () => {
    await pendingUploads.put(upload('f1', 'A'))
    await pendingUploads.put(upload('f2', 'A'))
    await pendingUploads.put(upload('f3', 'B'))
    const cache = new IndexedDbCiphertextCacheBackendV1()
    for (const [account, id] of [['A', 'a1'], ['B', 'b1']] as const) {
      await cache.putEntry(await entry(account, id))
      await cache.putChunk({ cacheId: id, index: 0, bytes: new Uint8Array([1]) })
    }

    await forgetFilesForAccount({ accountId: 'A' })

    expect(await pendingUploads.list('A')).toEqual([])
    expect((await pendingUploads.list('B')).map((u) => u.fileId)).toEqual(['f3'])
    const after = new IndexedDbCiphertextCacheBackendV1()
    expect(await after.listEntries(await opaqueAccountScopeV1('A'))).toEqual([])
    expect(await after.listChunks('a1')).toEqual([])
    expect((await after.listEntries(await opaqueAccountScopeV1('B'))).map((e) => e.cacheId)).toEqual(['b1'])
    expect(await after.listChunks('b1')).toHaveLength(1)
  })
})
