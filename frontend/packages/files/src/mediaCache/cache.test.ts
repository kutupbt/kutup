import { describe, expect, it, vi } from 'vitest'
import { PrivateCiphertextCacheV1 } from './cache'
import {
  ciphertextCacheBindingKeyV1,
  opaqueAccountScopeV1,
  type CiphertextCacheBackendV1,
  type CiphertextCacheBindingV1,
  type CiphertextCacheChunkV1,
  type CiphertextCacheEntryV1,
} from './types'

class MemoryBackend implements CiphertextCacheBackendV1 {
  readonly entries = new Map<string, CiphertextCacheEntryV1>()
  readonly chunks = new Map<string, CiphertextCacheChunkV1[]>()

  async getByBindingKey(bindingKey: string) {
    return [...this.entries.values()].find(entry => entry.bindingKey === bindingKey) ?? null
  }
  async putEntry(entry: CiphertextCacheEntryV1) {
    this.entries.set(entry.cacheId, structuredClone(entry))
  }
  async putChunk(chunk: CiphertextCacheChunkV1) {
    const chunks = this.chunks.get(chunk.cacheId) ?? []
    chunks.push({ ...chunk, bytes: chunk.bytes.slice() })
    this.chunks.set(chunk.cacheId, chunks)
  }
  async listChunks(cacheId: string) {
    return (this.chunks.get(cacheId) ?? []).map(chunk => ({ ...chunk, bytes: chunk.bytes.slice() }))
  }
  async listEntries(accountScope: string) {
    return [...this.entries.values()].filter(entry => entry.accountScope === accountScope)
  }
  async deleteEntry(cacheId: string) {
    this.entries.delete(cacheId)
    this.chunks.delete(cacheId)
  }
  async clearAccount(accountScope: string) {
    for (const entry of await this.listEntries(accountScope)) await this.deleteEntry(entry.cacheId)
  }
}

const binding = (objectId = '11111111-1111-4111-8111-111111111111', bytes = 130_000): CiphertextCacheBindingV1 => ({
  product: 'chat',
  suite: 1,
  objectId,
  ciphertextBytes: bytes,
  ciphertextSha256: objectId.startsWith('1') ? 'ab'.repeat(32) : 'cd'.repeat(32),
})

async function* source(bytes: number, fill = 7): AsyncGenerator<Uint8Array> {
  yield new Uint8Array(Math.floor(bytes / 2)).fill(fill)
  yield new Uint8Array(bytes - Math.floor(bytes / 2)).fill(fill)
}

describe('private ciphertext cache', () => {
  it('publishes ciphertext only after exact-length verification succeeds', async () => {
    const backend = new MemoryBackend()
    const cache = new PrivateCiphertextCacheV1('alice@a.test', {
      backend,
      maxBytes: 500_000,
      chunkBytes: 64 * 1024,
    })
    const verifier = vi.fn(async (chunks: AsyncIterable<Uint8Array>) => {
      let total = 0
      for await (const chunk of chunks) total += chunk.length
      expect(total).toBe(130_000)
      expect([...backend.entries.values()][0]?.state).toBe('partial')
    })
    const entry = await cache.putVerified(binding(), source(130_000), verifier)
    expect(entry).toMatchObject({ state: 'verified', chunkCount: 2, receivedBytes: 130_000 })
    expect(verifier).toHaveBeenCalledOnce()
    const restored: number[] = []
    for await (const chunk of cache.readVerified(binding())) restored.push(...chunk)
    expect(restored).toHaveLength(130_000)
    expect(new Set(restored)).toEqual(new Set([7]))
  })

  it('rolls back partial chunks after verification failure or cancellation', async () => {
    const backend = new MemoryBackend()
    const cache = new PrivateCiphertextCacheV1('alice@a.test', {
      backend,
      maxBytes: 500_000,
      chunkBytes: 64 * 1024,
    })
    await expect(cache.putVerified(binding(), source(130_000), async () => {
      throw new Error('AEAD final tag failed')
    })).rejects.toThrow('AEAD final tag failed')
    expect(backend.entries.size).toBe(0)
    expect(backend.chunks.size).toBe(0)

    const controller = new AbortController()
    async function* cancelled() {
      yield new Uint8Array(70_000)
      controller.abort()
      yield new Uint8Array(60_000)
    }
    await expect(cache.putVerified(binding(), cancelled(), async () => {}, {}, controller.signal))
      .rejects.toMatchObject({ name: 'AbortError' })
    expect(backend.entries.size).toBe(0)
  })

  it('cleans partial and expired entries on startup without crossing account scopes', async () => {
    const backend = new MemoryBackend()
    const aliceScope = await opaqueAccountScopeV1('alice@a.test')
    const bobScope = await opaqueAccountScopeV1('bob@b.test')
    const base = binding()
    const makeEntry = async (
      cacheId: string,
      accountScope: string,
      state: 'partial' | 'verified',
      expiresAtMs?: number,
    ): Promise<CiphertextCacheEntryV1> => ({
      version: 1,
      accountScope,
      cacheId,
      bindingKey: await ciphertextCacheBindingKeyV1(accountScope, base),
      ...base,
      state,
      chunkCount: 1,
      receivedBytes: base.ciphertextBytes,
      createdAtMs: 1,
      lastAccessMs: 1,
      pinned: false,
      ...(expiresAtMs === undefined ? {} : { expiresAtMs }),
    })
    await backend.putEntry(await makeEntry('alice-partial', aliceScope, 'partial'))
    // Different binding key is required by real IndexedDB's unique index.
    const expired = await makeEntry('alice-expired', aliceScope, 'verified', 9)
    expired.bindingKey = 'ef'.repeat(32)
    await backend.putEntry(expired)
    await backend.putEntry(await makeEntry('bob-partial', bobScope, 'partial'))
    const cache = new PrivateCiphertextCacheV1('alice@a.test', { backend, now: () => 10 })
    await cache.initialize()
    expect([...backend.entries.keys()]).toEqual(['bob-partial'])
  })

  it('evicts least-recently-used verified entries and preserves pinned entries', async () => {
    let now = 1
    const backend = new MemoryBackend()
    const cache = new PrivateCiphertextCacheV1('alice@a.test', {
      backend,
      maxBytes: 200_000,
      chunkBytes: 64 * 1024,
      now: () => now++,
    })
    const first = binding('11111111-1111-4111-8111-111111111111', 100_000)
    const second = binding('22222222-2222-4222-8222-222222222222', 100_000)
    const third = binding('33333333-3333-4333-8333-333333333333', 100_000)
    await cache.putVerified(first, source(100_000), async () => {}, { pinned: true })
    await cache.putVerified(second, source(100_000), async () => {})
    await cache.putVerified(third, source(100_000), async () => {})
    expect(await cache.getVerified(first)).not.toBeNull()
    expect(await cache.getVerified(second)).toBeNull()
    expect(await cache.getVerified(third)).not.toBeNull()
  })

  it('uses opaque account and exact-binding keys and purges one account', async () => {
    const backend = new MemoryBackend()
    const cache = new PrivateCiphertextCacheV1('alice@a.test', {
      backend,
      maxBytes: 500_000,
      chunkBytes: 64 * 1024,
    })
    await cache.putVerified(binding(), source(130_000), async () => {})
    const entry = [...backend.entries.values()][0]
    expect(entry.accountScope).toMatch(/^[0-9a-f]{64}$/u)
    expect(entry.accountScope).not.toContain('alice')
    expect(entry.bindingKey).toMatch(/^[0-9a-f]{64}$/u)
    expect(JSON.stringify(entry)).not.toContain('voice.webm')
    await cache.purgeAccount()
    expect(backend.entries.size).toBe(0)
    expect(backend.chunks.size).toBe(0)
  })

  it('purges an expired object by product binding without needing message metadata', async () => {
    const backend = new MemoryBackend()
    const cache = new PrivateCiphertextCacheV1('alice@a.test', {
      backend,
      maxBytes: 500_000,
      chunkBytes: 64 * 1024,
    })
    const target = binding()
    await cache.putVerified(target, source(130_000), async () => {})
    await cache.removeObject('chat', target.objectId)
    expect(await cache.getVerified(target)).toBeNull()
    expect(backend.chunks.size).toBe(0)
  })
})
