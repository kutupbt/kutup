import { IndexedDbCiphertextCacheBackendV1 } from './indexedDbBackend'
import {
  ciphertextCacheBindingKeyV1,
  opaqueAccountScopeV1,
  validateCiphertextCacheBindingV1,
  type CiphertextCacheBackendV1,
  type CiphertextCacheBindingV1,
  type CiphertextCacheEntryV1,
} from './types'

const DEFAULT_MAX_BYTES = 512 * 1024 * 1024
const DEFAULT_CHUNK_BYTES = 1024 * 1024

export interface CiphertextCacheOptionsV1 {
  maxBytes?: number
  chunkBytes?: number
  now?: () => number
  backend?: CiphertextCacheBackendV1
}

export interface CiphertextCacheLifecycleV1 {
  expiresAtMs?: number
  pinned?: boolean
}

export type CiphertextCacheVerifierV1 = (
  chunks: AsyncIterable<Uint8Array>,
  binding: CiphertextCacheBindingV1,
  signal?: AbortSignal,
) => Promise<void>

export class PrivateCiphertextCacheV1 {
  private readonly backend: CiphertextCacheBackendV1
  private readonly maxBytes: number
  private readonly chunkBytes: number
  private readonly now: () => number
  private readonly openCacheIds = new Set<string>()
  private accountScope: string | null = null

  constructor(private readonly accountId: string, options: CiphertextCacheOptionsV1 = {}) {
    this.backend = options.backend ?? new IndexedDbCiphertextCacheBackendV1()
    this.maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES
    this.chunkBytes = options.chunkBytes ?? DEFAULT_CHUNK_BYTES
    this.now = options.now ?? Date.now
    if (!Number.isSafeInteger(this.maxBytes) || this.maxBytes < 1 ||
        !Number.isSafeInteger(this.chunkBytes) || this.chunkBytes < 64 * 1024 ||
        this.chunkBytes > 4 * 1024 * 1024) {
      throw new Error('ciphertext cache limits are invalid')
    }
  }

  async initialize(): Promise<void> {
    const accountScope = await this.scope()
    const now = this.now()
    const entries = await this.backend.listEntries(accountScope)
    for (const entry of entries) {
      if (entry.state === 'partial' || (entry.expiresAtMs !== undefined && entry.expiresAtMs <= now)) {
        await this.backend.deleteEntry(entry.cacheId)
      }
    }
  }

  async getVerified(binding: CiphertextCacheBindingV1): Promise<CiphertextCacheEntryV1 | null> {
    const entry = await this.entryFor(binding)
    if (!entry || entry.state !== 'verified') return null
    if (entry.expiresAtMs !== undefined && entry.expiresAtMs <= this.now()) {
      await this.backend.deleteEntry(entry.cacheId)
      return null
    }
    const touched = { ...entry, lastAccessMs: this.now() }
    await this.backend.putEntry(touched)
    return touched
  }

  async bindingKey(binding: CiphertextCacheBindingV1): Promise<string> {
    return ciphertextCacheBindingKeyV1(await this.scope(), binding)
  }

  async putVerified(
    bindingInput: CiphertextCacheBindingV1,
    ciphertext: AsyncIterable<Uint8Array>,
    verifier: CiphertextCacheVerifierV1,
    lifecycle: CiphertextCacheLifecycleV1 = {},
    signal?: AbortSignal,
  ): Promise<CiphertextCacheEntryV1> {
    const binding = validateCiphertextCacheBindingV1(bindingInput)
    throwIfAborted(signal)
    if (binding.ciphertextBytes > this.maxBytes) {
      throw new Error('ciphertext object exceeds the local cache limit')
    }
    const existing = await this.entryFor(binding)
    if (existing?.state === 'verified' &&
        (existing.expiresAtMs === undefined || existing.expiresAtMs > this.now())) {
      return existing
    }
    if (existing) await this.backend.deleteEntry(existing.cacheId)
    await this.reserve(binding.ciphertextBytes)

    const accountScope = await this.scope()
    const bindingKey = await ciphertextCacheBindingKeyV1(accountScope, binding)
    const cacheId = crypto.randomUUID()
    const createdAtMs = this.now()
    let entry: CiphertextCacheEntryV1 = {
      version: 1,
      accountScope,
      cacheId,
      bindingKey,
      ...binding,
      state: 'partial',
      chunkCount: 0,
      receivedBytes: 0,
      createdAtMs,
      lastAccessMs: createdAtMs,
      pinned: lifecycle.pinned ?? false,
      ...(lifecycle.expiresAtMs === undefined ? {} : { expiresAtMs: lifecycle.expiresAtMs }),
    }
    await this.backend.putEntry(entry)
    try {
      let pending: Uint8Array<ArrayBufferLike> = new Uint8Array()
      for await (const input of ciphertext) {
        throwIfAborted(signal)
        if (!(input instanceof Uint8Array) || input.length === 0) continue
        pending = appendBytes(pending, input)
        while (pending.length >= this.chunkBytes) {
          const chunk = pending.slice(0, this.chunkBytes)
          pending = pending.slice(this.chunkBytes)
          entry = await this.append(entry, chunk)
        }
      }
      if (pending.length) entry = await this.append(entry, pending)
      if (entry.receivedBytes !== binding.ciphertextBytes) {
        throw new Error('ciphertext cache object length differs from its binding')
      }
      await verifier(this.readChunks(cacheId), binding, signal)
      throwIfAborted(signal)
      entry = { ...entry, state: 'verified', lastAccessMs: this.now() }
      await this.backend.putEntry(entry)
      return entry
    } catch (error) {
      await this.backend.deleteEntry(cacheId).catch(() => undefined)
      throw error
    }
  }

  async *readVerified(
    binding: CiphertextCacheBindingV1,
    signal?: AbortSignal,
  ): AsyncGenerator<Uint8Array, void, void> {
    const entry = await this.getVerified(binding)
    if (!entry) throw new Error('ciphertext object is not available in Kutup')
    this.openCacheIds.add(entry.cacheId)
    try {
      for await (const chunk of this.readChunks(entry.cacheId)) {
        throwIfAborted(signal)
        yield chunk
      }
    } finally {
      this.openCacheIds.delete(entry.cacheId)
    }
  }

  async remove(binding: CiphertextCacheBindingV1): Promise<void> {
    const entry = await this.entryFor(binding)
    if (entry) await this.backend.deleteEntry(entry.cacheId)
  }

  async removeObject(product: 'chat' | 'drive', objectId: string): Promise<void> {
    if (!objectId || objectId.length > 256 || /[\0\r\n]/u.test(objectId)) return
    const entries = await this.backend.listEntries(await this.scope())
    for (const entry of entries) {
      if (entry.product === product && entry.objectId === objectId) {
        await this.backend.deleteEntry(entry.cacheId)
      }
    }
  }

  async purgeAccount(): Promise<void> {
    const scope = await this.scope()
    this.openCacheIds.clear()
    await this.backend.clearAccount(scope)
  }

  close(): void {
    this.openCacheIds.clear()
    this.backend.close?.()
  }

  private async append(
    entry: CiphertextCacheEntryV1,
    bytes: Uint8Array,
  ): Promise<CiphertextCacheEntryV1> {
    if (entry.receivedBytes + bytes.length > entry.ciphertextBytes) {
      throw new Error('ciphertext cache object exceeds its bound length')
    }
    await this.backend.putChunk({ cacheId: entry.cacheId, index: entry.chunkCount, bytes })
    const updated = {
      ...entry,
      chunkCount: entry.chunkCount + 1,
      receivedBytes: entry.receivedBytes + bytes.length,
    }
    await this.backend.putEntry(updated)
    return updated
  }

  private async *readChunks(cacheId: string): AsyncGenerator<Uint8Array, void, void> {
    const chunks = await this.backend.listChunks(cacheId)
    for (let index = 0; index < chunks.length; index += 1) {
      const chunk = chunks[index]
      if (chunk.index !== index || chunk.cacheId !== cacheId) {
        throw new Error('ciphertext cache chunks are missing or reordered')
      }
      yield chunk.bytes.slice()
    }
  }

  private async entryFor(binding: CiphertextCacheBindingV1): Promise<CiphertextCacheEntryV1 | null> {
    const scope = await this.scope()
    const key = await ciphertextCacheBindingKeyV1(scope, binding)
    return this.backend.getByBindingKey(key)
  }

  private async reserve(requiredBytes: number): Promise<void> {
    const entries = await this.backend.listEntries(await this.scope())
    let used = entries.reduce(
      (total, entry) => total + (entry.state === 'verified' ? entry.ciphertextBytes : 0),
      0,
    )
    if (used + requiredBytes <= this.maxBytes) return
    const candidates = entries
      .filter(entry => entry.state === 'verified' && !entry.pinned && !this.openCacheIds.has(entry.cacheId))
      .sort((left, right) => left.lastAccessMs - right.lastAccessMs)
    for (const candidate of candidates) {
      await this.backend.deleteEntry(candidate.cacheId)
      used -= candidate.ciphertextBytes
      if (used + requiredBytes <= this.maxBytes) return
    }
    throw new Error('local ciphertext cache has no evictable capacity')
  }

  private async scope(): Promise<string> {
    this.accountScope ??= await opaqueAccountScopeV1(this.accountId)
    return this.accountScope
  }
}

function appendBytes(left: Uint8Array, right: Uint8Array): Uint8Array {
  if (left.length === 0) return right.slice()
  const joined = new Uint8Array(left.length + right.length)
  joined.set(left)
  joined.set(right, left.length)
  return joined
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new DOMException('ciphertext cache operation aborted', 'AbortError')
}
