export type CiphertextCacheProductV1 = 'chat' | 'drive'
export type CiphertextCacheStateV1 = 'partial' | 'verified'

export interface CiphertextCacheBindingV1 {
  product: CiphertextCacheProductV1
  suite: number
  objectId: string
  ciphertextBytes: number
  ciphertextSha256: string
}

export interface CiphertextCacheEntryV1 extends CiphertextCacheBindingV1 {
  version: 1
  accountScope: string
  cacheId: string
  bindingKey: string
  state: CiphertextCacheStateV1
  chunkCount: number
  receivedBytes: number
  createdAtMs: number
  lastAccessMs: number
  pinned: boolean
  expiresAtMs?: number
}

export interface CiphertextCacheChunkV1 {
  cacheId: string
  index: number
  bytes: Uint8Array
}

export interface CiphertextCacheBackendV1 {
  getByBindingKey(bindingKey: string): Promise<CiphertextCacheEntryV1 | null>
  putEntry(entry: CiphertextCacheEntryV1): Promise<void>
  putChunk(chunk: CiphertextCacheChunkV1): Promise<void>
  listChunks(cacheId: string): Promise<CiphertextCacheChunkV1[]>
  listEntries(accountScope: string): Promise<CiphertextCacheEntryV1[]>
  deleteEntry(cacheId: string): Promise<void>
  clearAccount(accountScope: string): Promise<void>
  close?(): void
}

export function validateCiphertextCacheBindingV1(
  binding: CiphertextCacheBindingV1,
): CiphertextCacheBindingV1 {
  if (binding.product !== 'chat' && binding.product !== 'drive') {
    throw new Error('ciphertext cache product is invalid')
  }
  if (!Number.isSafeInteger(binding.suite) || binding.suite < 1 || binding.suite > 255) {
    throw new Error('ciphertext cache suite is invalid')
  }
  if (!binding.objectId || binding.objectId.length > 256 || /[\0\r\n]/u.test(binding.objectId)) {
    throw new Error('ciphertext cache object binding is invalid')
  }
  if (!Number.isSafeInteger(binding.ciphertextBytes) || binding.ciphertextBytes < 1 ||
      binding.ciphertextBytes > 3 * 1024 * 1024 * 1024) {
    throw new Error('ciphertext cache length is invalid')
  }
  if (!/^[0-9a-f]{64}$/u.test(binding.ciphertextSha256)) {
    throw new Error('ciphertext cache digest is invalid')
  }
  return binding
}

export async function opaqueAccountScopeV1(accountId: string): Promise<string> {
  if (!accountId || accountId.length > 1024 || /[\0\r\n]/u.test(accountId)) {
    throw new Error('ciphertext cache account scope is invalid')
  }
  return digestText(`kutup/private-ciphertext-cache/account/v1\0${accountId}`)
}

export async function ciphertextCacheBindingKeyV1(
  accountScope: string,
  binding: CiphertextCacheBindingV1,
): Promise<string> {
  validateCiphertextCacheBindingV1(binding)
  if (!/^[0-9a-f]{64}$/u.test(accountScope)) {
    throw new Error('ciphertext cache account scope is invalid')
  }
  const fields = [
    'kutup/private-ciphertext-cache/binding/v1',
    accountScope,
    binding.product,
    String(binding.suite),
    binding.objectId,
    String(binding.ciphertextBytes),
    binding.ciphertextSha256,
  ]
  return digestText(fields.map(field => `${field.length}:${field}`).join('|'))
}

async function digestText(value: string): Promise<string> {
  if (!globalThis.crypto?.subtle) throw new Error('Web Crypto is unavailable')
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('')
}
