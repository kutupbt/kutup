import { PrivateCiphertextCacheV1 } from './cache'

const accountCaches = new Map<string, PrivateCiphertextCacheV1>()

export function privateCiphertextCacheForAccountV1(accountId: string): PrivateCiphertextCacheV1 {
  if (!accountId) throw new Error('ciphertext cache requires an account id')
  let cache = accountCaches.get(accountId)
  if (!cache) {
    cache = new PrivateCiphertextCacheV1(accountId)
    accountCaches.set(accountId, cache)
  }
  return cache
}

export async function purgePrivateCiphertextCacheForAccountV1(accountId: string): Promise<void> {
  if (!accountId) return
  const cache = accountCaches.get(accountId) ?? new PrivateCiphertextCacheV1(accountId)
  try {
    await cache.purgeAccount()
  } finally {
    cache.close()
    accountCaches.delete(accountId)
  }
}
