// KDF Web Worker — runs canonical Rust/WASM Argon2id off the main thread.
import '../polyfills'
import { generateRegistrationKeys, deriveAccountProtectionKeys } from '../crypto/index'
import type { AccountProtectionConfig } from '../crypto/kdf'

export type KDFWorkerRequest =
  | { type: 'register'; password: string; loginEmail: string }
  | { type: 'deriveKeys'; password: string; accountProtection: AccountProtectionConfig }

export type KDFWorkerResponse =
  | { type: 'register'; keys: Awaited<ReturnType<typeof generateRegistrationKeys>> }
  | { type: 'deriveKeys'; keyEncryptionKey: Uint8Array; loginKey: Uint8Array }
  | { type: 'error'; message: string }

self.onmessage = async (e: MessageEvent<KDFWorkerRequest>) => {
  // S2-10 fix: Reject messages from unexpected origins to prevent cross-origin
  // abuse (e.g. triggering expensive Argon2id from an embedded iframe).
  // e.origin is '' for same-origin dedicated worker messages in most browsers,
  // and non-empty for cross-origin postMessage — block those.
  if (e.origin !== '' && e.origin !== self.location.origin) {
    self.postMessage({ type: 'error', message: 'Unauthorized origin' } satisfies KDFWorkerResponse)
    return
  }

  try {
    const req = e.data
    if (req.type === 'register') {
      const keys = await generateRegistrationKeys(req.password, req.loginEmail)
      self.postMessage({ type: 'register', keys } satisfies KDFWorkerResponse)
    } else if (req.type === 'deriveKeys') {
      const { keyEncryptionKey, loginKey } = await deriveAccountProtectionKeys(
        req.password,
        req.accountProtection,
      )
      self.postMessage({ type: 'deriveKeys', keyEncryptionKey, loginKey } satisfies KDFWorkerResponse)
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error'
    self.postMessage({ type: 'error', message } satisfies KDFWorkerResponse)
  }
}
