// KDF Web Worker — runs Argon2id off the main thread.
// libsodium-sumo must be initialized separately inside the worker.
import '../polyfills'
import { generateRegistrationKeys, deriveKeyEncryptionKey, deriveLoginKey, fromBase64 } from '../crypto/index'

export type KDFWorkerRequest =
  | { type: 'register'; password: string }
  | { type: 'deriveKeys'; password: string; kdfSalt: string; loginKeySalt: string }

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
      const keys = await generateRegistrationKeys(req.password)
      self.postMessage({ type: 'register', keys } satisfies KDFWorkerResponse)
    } else if (req.type === 'deriveKeys') {
      const kdfSaltBytes = fromBase64(req.kdfSalt)
      const loginKeySaltBytes = fromBase64(req.loginKeySalt)
      const [keyEncryptionKey, loginKey] = await Promise.all([
        deriveKeyEncryptionKey(req.password, kdfSaltBytes),
        deriveLoginKey(req.password, loginKeySaltBytes),
      ])
      self.postMessage({ type: 'deriveKeys', keyEncryptionKey, loginKey } satisfies KDFWorkerResponse)
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error'
    self.postMessage({ type: 'error', message } satisfies KDFWorkerResponse)
  }
}
