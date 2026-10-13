import type { RegistrationKeys } from './index'
import type { AccountProtectionConfig } from './kdf'
import { LoadFailure, retryLoad } from './retry'
import type { KDFWorkerRequest, KDFWorkerResponse } from './workers/kdf.worker'

function bytes(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return value
  if (Array.isArray(value)) return new Uint8Array(value)
  if (typeof value === 'object' && value !== null) {
    return new Uint8Array(Object.values(value as Record<string, number>))
  }
  throw new Error('KDF worker returned malformed key bytes')
}

/**
 * One request to a new KDF worker. A worker that could not start (its script
 * not fetched) rejects with [`LoadFailure`], and [`retryLoad`] runs the
 * request again in another new worker, which has a module map of its own.
 * Inside, the worker's WASM load retries by itself (@kutup/crypto/rustWasm);
 * what the worker reports after that, a real error or a load that kept
 * failing, is not retried here, so the waits do not multiply.
 */
function runWorker(request: KDFWorkerRequest): Promise<KDFWorkerResponse> {
  return retryLoad(
    () =>
      new Promise<KDFWorkerResponse>((resolve, reject) => {
        const worker = new Worker(new URL('./workers/kdf.worker.ts', import.meta.url), { type: 'module' })
        worker.onmessage = (event: MessageEvent<KDFWorkerResponse>) => {
          worker.terminate()
          const response = event.data
          if (response.type === 'error') reject(new Error(response.message))
          else resolve(response)
        }
        // The worker reports its own errors; this is one that never started.
        worker.onerror = (event) => {
          worker.terminate()
          reject(new LoadFailure(event.message || 'KDF worker could not start'))
        }
        worker.postMessage(request)
      }),
  )
}

export async function generateRegistrationInWorker(password: string, binding: string): Promise<RegistrationKeys> {
  const response = await runWorker({ type: 'register', password, binding })
  if (response.type !== 'register') throw new Error('KDF worker returned an unexpected response')
  return response.keys
}

export async function deriveAccountProtectionInWorker(
  password: string,
  accountProtection: AccountProtectionConfig,
): Promise<{ keyEncryptionKey: Uint8Array; loginKey: Uint8Array }> {
  const response = await runWorker({ type: 'deriveKeys', password, accountProtection })
  if (response.type !== 'deriveKeys') throw new Error('KDF worker returned an unexpected response')
  return { keyEncryptionKey: bytes(response.keyEncryptionKey), loginKey: bytes(response.loginKey) }
}
