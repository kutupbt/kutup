import type { RegistrationKeys } from './index'
import type { AccountProtectionConfig } from './kdf'

function bytes(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return value
  if (Array.isArray(value)) return new Uint8Array(value)
  if (typeof value === 'object' && value !== null) {
    return new Uint8Array(Object.values(value as Record<string, number>))
  }
  throw new Error('KDF worker returned malformed key bytes')
}

export function generateRegistrationInWorker(
  password: string,
  loginEmail: string,
): Promise<RegistrationKeys> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('../workers/kdf.worker.ts', import.meta.url), { type: 'module' })
    worker.onmessage = (event) => {
      worker.terminate()
      if (event.data.type === 'error') reject(new Error(event.data.message))
      else if (event.data.type === 'register') resolve(event.data.keys as RegistrationKeys)
      else reject(new Error('KDF worker returned an unexpected response'))
    }
    worker.onerror = (event) => { worker.terminate(); reject(new Error(event.message)) }
    worker.postMessage({ type: 'register', password, loginEmail })
  })
}

export function deriveAccountProtectionInWorker(
  password: string,
  accountProtection: AccountProtectionConfig,
): Promise<{ keyEncryptionKey: Uint8Array; loginKey: Uint8Array }> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('../workers/kdf.worker.ts', import.meta.url), { type: 'module' })
    worker.onmessage = (event) => {
      worker.terminate()
      if (event.data.type === 'error') reject(new Error(event.data.message))
      else if (event.data.type === 'deriveKeys') {
        resolve({
          keyEncryptionKey: bytes(event.data.keyEncryptionKey),
          loginKey: bytes(event.data.loginKey),
        })
      } else reject(new Error('KDF worker returned an unexpected response'))
    }
    worker.onerror = (event) => { worker.terminate(); reject(new Error(event.message)) }
    worker.postMessage({ type: 'deriveKeys', password, accountProtection })
  })
}

