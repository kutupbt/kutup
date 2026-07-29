// Account-protection KDF bindings. All construction, labels, validation and
// policy live in the canonical Rust kutup-crypto crate; this module is only a
// browser transport adapter.

import { fromBase64 } from './base64'

const MODULE_URL = '/crypto-wasm/kutup_crypto_wasm.js'

export const ACCOUNT_PROTECTION_SUITE_V1 = 1
export const ACCOUNT_PROTECTION_DEFAULTS = Object.freeze({
  suite: ACCOUNT_PROTECTION_SUITE_V1,
  memoryKib: 64 * 1024,
  iterations: 3,
  parallelism: 1,
})

export interface AccountProtectionConfig {
  suite: number
  salt: string
  memoryKib: number
  iterations: number
  parallelism: number
}

interface AccountProtectionKeysWire {
  keyEncryptionKey: string
  loginKey: string
}

interface CryptoWasmModule {
  default(): Promise<unknown>
  deriveAccountProtectionKeys(
    password: string,
    saltBase64: string,
    suite: number,
    memoryKib: number,
    iterations: number,
    parallelism: number,
  ): AccountProtectionKeysWire
  deriveRecoveryAuthProof(recoveryEntropyBase64: string, loginEmail: string): string
}

let modulePromise: Promise<CryptoWasmModule> | null = null

async function loadCryptoWasm(): Promise<CryptoWasmModule> {
  if (!modulePromise) {
    modulePromise = (async () => {
      const module = (await import(/* @vite-ignore */ MODULE_URL)) as CryptoWasmModule
      await module.default()
      return module
    })()
  }
  return modulePromise
}

export async function deriveAccountProtectionKeys(
  password: string,
  config: AccountProtectionConfig,
): Promise<{ keyEncryptionKey: Uint8Array; loginKey: Uint8Array }> {
  const module = await loadCryptoWasm()
  const keys = module.deriveAccountProtectionKeys(
    password,
    config.salt,
    config.suite,
    config.memoryKib,
    config.iterations,
    config.parallelism,
  )
  return {
    keyEncryptionKey: fromBase64(keys.keyEncryptionKey),
    loginKey: fromBase64(keys.loginKey),
  }
}

export async function deriveRecoveryAuthProof(
  recoveryEntropyBase64: string,
  loginEmail: string,
): Promise<string> {
  const module = await loadCryptoWasm()
  return module.deriveRecoveryAuthProof(recoveryEntropyBase64, loginEmail)
}

export function generateAccountProtectionSalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(16))
}
