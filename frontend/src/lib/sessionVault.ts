// Cross-platform session persistence for the Tauri desktop / mobile shell.
//
// "Production-grade restart UX, like Nextcloud / Signal / Element":
//   • Secrets (access token, master key, private key) live in the OS
//     keychain via the Rust `keyring` crate, exposed as `vault_set` /
//     `vault_get` / `vault_delete` Tauri commands.
//       Linux   → libsecret (Secret Service: gnome-keyring / KWallet)
//       macOS   → macOS Keychain
//       Windows → Windows Credential Manager
//   • Profile (non-sensitive identity + UI state) lives alongside the
//     server URL in the Store-plugin file `kutup.dat`.
//
// On the web (`!isTauri`) this module is a no-op — the existing
// sessionStorage flow handles the tab-scoped lifetime web users expect.
//
// Degraded mode: if the keyring backend is unavailable (e.g. headless
// Linux without a Secret Service daemon), `save()` throws with a
// recognisable error code that the caller surfaces as a one-time toast.
// The user can still sign in normally for this run.

import { isTauri } from './isTauri'
import { toBase64, fromBase64 } from '../crypto'

const STORE_FILE = 'kutup.dat'
const PROFILE_KEY = 'profile'

// Keychain keys. Kept short + namespaced by the OS-side service
// (`dev.kutup.client`, see src-tauri/src/lib.rs).
const KK_ACCESS_TOKEN = 'accessToken'
const KK_MASTER_KEY = 'masterKey'
const KK_PRIVATE_KEY = 'privateKey'

export interface VaultProfile {
  userId: string
  email: string
  username: string | null
  isAdmin: boolean
  storageQuotaBytes: number
  storageUsedBytes: number
  totpEnabled: boolean
  color: string | null
  currentDeviceId: number | null
  publicKey: string // base64, public by design
}

export interface VaultSecrets {
  accessToken: string
  masterKey: Uint8Array
  privateKey: Uint8Array
}

export interface VaultPayload {
  profile: VaultProfile
  secrets: VaultSecrets
}

export class VaultUnavailableError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'VaultUnavailableError'
  }
}

// Dynamic imports keep Tauri-only modules out of the web bundle's
// critical path. We cache the store handle for the page lifetime.
let storePromise: Promise<unknown> | null = null
async function getStore(): Promise<{
  get: <T>(key: string) => Promise<T | null | undefined>
  set: (key: string, value: unknown) => Promise<void>
  delete: (key: string) => Promise<boolean>
  save: () => Promise<void>
}> {
  if (!storePromise) {
    storePromise = import('@tauri-apps/plugin-store').then(({ load }) =>
      load(STORE_FILE, { autoSave: true, defaults: {} }),
    )
  }
  return storePromise as unknown as ReturnType<typeof getStore>
}

async function invokeVault(
  cmd: 'vault_set' | 'vault_get' | 'vault_delete',
  args: { key: string; value?: string },
): Promise<unknown> {
  const { invoke } = await import('@tauri-apps/api/core')
  return invoke(cmd, args)
}

async function vaultSetSecret(key: string, value: string): Promise<void> {
  try {
    await invokeVault('vault_set', { key, value })
  } catch (e) {
    throw new VaultUnavailableError(
      typeof e === 'string' ? e : (e as Error)?.message ?? 'unknown keyring error',
    )
  }
}

async function vaultGetSecret(key: string): Promise<string | null> {
  try {
    const v = await invokeVault('vault_get', { key })
    return typeof v === 'string' ? v : null
  } catch {
    return null
  }
}

async function vaultDeleteSecret(key: string): Promise<void> {
  try {
    await invokeVault('vault_delete', { key })
  } catch {
    // best-effort
  }
}

// save persists the full session in two steps:
//   1. three keychain writes (one per secret)
//   2. one Store write for the profile
//
// If step 1 fails (no keyring daemon, user denied access), the function
// throws VaultUnavailableError and the profile is NOT written — the
// next launch's restore will see no profile and fall back to /login.
export async function save(payload: VaultPayload): Promise<void> {
  if (!isTauri) return

  await vaultSetSecret(KK_ACCESS_TOKEN, payload.secrets.accessToken)
  await vaultSetSecret(KK_MASTER_KEY, toBase64(payload.secrets.masterKey))
  await vaultSetSecret(KK_PRIVATE_KEY, toBase64(payload.secrets.privateKey))

  const store = await getStore()
  await store.set(PROFILE_KEY, payload.profile)
  await store.save()
}

// load returns null if anything is missing or unreadable. The caller
// treats null as "no vault, do the normal login flow".
export async function load(): Promise<VaultPayload | null> {
  if (!isTauri) return null

  let profile: VaultProfile | null = null
  try {
    const store = await getStore()
    const got = await store.get<VaultProfile>(PROFILE_KEY)
    if (got && typeof got === 'object') profile = got
  } catch {
    return null
  }
  if (!profile) return null

  const accessToken = await vaultGetSecret(KK_ACCESS_TOKEN)
  const masterKeyB64 = await vaultGetSecret(KK_MASTER_KEY)
  const privateKeyB64 = await vaultGetSecret(KK_PRIVATE_KEY)
  if (!accessToken || !masterKeyB64 || !privateKeyB64) return null

  let masterKey: Uint8Array
  let privateKey: Uint8Array
  try {
    masterKey = fromBase64(masterKeyB64)
    privateKey = fromBase64(privateKeyB64)
  } catch {
    return null
  }

  return {
    profile,
    secrets: { accessToken, masterKey, privateKey },
  }
}

// clear wipes both secrets and profile. Called by the logout thunk so an
// explicit "Sign out" doesn't auto-rehydrate on the next launch. We
// delete sequentially rather than via Promise.all — keyring backends
// (especially Linux's secret-service over DBus) serialize per-process
// anyway, and concurrent invokes have produced lost writes in testing.
export async function clear(): Promise<void> {
  if (!isTauri) return

  await vaultDeleteSecret(KK_ACCESS_TOKEN)
  await vaultDeleteSecret(KK_MASTER_KEY)
  await vaultDeleteSecret(KK_PRIVATE_KEY)

  try {
    const store = await getStore()
    await store.delete(PROFILE_KEY)
    await store.save()
  } catch {
    // best-effort
  }
}
