import { describe, it, expect, beforeEach, vi } from 'vitest'

// In-test stand-ins for the OS keychain (Map) and the Store plugin (Map).
const keychain = new Map<string, string>()
const storeMap = new Map<string, unknown>()

// Toggle: if true, vault_set throws like a missing Secret Service daemon.
let keyringBroken = false

const invokeMock = vi.fn(async (cmd: string, args: { key: string; value?: string }) => {
  if (cmd === 'vault_set') {
    if (keyringBroken) throw 'platform failure: no keyring backend'
    keychain.set(args.key, args.value as string)
    return
  }
  if (cmd === 'vault_get') {
    return keychain.get(args.key) ?? null
  }
  if (cmd === 'vault_delete') {
    keychain.delete(args.key)
    return
  }
  throw new Error('unexpected invoke: ' + cmd)
})

vi.mock('@tauri-apps/api/core', () => ({
  invoke: (cmd: string, args: { key: string; value?: string }) =>
    invokeMock(cmd, args),
}))

vi.mock('@tauri-apps/plugin-store', () => ({
  load: async (_file: string) => ({
    get: async (k: string) => storeMap.get(k) ?? null,
    set: async (k: string, v: unknown) => {
      storeMap.set(k, v)
    },
    delete: async (k: string) => storeMap.delete(k),
    save: async () => {},
  }),
}))

const isTauriMock = vi.hoisted(() => ({ value: true }))
vi.mock('./isTauri', () => ({
  get isTauri() {
    return isTauriMock.value
  },
}))

async function loadFreshModule() {
  vi.resetModules()
  return await import('./sessionVault')
}

const profile = {
  userId: 'u1',
  email: 'a@b.c',
  username: 'alice',
  isAdmin: false,
  storageQuotaBytes: 1024,
  storageUsedBytes: 0,
  totpEnabled: false,
  color: null,
  currentDeviceId: null,
  publicKey: 'cHVibGlj',
}

const secrets = {
  accessToken: 'jwt-token-xyz',
  masterKey: new Uint8Array([1, 2, 3, 4, 5]),
  privateKey: new Uint8Array([9, 8, 7, 6, 5, 4]),
}

describe('sessionVault', () => {
  beforeEach(() => {
    keychain.clear()
    storeMap.clear()
    invokeMock.mockClear()
    keyringBroken = false
    isTauriMock.value = true
  })

  it('save → load round-trips profile + secrets byte-exact', async () => {
    const vault = await loadFreshModule()
    await vault.save({ profile, secrets })
    const got = await vault.load()
    expect(got).not.toBeNull()
    expect(got!.profile).toEqual(profile)
    expect(got!.secrets.accessToken).toBe(secrets.accessToken)
    expect(Array.from(got!.secrets.masterKey)).toEqual(
      Array.from(secrets.masterKey),
    )
    expect(Array.from(got!.secrets.privateKey)).toEqual(
      Array.from(secrets.privateKey),
    )
  })

  it('clear wipes both secrets and profile', async () => {
    const vault = await loadFreshModule()
    await vault.save({ profile, secrets })
    expect(keychain.size).toBe(3)
    await vault.clear()
    expect(await vault.load()).toBeNull()
    expect(keychain.size).toBe(0)
    expect(storeMap.get('profile')).toBeUndefined()
  })

  it('load returns null if profile is missing', async () => {
    const vault = await loadFreshModule()
    // secrets present, profile not — partial vault should be treated as
    // "no vault" rather than reconstruct a half-session.
    keychain.set('accessToken', 'x')
    keychain.set('masterKey', 'AQ==')
    keychain.set('privateKey', 'AQ==')
    expect(await vault.load()).toBeNull()
  })

  it('load returns null if any secret is missing', async () => {
    const vault = await loadFreshModule()
    storeMap.set('profile', profile)
    keychain.set('accessToken', 'x')
    // masterKey + privateKey deliberately missing
    expect(await vault.load()).toBeNull()
  })

  it('save throws VaultUnavailableError when keyring is broken', async () => {
    keyringBroken = true
    const vault = await loadFreshModule()
    await expect(vault.save({ profile, secrets })).rejects.toThrow(
      vault.VaultUnavailableError,
    )
    // Profile must NOT be written if the secrets failed — we never want a
    // partial vault left around.
    expect(storeMap.get('profile')).toBeUndefined()
  })

  it('is a no-op outside Tauri (save / load / clear)', async () => {
    isTauriMock.value = false
    const vault = await loadFreshModule()
    await vault.save({ profile, secrets })
    expect(await vault.load()).toBeNull()
    expect(invokeMock).not.toHaveBeenCalled()
    expect(keychain.size).toBe(0)
    expect(storeMap.size).toBe(0)
  })
})
