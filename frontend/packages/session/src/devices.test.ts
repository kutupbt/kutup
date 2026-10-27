// @vitest-environment node
// The own-manifest pin on the publish path, with the real Rust checks: a
// server can't have this origin sign a successor of an older head, or start
// a new chain once it saw one.
import { AxiosError, AxiosHeaders } from 'axios'
import { beforeEach, describe, expect, it, vi } from 'vitest'
vi.mock('@kutup/crypto/rustWasm', async () => {
  const [{ readFile }, module] = await Promise.all([
    import('node:fs/promises'),
    import('../../../wasm/crypto-wasm/kutup_crypto_wasm.js'),
  ])
  const wasm = await readFile(new URL('../../../wasm/crypto-wasm/kutup_crypto_wasm_bg.wasm', import.meta.url))
  await module.default({ module_or_path: wasm })
  return { getCryptoWasm: async () => module }
})

import { listDeviceInManifest, type AccountManifest, type ManifestDevice } from '@kutup/crypto/accountManifest'
import { toBase64 } from '@kutup/crypto/base64'
import { generateSigningKey } from '@kutup/crypto/signing'

const ACCOUNT = 'aci:0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b@kutup.example'
const MASTER_KEY = new Uint8Array(32).fill(7)

/** What the server serves as the head; null: `404 noManifest`. */
let served: AccountManifest | null = null
vi.mock('./client', () => ({
  default: {
    get: async () => {
      if (served) return { data: served }
      throw new AxiosError('x', 'ERR', undefined, undefined, {
        status: 404,
        statusText: '',
        data: { code: 'noManifest' },
        headers: {},
        config: { headers: new AxiosHeaders() },
      })
    },
    post: async (_path: string, manifest: AccountManifest) => {
      served = manifest
      return { data: { manifest } }
    },
  },
}))
vi.mock('./store', () => ({ getSession: () => ({ masterKey: MASTER_KEY }) }))

import { publishNextManifest } from './devices'

async function editor(deviceId: number): Promise<ManifestDevice> {
  const { publicKey } = await generateSigningKey()
  return { deviceId, kind: 'editor', frameKey: toBase64(publicKey), session: 'ab'.repeat(32) }
}

/** Publishes the account's next manifest listing `entry`, as a device does. */
async function list(entry: ManifestDevice): Promise<AccountManifest | null> {
  return publishNextManifest(ACCOUNT, '1.x', (head) =>
    listDeviceInManifest(head, entry, new Date().toISOString(), toBase64(MASTER_KEY), ACCOUNT),
  )
}

/** This origin's localStorage (the node environment has none). */
const stored = new Map<string, string>()
vi.stubGlobal('localStorage', {
  getItem: (key: string) => stored.get(key) ?? null,
  setItem: (key: string, value: string) => void stored.set(key, value),
  clear: () => stored.clear(),
})

describe('publishNextManifest and the own-manifest pin', () => {
  beforeEach(() => {
    served = null
    stored.clear()
  })

  it('refuses a new chain once a head was seen', async () => {
    expect((await list(await editor(1)))?.sequence).toBe(1)
    // The server "loses" the manifest: listing again would sign a fresh
    // first manifest over the existing chain.
    served = null
    await expect(list(await editor(2))).rejects.toThrow(/no manifest/)
  })

  it('refuses an older head, and takes the current one', async () => {
    const first = await list(await editor(1))
    const second = await list(await editor(2))
    expect(second?.sequence).toBe(2)
    // Rolled back to the first (device 2 gone again): refused.
    served = first
    await expect(list(await editor(3))).rejects.toThrow(/older/)
    // The current head again: the next one follows it.
    served = second
    expect((await list(await editor(3)))?.sequence).toBe(3)
  })

  it('refuses a head that does not verify', async () => {
    const first = await list(await editor(1))
    served = { ...first!, devices: [...first!.devices, await editor(4)] }
    await expect(list(await editor(2))).rejects.toThrow()
  })
})
