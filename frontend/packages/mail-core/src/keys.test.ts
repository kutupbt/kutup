// @vitest-environment node
import { describe, expect, it, vi } from 'vitest'
vi.mock('../../crypto/src/rustWasm', async () => {
  const [{ readFile }, module] = await Promise.all([
    import('node:fs/promises'),
    import('../../../wasm/crypto-wasm/kutup_crypto_wasm.js'),
  ])
  const wasm = await readFile(new URL('../../../wasm/crypto-wasm/kutup_crypto_wasm_bg.wasm', import.meta.url))
  await module.default({ module_or_path: wasm })
  return { getCryptoWasm: () => Promise.resolve(module) }
})
const get = vi.hoisted(() => vi.fn())
vi.mock('@kutup/session/client', () => ({ default: { get } }))
// What the pin list says (drive-core's own tests cover how it decides).
type Verdict = { kind: string; now?: string }
const pins: { verdict: Verdict } = vi.hoisted(() => ({ verdict: { kind: 'unknown' } }))
vi.mock('@kutup/drive-core/identityPins', () => ({ pinnedVerdict: vi.fn(() => Promise.resolve(pins.verdict)) }))
vi.mock('@kutup/drive-core/identity', () => ({ driveIdentityOf: vi.fn(() => Promise.resolve({})) }))
vi.mock('@kutup/session/store', () => ({ getSession: () => ({ username: 'me' }) }))

import { deriveAccountIdentityKeys, generateMailAddressKey, MAIL_KEY_FLAGS, signMailKeyList, toBase64 } from '@kutup/crypto'
import { addressKeys, forgetKeys, KeysIdentityChanged, UnverifiedKeys, verified } from './keys'

/** What `GET /api/mail/keys` answers for `address` (as stored), its newest list naming `listed`. */
async function lookupOf(master: string, binding: string, address: string, listed = address) {
  const key = await generateMailAddressKey(master, binding, address)
  const list = await signMailKeyList(master, {
    address: listed,
    sequence: 1,
    issuedAt: '2026-10-14T12:00:00Z',
    keys: [{ fingerprint: key.fingerprint, sha256Fingerprint: key.sha256Fingerprint, primary: true, flags: MAIL_KEY_FLAGS.notCompromised | MAIL_KEY_FLAGS.notObsolete }],
  })
  const identity = await deriveAccountIdentityKeys(master)
  return {
    address,
    server: 'kutup.dev',
    accountId: '3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70',
    accountAuthorityPublicKey: identity.authorityPublicKey,
    keys: [{ fingerprint: key.fingerprint, sha256Fingerprint: key.sha256Fingerprint, publicKey: key.publicKey, primary: true, flags: 3 }],
    keyLists: [{ data: list.data, signature: list.signature }],
  }
}

describe('an address’s keys', () => {
  const master = toBase64(crypto.getRandomValues(new Uint8Array(32)))
  const binding = crypto.randomUUID()

  it('are the current address’s, asked in any spelling', async () => {
    const lookup = await lookupOf(master, binding, 'ada_l@kutup.dev')
    for (const asked of ['ada_l@kutup.dev', 'ada.l@kutup.dev', 'Ada-L@Kutup.dev', 'adal@kutup.dev']) {
      const keys = await verified(asked, lookup)
      expect(keys.address).toBe('ada_l@kutup.dev')
      expect(keys.primary).toBe(lookup.keys[0].publicKey)
    }
  })

  it('are refused when the newest list names another address of the account', async () => {
    // After a rename to `ada_lovelace`, the old address still receives with
    // its own list: a list of the new address served for it is refused.
    const lookup = await lookupOf(master, binding, 'ada_l@kutup.dev')
    await expect(verified('ada.l@kutup.dev', lookup)).resolves.toMatchObject({ address: 'ada_l@kutup.dev' })
    const other = await lookupOf(master, binding, 'ada_l@kutup.dev', 'ada_lovelace@kutup.dev')
    await expect(verified('ada_l@kutup.dev', other)).rejects.toThrow()
  })

  it('are refused when the answer is another address', async () => {
    const lookup = await lookupOf(master, binding, 'ada_l@kutup.dev')
    await expect(verified('bob@kutup.dev', lookup)).rejects.toBeInstanceOf(UnverifiedKeys)
    await expect(verified('ada_l@other.dev', lookup)).rejects.toBeInstanceOf(UnverifiedKeys)
  })
})

describe('an address’s keys against the pin list', () => {
  const master = toBase64(crypto.getRandomValues(new Uint8Array(32)))
  const binding = crypto.randomUUID()

  async function lookedUp(verdict: { kind: string; now?: string }) {
    pins.verdict = verdict
    forgetKeys()
    const lookup = await lookupOf(master, binding, 'ada_l@kutup.dev')
    get.mockResolvedValueOnce({ data: lookup })
    return addressKeys('ada_l@kutup.dev')
  }

  it('refuses another authority for a pinned person', async () => {
    await expect(lookedUp({ kind: 'changed' })).rejects.toBeInstanceOf(KeysIdentityChanged)
  })

  it('refuses someone else at a name a pinned person left, naming where that person is', async () => {
    await expect(lookedUp({ kind: 'changed', now: 'ada_lovelace@kutup.dev' })).rejects.toMatchObject({
      now: 'ada_lovelace@kutup.dev',
    })
  })

  it('takes an old address its verified rename chain covers, and someone never met', async () => {
    await expect(lookedUp({ kind: 'renamed', now: 'ada_lovelace@kutup.dev' })).resolves.toMatchObject({ address: 'ada_l@kutup.dev' })
    await expect(lookedUp({ kind: 'pinned' })).resolves.toMatchObject({ address: 'ada_l@kutup.dev' })
    await expect(lookedUp({ kind: 'unknown' })).resolves.toMatchObject({ address: 'ada_l@kutup.dev' })
  })
})
