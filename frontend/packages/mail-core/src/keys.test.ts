// @vitest-environment node
import { describe, expect, it, vi } from 'vitest'
vi.mock('../../crypto/src/rustWasm', async () => {
  const [{ readFile }, module] = await Promise.all([
    import('node:fs/promises'),
    import('../../../wasm/crypto-wasm/kutup_crypto_wasm.js'),
  ])
  const wasm = await readFile(new URL('../../../wasm/crypto-wasm/kutup_crypto_wasm_bg.wasm', import.meta.url))
  await module.default({ module_or_path: wasm })
  return { getCryptoWasm: async () => module }
})
vi.mock('@kutup/session/client', () => ({ default: { get: vi.fn() } }))

import { deriveAccountIdentityKeys, generateMailAddressKey, MAIL_KEY_FLAGS, signMailKeyList, toBase64 } from '@kutup/crypto'
import { UnverifiedKeys, verified } from './keys'

/** What `GET /api/mail/keys` answers for `address` (as stored), its newest list naming `account`. */
async function lookupOf(master: string, binding: string, address: string, account: string) {
  const key = await generateMailAddressKey(master, binding, address)
  const list = await signMailKeyList(master, {
    account,
    address,
    sequence: 1,
    issuedAt: '2026-10-14T12:00:00Z',
    keys: [{ fingerprint: key.fingerprint, sha256Fingerprint: key.sha256Fingerprint, primary: true, flags: MAIL_KEY_FLAGS.notCompromised | MAIL_KEY_FLAGS.notObsolete }],
  })
  const identity = await deriveAccountIdentityKeys(master)
  return {
    address,
    account,
    accountAuthorityPublicKey: identity.authorityPublicKey,
    keys: [{ fingerprint: key.fingerprint, sha256Fingerprint: key.sha256Fingerprint, publicKey: key.publicKey, primary: true, flags: 3 }],
    keyLists: [{ data: list.data, signature: list.signature }],
  }
}

describe('an address’s keys', () => {
  const master = toBase64(crypto.getRandomValues(new Uint8Array(32)))
  const binding = crypto.randomUUID()

  it('are the current address’s, asked in any spelling', async () => {
    const lookup = await lookupOf(master, binding, 'ada_l@kutup.dev', 'ada_l@kutup.dev')
    for (const asked of ['ada_l@kutup.dev', 'ada.l@kutup.dev', 'Ada-L@Kutup.dev', 'adal@kutup.dev']) {
      const keys = await verified(asked, lookup)
      expect(keys.address).toBe('ada_l@kutup.dev')
      expect(keys.primary).toBe(lookup.keys[0].publicKey)
    }
  })

  it('are an old address’s, its list naming the account as it was called then', async () => {
    // After a rename to `ada_lovelace`, the old address still receives: its
    // list names the old account, which the server now answers with.
    const lookup = await lookupOf(master, binding, 'ada_l@kutup.dev', 'ada_l@kutup.dev')
    await expect(verified('ada.l@kutup.dev', lookup)).resolves.toMatchObject({ account: 'ada_l@kutup.dev' })
    // An answer naming another account than the list does is refused.
    await expect(verified('ada_l@kutup.dev', { ...lookup, account: 'ada_lovelace@kutup.dev' })).rejects.toBeInstanceOf(UnverifiedKeys)
  })

  it('are refused when the answer is another address', async () => {
    const lookup = await lookupOf(master, binding, 'ada_l@kutup.dev', 'ada_l@kutup.dev')
    await expect(verified('bob@kutup.dev', lookup)).rejects.toBeInstanceOf(UnverifiedKeys)
    await expect(verified('ada_l@other.dev', lookup)).rejects.toBeInstanceOf(UnverifiedKeys)
  })
})
