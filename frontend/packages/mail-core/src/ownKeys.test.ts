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
// The device's revision guard, in memory.
const seen = vi.hoisted(() => new Map<string, number>())
vi.mock('@kutup/crypto/revisionGuard', async (importActual) => {
  const actual = await importActual<typeof import('@kutup/crypto/revisionGuard')>()
  return {
    ...actual,
    revisionGuard: () => ({
      accept: (scope: string, id: string, revision: number) => {
        const before = seen.get(`${scope}/${id}`) ?? 0
        if (revision < before) return Promise.reject(new actual.OlderThanSeenError(scope, revision, before))
        seen.set(`${scope}/${id}`, revision)
        return Promise.resolve()
      },
    }),
  }
})
vi.mock('@kutup/session/client', () => ({ default: {} }))

import { generateMailAddressKey, MAIL_KEY_FLAGS, signMailKeyList, toBase64 } from '@kutup/crypto'
import { checkedAddresses, missingKeys, OwnKeyListRolledBack } from './keyList'

const both = MAIL_KEY_FLAGS.notCompromised | MAIL_KEY_FLAGS.notObsolete
const BINDING = crypto.randomUUID()

/** An address row as the server lists it, with its key and the list the account signed (sequence `sequence`). */
async function ownRow(masterKey: Uint8Array, address: string, sequence = 1, listed = address) {
  const master = toBase64(masterKey)
  const key = await generateMailAddressKey(master, BINDING, address)
  const list = await signMailKeyList(master, {
    address: listed,
    sequence,
    // A later list follows one before it (any hash will do here).
    ...(sequence > 1 ? { previousHash: String(sequence).repeat(64) } : {}),
    issuedAt: '2026-10-20T00:00:00Z',
    keys: [{ fingerprint: key.fingerprint, sha256Fingerprint: key.sha256Fingerprint, primary: true, flags: both }],
  })
  return {
    key,
    row: {
      id: address,
      address,
      state: 'active' as const,
      keys: [{ fingerprint: key.fingerprint, sha256Fingerprint: key.sha256Fingerprint, publicKey: key.publicKey, privateKeyEnvelope: key.envelope, primary: true, flags: both }],
      keyList: { data: list.data, signature: list.signature },
    },
  }
}

describe('the account’s own addresses, checked against its own authority', () => {
  const masterKey = crypto.getRandomValues(new Uint8Array(32))
  const session = { masterKey, userId: 'me' }

  it('names a key the account only when its public key has the signed fingerprints', async () => {
    const { row } = await ownRow(masterKey, 'ada@kutup.test')
    const [checked] = await checkedAddresses(session, [row])
    expect(checked.verifiedList?.sequence).toBe(1)
    expect(checked.keys[0].listed).toBe(true)
    expect(missingKeys(checked)).toEqual([])
    // The server swaps in a key of its own under the signed fingerprints.
    const other = await generateMailAddressKey(toBase64(crypto.getRandomValues(new Uint8Array(32))), BINDING, 'ada@kutup.test')
    const [swapped] = await checkedAddresses(session, [{ ...row, keys: [{ ...row.keys[0], publicKey: other.publicKey }] }])
    expect(swapped.keys[0].listed).toBe(false)
    expect(missingKeys(swapped).map((entry) => entry.fingerprint)).toEqual([row.keys[0].fingerprint])
  })

  it('trusts no list another account signed, nor one for another address', async () => {
    const { row } = await ownRow(crypto.getRandomValues(new Uint8Array(32)), 'bob@kutup.test')
    expect((await checkedAddresses(session, [row]))[0].verifiedList).toBeNull()
    const { row: elsewhere } = await ownRow(masterKey, 'adal2@kutup.test', 1, 'grace@kutup.test')
    const [checked] = await checkedAddresses(session, [elsewhere])
    expect(checked.verifiedList).toBeNull()
    expect(checked.keys[0].listed).toBe(false)
  })

  it('refuses a list older than one this device has seen', async () => {
    const { row: newer } = await ownRow(masterKey, 'lin@kutup.test', 3)
    await checkedAddresses(session, [newer])
    const { row: older } = await ownRow(masterKey, 'lin@kutup.test', 2)
    expect((await checkedAddresses(session, [older]))[0].verifiedList).toBeNull()
    await expect(checkedAddresses(session, [older], { strict: true })).rejects.toBeInstanceOf(OwnKeyListRolledBack)
  })
})
