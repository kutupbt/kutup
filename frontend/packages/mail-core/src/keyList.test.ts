import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { MailKeyListInput, SignedMailKeyList } from '@kutup/crypto'

const signed: MailKeyListInput[] = []
const put = vi.fn((_url: string, _body: unknown) => Promise.resolve({ data: null }))
// Lists the account signed, by their data: what verifying a row's list gives.
const verified = new Map<string, SignedMailKeyList>()
vi.mock('@kutup/crypto', () => ({
  MAIL_KEY_FLAGS: { notCompromised: 1, notObsolete: 2, emailNoEncrypt: 4, emailNoSign: 8 },
  toBase64: () => 'master',
  foldAddress: (address: string) => Promise.resolve(address.toLowerCase()),
  // Rows here carry no real public keys: none is listed (settling needs only the signed list).
  inspectMailAddressPublicKey: () => Promise.reject(new Error('not a key')),
  deriveAccountIdentityKeys: () => Promise.resolve({ authorityPublicKey: 'authority' }),
  verifyMailKeyList: (list: { data: string }) => {
    const found = verified.get(list.data)
    return found ? Promise.resolve(found) : Promise.reject(new Error('not signed by this account'))
  },
  signMailKeyList: (_master: string, input: MailKeyListInput) => {
    signed.push(input)
    return Promise.resolve({ ...input, data: 'data', signature: 'signature', hash: 'next' })
  },
}))
vi.mock('@kutup/crypto/revisionGuard', () => ({
  OlderThanSeenError: class extends Error {},
  revisionGuard: () => ({ accept: () => Promise.resolve() }),
}))
vi.mock('@kutup/session/client', () => ({ default: { put: (url: string, body: unknown) => put(url, body) } }))

const { encryptionOff, encryptionOffList, KeyListNotSigned, nextKeyList, settleOwedKeyLists, signedEntries, unlistedKeys, withEncryptionOff } =
  await import('./keyList')

const both = 3
const noEncrypt = 4
const a = { fingerprint: 'aa', sha256Fingerprint: '01', primary: true, flags: both }
const b = { fingerprint: 'bb', sha256Fingerprint: '02', primary: false, flags: both }
const listOf = (keys: (typeof a)[], data = 'data'): SignedMailKeyList => ({
  address: 'alice@kutup.test',
  sequence: 4,
  previousHash: 'before',
  issuedAt: '2026-10-20T00:00:00Z',
  keys,
  data,
  signature: 'signature',
  hash: 'current',
})
const list = listOf([a, b])
const session = { masterKey: new Uint8Array(32), userId: 'me' }
const row = (key: typeof a & { forwarding?: boolean }) => ({ ...key, id: key.fingerprint, publicKey: '', privateKeyEnvelope: '', createdAt: '' })

beforeEach(() => {
  signed.length = 0
  put.mockClear()
  verified.clear()
})

describe('the next key list', () => {
  it('is built from the signed list, never from the server rows', async () => {
    // The server adds a key of its own as primary, and flips a flag.
    const injected = { fingerprint: 'cc', sha256Fingerprint: '03', primary: true, flags: both }
    const address = { address: list.address, keys: [{ ...a, primary: false }, { ...b, flags: 7 }, injected], verifiedList: list }
    expect(signedEntries(address)).toEqual([a, b])
    expect(unlistedKeys(address)).toEqual([injected])
    await nextKeyList(session, address, signedEntries(address))
    expect(signed.at(-1)).toMatchObject({ sequence: 5, previousHash: 'current', keys: [a, b] })
  })

  it('reports a key listed under another SHA-256 fingerprint, but never a forwarding key', () => {
    const address = { keys: [a, { ...b, sha256Fingerprint: 'ff' }, { fingerprint: 'dd', sha256Fingerprint: '04', primary: false, flags: both, forwarding: true }], verifiedList: list }
    expect(unlistedKeys(address).map((key) => key.fingerprint)).toEqual(['bb'])
  })

  it('needs a list this account signed', async () => {
    const address = { keys: [a], verifiedList: null }
    expect(() => signedEntries(address)).toThrow(KeyListNotSigned)
    await expect(nextKeyList(session, address, [a])).rejects.toThrow(KeyListNotSigned)
  })
})

describe('key lists and forwarding (docs/plans/mail-forwarding.md)', () => {
  it('reads encryption as off only from the signed list', () => {
    expect(encryptionOff({ verifiedList: list })).toBe(false)
    expect(encryptionOff({ verifiedList: listOf([{ ...a, flags: both | noEncrypt }]) })).toBe(true)
    expect(encryptionOff({ verifiedList: null })).toBe(false)
  })

  it('sets and clears the flag on every key, the rest unchanged', () => {
    const entries = [a, { ...b, flags: 1 }]
    const off = withEncryptionOff(entries, true)
    expect(off.every((entry) => entry.flags & noEncrypt)).toBe(true)
    expect(off[1].flags & 2).toBe(0)
    expect(withEncryptionOff(off, false)).toEqual(entries)
  })

  it('turns encryption off on the signed keys only', async () => {
    const injected = { fingerprint: 'cc', sha256Fingerprint: '03', primary: true, flags: both }
    await encryptionOffList(session, { verifiedList: list, keys: [a, b, injected] } as never)
    expect(signed.at(-1)!.keys).toEqual(withEncryptionOff([a, b], true))
  })

  it('keeps encryption off in every next list while the signed list says so', async () => {
    const off = listOf(withEncryptionOff([a, b], true))
    await nextKeyList(session, { verifiedList: off }, signedEntries({ verifiedList: off }))
    expect(signed.at(-1)!.keys.every((key) => key.flags & noEncrypt)).toBe(true)
  })
})

describe('settling owed key lists without a click', () => {
  const address = (keys: ReturnType<typeof row>[], current: SignedMailKeyList) => {
    verified.set(current.data, current)
    return { id: 'address', address: current.address, state: 'active' as const, keys, keyList: { data: current.data, signature: 'signature' }, keyListOwed: true }
  }

  it('signs only the flag, over the signed keys, never a key the server added', async () => {
    const off = listOf(withEncryptionOff([a, b], true), 'off')
    const injected = { fingerprint: 'cc', sha256Fingerprint: '03', primary: true, flags: both }
    expect(await settleOwedKeyLists(session, [address([row({ ...a, primary: false }), row(b), row(injected)], off)])).toBe(true)
    expect(signed).toHaveLength(1)
    expect(signed[0].keys).toEqual([a, b])
    expect(put).toHaveBeenCalledTimes(1)
  })

  it('signs nothing when the signed list has encryption on, whatever the server rows say', async () => {
    // The server flips EMAIL_NO_ENCRYPT on its rows and says a list is owed.
    expect(await settleOwedKeyLists(session, [address([row({ ...a, flags: both | noEncrypt }), row(b)], list)])).toBe(false)
    expect(signed).toHaveLength(0)
    expect(put).not.toHaveBeenCalled()
  })

  it('signs nothing over a list this account did not sign', async () => {
    const row0 = { id: 'address', address: list.address, state: 'active' as const, keys: [row(a)], keyList: { data: 'forged', signature: 'x' }, keyListOwed: true }
    expect(await settleOwedKeyLists(session, [row0])).toBe(false)
    expect(signed).toHaveLength(0)
  })
})
