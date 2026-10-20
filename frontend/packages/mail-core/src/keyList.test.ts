import { describe, expect, it, vi } from 'vitest'
import type { MailKeyListInput, SignedMailKeyList } from '@kutup/crypto'

const signed: MailKeyListInput[] = []
vi.mock('@kutup/crypto', () => ({
  toBase64: () => 'master',
  signMailKeyList: (_master: string, input: MailKeyListInput) => {
    signed.push(input)
    return Promise.resolve({ ...input, data: 'data', signature: 'signature', hash: 'next' })
  },
}))

const { KeyListNotSigned, nextKeyList, signedEntries, unlistedKeys } = await import('./keyList')

const a = { fingerprint: 'aa', sha256Fingerprint: '01', primary: true, flags: 3 }
const b = { fingerprint: 'bb', sha256Fingerprint: '02', primary: false, flags: 3 }
const list: SignedMailKeyList = {
  address: 'alice@kutup.test',
  sequence: 4,
  previousHash: 'before',
  issuedAt: '2026-10-20T00:00:00Z',
  keys: [a, b],
  data: 'data',
  signature: 'signature',
  hash: 'current',
}
const session = { masterKey: new Uint8Array(32) }

describe('the next key list', () => {
  it('is built from the signed list, never from the server rows', async () => {
    // The server adds a key of its own as primary, and flips a flag.
    const injected = { fingerprint: 'cc', sha256Fingerprint: '03', primary: true, flags: 3 }
    const address = { address: list.address, keys: [{ ...a, primary: false }, { ...b, flags: 7 }, injected], verifiedList: list }
    expect(signedEntries(address)).toEqual([a, b])
    expect(unlistedKeys(address)).toEqual([injected])
    await nextKeyList(session, address, signedEntries(address))
    expect(signed.at(-1)).toMatchObject({ sequence: 5, previousHash: 'current', keys: [a, b] })
  })

  it('reports a key listed under another SHA-256 fingerprint', () => {
    const address = { keys: [a, { ...b, sha256Fingerprint: 'ff' }], verifiedList: list }
    expect(unlistedKeys(address).map((key) => key.fingerprint)).toEqual(['bb'])
  })

  it('needs a list this account signed', async () => {
    const address = { keys: [a], verifiedList: null }
    expect(() => signedEntries(address)).toThrow(KeyListNotSigned)
    await expect(nextKeyList(session, address, [a])).rejects.toThrow(KeyListNotSigned)
  })
})
