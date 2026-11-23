import { beforeEach, describe, expect, it, vi } from 'vitest'
import { testRoots } from '@kutup/crypto/accountRoots.testing'

// The crypto is kutup-crypto's (its vectors check it); what is tested here is
// which key goes where, and what reaches the server
// (docs/plans/drive-link-password.md).
const SECRET = new Uint8Array(32).fill(1)
const FRESH = new Uint8Array(32).fill(2)
vi.mock('@kutup/crypto', () => ({
  generateKey: vi.fn(() => Promise.resolve(FRESH)),
  sealPublicLinkCollectionKeyV1: vi.fn((_key: Uint8Array, linkKey: Uint8Array) => Promise.resolve(`collection-under-${linkKey[0]}`)),
  sealPublicLinkFileKeyV1: vi.fn((_key: Uint8Array, linkKey: Uint8Array) => Promise.resolve(`file-under-${linkKey[0]}`)),
}))
vi.mock('@kutup/crypto/publicLink', () => ({
  openOwnerLinkKeyV1: vi.fn(() => Promise.resolve(SECRET)),
  openOwnerLinkSecretV1: vi.fn(() => Promise.resolve({ secret: SECRET, password: 'old one' })),
  sealOwnerLinkKeyV1: vi.fn((linkKey: Uint8Array) => Promise.resolve(`owner-${linkKey[0]}`)),
  sealOwnerLinkSecretV1: vi.fn((_secret: Uint8Array, password: string) => Promise.resolve(`secret-${password}`)),
  protectLinkPasswordV1: vi.fn((_secret: Uint8Array, _password: string, linkKey: Uint8Array, context: { keyRevision: number }) =>
    Promise.resolve({ salt: 's', operations: 3, memory: 67108864, verifier: 'v', linkKeyEnvelope: `pw-${linkKey[0]}-r${context.keyRevision}` }),
  ),
  deriveLinkPasswordV1: vi.fn(() => Promise.resolve({ proof: 'proof-b64', wrapKey: new Uint8Array(32) })),
  openLinkPasswordKeyV1: vi.fn(() => Promise.resolve(FRESH)),
}))
const http = vi.hoisted(() => ({ get: vi.fn(), put: vi.fn() }))
vi.mock('@kutup/session/client', () => ({ default: http }))
vi.mock('./identity', () => ({ useDriveIdentity: vi.fn() }))

const { linkPassword, linkSecret, setLinkExpiry, setLinkPassword, LinkChanged } = await import('./linkSettings')
const { forgetLink, linkHeaders, linkKeyOf, linkPasswordFailure, unlockLink } = await import('./publicLinkPassword')

const me = { accountId: 'me', masterKey: new Uint8Array(32), roots: testRoots(0), accountRef: { server: 'kutup.dev', accountId: 'me' }, incarnationId: 'inc-me' }
const plain = { id: 'link', token: 'tok', ownerLinkKeyEnvelope: 'owner', keyRevision: 1, expiresAt: null }
const protectedLink = { ...plain, keyRevision: 2, ownerSecretEnvelope: 'sealed-secret' }
const folder = { kind: 'collection' as const, id: 'folder', key: new Uint8Array(32), epoch: 4 }

beforeEach(() => {
  http.get.mockReset()
  http.put.mockReset().mockResolvedValue({ data: {} })
})

describe('link settings, for the owner', () => {
  it("takes the URL's secret from the owner's copy", async () => {
    expect(await linkSecret(plain, me as never)).toBe(SECRET)
    expect(await linkSecret(protectedLink, me as never)).toBe(SECRET)
    expect(await linkPassword(plain, me as never)).toBe('')
    expect(await linkPassword(protectedLink, me as never)).toBe('old one')
  })

  it('a password moves the target under a new link key, sealed under the password at the next revision', async () => {
    await setLinkPassword(plain, folder, 'hunter2', me as never)
    expect(http.put).toHaveBeenCalledWith('/drive/public-links/tok/password', {
      fromKeyRevision: 1,
      keyEpoch: 4,
      targetKeyEnvelope: 'collection-under-2',
      ownerLinkKeyEnvelope: 'owner-2',
      password: {
        salt: 's',
        operations: 3,
        memory: 67108864,
        verifier: 'v',
        linkKeyEnvelope: 'pw-2-r2',
        ownerSecretEnvelope: 'secret-hunter2',
      },
    })
  })

  it('removing it puts the target back under the URL secret', async () => {
    await setLinkPassword(protectedLink, { kind: 'file', id: 'file', key: new Uint8Array(32), generation: 5 }, null, me as never)
    expect(http.put).toHaveBeenCalledWith('/drive/public-links/tok/password', {
      fromKeyRevision: 2,
      keyEpoch: 5,
      targetKeyEnvelope: 'file-under-1',
      ownerLinkKeyEnvelope: 'owner-1',
      password: null,
    })
  })

  it('a link changed since is told apart', async () => {
    http.put.mockRejectedValueOnce({ response: { status: 409 } })
    await expect(setLinkPassword(plain, folder, 'x', me as never)).rejects.toBeInstanceOf(LinkChanged)
  })

  it('sets and clears the expiry', async () => {
    await setLinkExpiry(plain, new Date('2027-01-02T20:59:59.999Z'))
    expect(http.put).toHaveBeenLastCalledWith('/drive/public-links/tok/expiry', { expiresAt: '2027-01-02T20:59:59.999Z' })
    await setLinkExpiry(plain, null)
    expect(http.put).toHaveBeenLastCalledWith('/drive/public-links/tok/expiry', { expiresAt: null })
  })
})

describe('a protected link, for its viewer', () => {
  it("names the server's refusals", () => {
    expect(linkPasswordFailure({ response: { data: { code: 'linkPassword' } } })).toBe('passwordRequired')
    expect(linkPasswordFailure({ response: { data: { code: 'linkPasswordWrong' } } })).toBe('passwordWrong')
    expect(linkPasswordFailure({ response: { data: { code: 'linkPasswordLocked' } } })).toBe('passwordLocked')
    expect(linkPasswordFailure({ response: { data: { code: 'notFound' } } })).toBeNull()
  })

  it('sends the proof once unlocked, and opens the link key with the password', async () => {
    expect(linkHeaders('tok')).toEqual({})
    http.get.mockResolvedValueOnce({ data: { linkId: 'link', salt: 's', operations: 3, memory: 67108864 } })
    await unlockLink('tok', SECRET, 'hunter2')
    expect(http.get).toHaveBeenCalledWith('/drive/public-links/tok/password')
    expect(linkHeaders('tok')).toEqual({ 'X-Kutup-Link-Proof': 'proof-b64' })
    const share = { id: 'link', ownerAccountId: 'owner', keyRevision: 2, passwordLinkKeyEnvelope: 'pw' }
    expect(await linkKeyOf('tok', share, SECRET)).toBe(FRESH)
    // An unprotected link's key is the secret itself.
    expect(await linkKeyOf('tok', { ...share, passwordLinkKeyEnvelope: undefined }, SECRET)).toBe(SECRET)
    forgetLink('tok')
    expect(linkHeaders('tok')).toEqual({})
    await expect(linkKeyOf('tok', share, SECRET)).rejects.toThrow()
  })
})
