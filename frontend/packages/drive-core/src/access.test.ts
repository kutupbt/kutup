import { beforeEach, describe, expect, it, vi } from 'vitest'

// The crypto is not what is tested here: who gets the new key, and who is
// removed, is.
vi.mock('@kutup/crypto', () => ({
  generateKey: vi.fn(() => Promise.resolve(new Uint8Array(32))),
  sealNamedShareEnvelope: vi.fn((_key: Uint8Array, _master: Uint8Array, publicKey: string) => Promise.resolve(`sealed-to-${publicKey}`)),
  sealPublicLinkCollectionKeyV1: vi.fn(() => Promise.resolve('link-envelope')),
}))
vi.mock('@kutup/crypto/collectionEpoch', () => ({ createCollectionEpochStatement: vi.fn(() => Promise.resolve('statement')) }))
vi.mock('@kutup/crypto/collectionKeyring', () => ({ sealPreviousCollectionKey: vi.fn(() => Promise.resolve('previous')) }))
vi.mock('@kutup/crypto/driveEnvelope', () => ({
  DRIVE_ENVELOPE_PURPOSE: { collectionKey: 1, collectionName: 2 },
  sealDriveEnvelope: vi.fn(() => Promise.resolve('envelope')),
}))
vi.mock('@kutup/crypto/publicLink', () => ({ openOwnerLinkKeyV1: vi.fn(() => Promise.resolve(new Uint8Array(32))) }))
const http = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn() }))
vi.mock('@kutup/session/client', () => ({ default: http }))
vi.mock('./mutations', () => ({ useDriveMutation: vi.fn() }))

const { rotateFolder } = await import('./access')
const { MembersPendingUpgrade } = await import('./identityPins')
type FolderAccess = import('./access').FolderAccess

const folder = { id: 'folder', name: 'Shared', key: new Uint8Array(32), keyEpoch: 3, nameRevision: 1, canManage: true, epochStatementHash: 'h3' }
const me = { userId: 'me', masterKey: new Uint8Array(32), accountRef: { server: 'kutup.dev', accountId: 'me' }, incarnationId: 'inc-me' }

function member(userId: string, identitySuite: number) {
  return {
    userId,
    account: `${userId}@kutup.dev`,
    accountIncarnationId: `inc-${userId}`,
    drivePublicKey: `key-${userId}`,
    identitySuite,
    canUpload: false,
    canDelete: false,
    uploadQuotaBytes: null,
    createdAt: '2026-10-19T00:00:00Z',
  }
}

const access: FolderAccess = {
  keyEpoch: 3,
  epochStatementHash: 'h3',
  members: [member('gone', 2), member('new', 2), member('old', 1)],
  publicLinks: [],
  federatedShares: [
    {
      id: 'far',
      recipientUsername: 'far',
      recipientServer: 'other.example',
      recipientAccountId: 'acct-far',
      recipientIncarnationId: 'inc-far',
      canUpload: false,
      canDelete: false,
      uploadQuotaBytes: null,
      createdAt: '2026-10-19T00:00:00Z',
    },
  ],
}

beforeEach(() => {
  http.get.mockReset()
  http.post.mockReset()
  // The federated recipient is still on identity suite 1 too.
  http.get.mockResolvedValue({
    data: { server: 'other.example', accountId: 'acct-far', account: 'far@other.example', driveHpkePublicKey: 'key-far', accountIncarnationId: 'inc-far', identitySuite: 1 },
  })
  http.post.mockResolvedValue({ data: null })
})

const removal = { members: ['gone'], publicLinks: [], federatedShares: [] }

describe('removing someone while others are not yet upgraded', () => {
  it('stops before anything is sealed or sent, naming them', async () => {
    const error = await rotateFolder(folder as never, me as never, access, removal).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(MembersPendingUpgrade)
    expect((error as InstanceType<typeof MembersPendingUpgrade>).accounts).toEqual(['old@kutup.dev', 'far@other.example'])
    expect(http.post).not.toHaveBeenCalled()
  })

  it('removes them too once the owner confirmed, and seals to everyone else', async () => {
    await rotateFolder(folder as never, me as never, access, removal, undefined, { members: ['old'], federatedShares: ['far'] })
    const [path, body] = http.post.mock.calls[0] as [string, { members: { userId: string; namedShareEnvelope: string }[]; federatedShares: unknown[]; removed: Record<string, string[]> }]
    expect(path).toBe('/collections/folder/rotate')
    expect(body.members).toEqual([{ userId: 'new', namedShareEnvelope: 'sealed-to-key-new' }])
    expect(body.federatedShares).toEqual([])
    expect(body.removed).toEqual({ members: ['gone', 'old'], publicLinks: [], federatedShares: ['far'] })
  })
})
