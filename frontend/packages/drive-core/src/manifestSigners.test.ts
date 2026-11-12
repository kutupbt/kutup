import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { ManifestSignature } from '@kutup/crypto'
import type { IdentityPin } from '@kutup/crypto/identityPins'
import type { DriveIdentity } from './identity'

const pins = vi.hoisted(() => ({ list: [] as unknown[], keys: new Map<string, string | null>(), fail: false }))

vi.mock('@kutup/crypto', () => ({
  deriveAccountIdentityKeys: vi.fn(() => Promise.resolve({ driveSigningPublicKey: 'key-me' })),
  setManifestSignerCheck: vi.fn(),
  toBase64: () => 'master',
}))
vi.mock('@kutup/crypto/identityPins', () => ({
  incarnationIdOfAuthority: vi.fn((authority: string) => Promise.resolve(`inc-${authority}`)),
  pinAddress: (pin: IdentityPin) => pin.addresses?.at(-1)?.address,
}))
vi.mock('@kutup/session/store', () => ({ getSession: () => null }))
vi.mock('./identity', () => ({ driveIdentityOf: vi.fn() }))
vi.mock('./identityPins', () => ({
  pinsOfAccountId: vi.fn((_me: unknown, accountId: string) =>
    pins.fail ? Promise.reject(new Error('offline')) : Promise.resolve((pins.list as IdentityPin[]).filter((pin) => pin.account.accountId === accountId)),
  ),
  boundSigningKeyOf: vi.fn((_me: unknown, pin: IdentityPin) => Promise.resolve(pins.keys.get(pin.authorityPublicKey) ?? null)),
}))

import { manifestSignerVerdict } from './manifestSigners'

const me = { userId: 'me', account: 'me@kutup.dev', incarnationId: 'inc-ME', masterKey: new Uint8Array(32) } as unknown as DriveIdentity

function signature(accountId: string, incarnationId: string, key: string): ManifestSignature {
  return { fileId: 'f', revisionId: 'r', accountId, incarnationId, signedBy: (candidate) => candidate === key }
}

function pin(accountId: string, authority: string, replaced?: string[]): IdentityPin {
  return {
    account: { server: 'kutup.dev', accountId },
    authorityPublicKey: authority,
    state: 'seen',
    since: '2026-11-01T00:00:00Z',
    addresses: [{ address: `${accountId}@kutup.dev`, seenAt: '2026-11-01T00:00:00Z' }],
    ...(replaced ? { replaced } : {}),
  }
}

describe('who signed a revision', () => {
  beforeEach(() => {
    pins.list = [pin('bob', 'B')]
    pins.keys = new Map([['B', 'key-bob']])
    pins.fail = false
  })

  it("takes this account's own signature, and warns of one under its name it did not make", async () => {
    expect(await manifestSignerVerdict(me, signature('me', 'inc-ME', 'key-me'))).toEqual({ kind: 'verified' })
    expect(await manifestSignerVerdict(me, signature('me', 'inc-ME', 'key-other'))).toEqual({ kind: 'forged', name: 'me@kutup.dev' })
    // This account under another incarnation than its own now: a reset
    // this device didn't make, or its name passed off.
    expect(await manifestSignerVerdict(me, signature('me', 'inc-OLD', 'key-old'))).toEqual({ kind: 'changed', name: 'me@kutup.dev' })
  })

  it('warns when a good signature is not by the author the history shows', async () => {
    // The version row says bob saved it; bob signed it.
    expect(await manifestSignerVerdict(me, signature('bob', 'inc-B', 'key-bob'), { accountId: 'bob' })).toEqual({ kind: 'verified' })
    expect(await manifestSignerVerdict(me, signature('me', 'inc-ME', 'key-me'), { accountId: 'me' })).toEqual({ kind: 'verified' })
    // The history says me; bob signed it.
    expect(await manifestSignerVerdict(me, signature('bob', 'inc-B', 'key-bob'), { accountId: 'me' })).toEqual({
      kind: 'authorMismatch',
      name: 'bob@kutup.dev',
      claimed: null,
    })
    // Someone on another server, by address (case aside).
    expect(await manifestSignerVerdict(me, signature('bob', 'inc-B', 'key-bob'), { address: 'Bob@Kutup.dev' })).toEqual({ kind: 'verified' })
    expect(await manifestSignerVerdict(me, signature('me', 'inc-ME', 'key-me'), { address: 'bob@kutup.dev' })).toEqual({
      kind: 'authorMismatch',
      name: 'me@kutup.dev',
      claimed: 'bob@kutup.dev',
    })
    // A forged or changed signature says so, whatever the history claims.
    expect(await manifestSignerVerdict(me, signature('bob', 'inc-B', 'key-mallory'), { accountId: 'me' })).toEqual({ kind: 'forged', name: 'bob@kutup.dev' })
    // An account never met stays silent, whoever the history names.
    expect(await manifestSignerVerdict(me, signature('carol', 'inc-C', 'key-carol'), { accountId: 'bob' })).toEqual({ kind: 'unknown' })
  })

  it("checks a pinned account's signature with the key its pinned authority vouches for", async () => {
    expect(await manifestSignerVerdict(me, signature('bob', 'inc-B', 'key-bob'))).toEqual({ kind: 'verified' })
    expect(await manifestSignerVerdict(me, signature('bob', 'inc-B', 'key-mallory'))).toEqual({ kind: 'forged', name: 'bob@kutup.dev' })
  })

  it('warns when a pinned account signs under an incarnation that is not the pinned one', async () => {
    expect(await manifestSignerVerdict(me, signature('bob', 'inc-NEW', 'key-new'))).toEqual({ kind: 'changed', name: 'bob@kutup.dev' })
  })

  it('says nothing of what an incarnation the user moved on from signed', async () => {
    pins.list = [pin('bob', 'B2', ['inc-B'])]
    pins.keys = new Map([['B2', 'key-bob-2']])
    expect(await manifestSignerVerdict(me, signature('bob', 'inc-B', 'key-bob'))).toEqual({ kind: 'unknown' })
    expect(await manifestSignerVerdict(me, signature('bob', 'inc-B2', 'key-bob-2'))).toEqual({ kind: 'verified' })
  })

  it("can't tell of an account never met, a key that can't be had, or pins that can't be read", async () => {
    expect(await manifestSignerVerdict(me, signature('carol', 'inc-C', 'key-carol'))).toEqual({ kind: 'unknown' })
    pins.keys = new Map()
    expect(await manifestSignerVerdict(me, signature('bob', 'inc-B', 'key-bob'))).toEqual({ kind: 'unknown' })
    pins.fail = true
    expect(await manifestSignerVerdict(me, signature('bob', 'inc-B', 'key-bob'))).toEqual({ kind: 'unknown' })
  })

  it('tells two accounts with one id on different servers apart by incarnation', async () => {
    pins.list = [pin('bob', 'B'), { ...pin('bob', 'X'), account: { server: 'other.example', accountId: 'bob' } }]
    pins.keys = new Map([
      ['B', 'key-bob'],
      ['X', 'key-x'],
    ])
    expect(await manifestSignerVerdict(me, signature('bob', 'inc-X', 'key-x'))).toEqual({ kind: 'verified' })
    expect(await manifestSignerVerdict(me, signature('bob', 'inc-X', 'key-bob'))).toEqual({ kind: 'forged', name: 'bob@kutup.dev' })
  })
})
