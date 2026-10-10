import { beforeEach, describe, expect, it, vi } from 'vitest'

// The crypto is Rust's (kutup-crypto vectors); here, its decisions are stubbed:
// a binding "verifies" when it names the authority it was made with, an
// incarnation is the authority's name, and a sealed list is its JSON.
vi.mock('@kutup/crypto/identityPins', () => ({
  verifyDriveKeyBinding: vi.fn((_account: string, authority: string, _h: string, _s: string, binding: string) =>
    Promise.resolve(binding === `bound-by-${authority}`),
  ),
  incarnationIdOfAuthority: vi.fn((authority: string) => Promise.resolve(`inc-${authority}`)),
  // The pair's number names both authorities; a scan matches only the current pair.
  deriveSafetyNumber: vi.fn((local: string, la: string, peer: string, pa: string) =>
    Promise.resolve({ fingerprint: `${la}-${pa}`, qrPayload: `qr:${local}:${la}:${peer}:${pa}` }),
  ),
  safetyQrMatches: vi.fn((local: string, la: string, peer: string, pa: string, scanned: string) =>
    Promise.resolve(scanned === `qr:${local}:${la}:${peer}:${pa}`),
  ),
  sealIdentityPins: vi.fn((_m: string, _o: string, revision: number, list: unknown) => Promise.resolve(JSON.stringify({ revision, list }))),
  openIdentityPins: vi.fn((_m: string, _o: string, revision: number, sealed: string) => {
    const parsed = JSON.parse(sealed) as { revision: number; list: unknown }
    return parsed.revision === revision ? Promise.resolve(parsed.list) : Promise.reject(new Error('relabelled'))
  }),
}))

const server = {
  people: new Map<string, Record<string, unknown>>(),
  pins: null as { revision: number; envelope: string } | null,
  puts: 0,
  conflictOnce: false,
  batches: [] as string[][],
}

vi.mock('@kutup/session/client', () => {
  const notFound = () => Object.assign(new Error('404'), { isAxiosError: true, response: { status: 404 } })
  const conflict = () => Object.assign(new Error('409'), { isAxiosError: true, response: { status: 409 } })
  return {
    default: {
      get: vi.fn((url: string) => {
        if (url === '/user/identity-pins') return server.pins ? Promise.resolve({ data: server.pins }) : Promise.reject(notFound())
        const person = server.people.get(decodeURIComponent(url.split('/').pop()!))
        return person ? Promise.resolve({ data: person }) : Promise.reject(notFound())
      }),
      post: vi.fn((url: string, body: { accounts: string[] }) => {
        if (url !== '/users/drive-identities') return Promise.reject(new Error(url))
        server.batches.push(body.accounts)
        return Promise.resolve({ data: body.accounts.flatMap((a) => server.people.get(a) ?? []) })
      }),
      put: vi.fn((_url: string, body: { revision: number; envelope: string }) => {
        server.puts++
        if (server.conflictOnce) {
          server.conflictOnce = false
          // Another app stored revision 1 with a pin of its own.
          server.pins = {
            revision: 1,
            envelope: JSON.stringify({ revision: 1, list: { pins: [{ account: 'carol@kutup.dev', authorityPublicKey: 'C', state: 'seen', since: '2026-10-10T00:00:00Z' }] } }),
          }
          return Promise.reject(conflict())
        }
        if (body.revision !== (server.pins?.revision ?? 0) + 1) return Promise.reject(conflict())
        server.pins = body
        return Promise.resolve({ data: null })
      }),
    },
  }
})

import { acceptIdentity, checkIdentity, personSafetyNumber, PinsRolledBack, resetIdentityPinsForTesting, SafetyNumberMismatch, verifyPerson } from './identityPins'
import type { DriveIdentity } from './identity'

const me: DriveIdentity = {
  userId: 'me-id',
  account: 'me@kutup.dev',
  incarnationId: 'inc-ME',
  masterKey: new Uint8Array(32),
  privateKey: new Uint8Array(32),
  authorityPublicKey: 'ME',
}

function publish(account: string, authority: string, { bound = true, hpke = `${authority}-hpke`, signing = `${authority}-sign` } = {}) {
  server.people.set(account, {
    account,
    accountAuthorityPublicKey: authority,
    driveHpkePublicKey: hpke,
    driveSigningPublicKey: signing,
    driveKeyBinding: bound ? `bound-by-${authority}` : undefined,
  })
}

function storedPins(): { account: string; authorityPublicKey: string; replaced?: string[] }[] {
  return (JSON.parse(server.pins!.envelope) as { list: { pins: { account: string; authorityPublicKey: string; replaced?: string[] }[] } }).list.pins
}

beforeEach(() => {
  resetIdentityPinsForTesting()
  server.people.clear()
  server.pins = null
  server.puts = 0
  server.conflictOnce = false
  server.batches = []
  localStorage.clear()
})

describe('checkIdentity', () => {
  it('pins an account the first time, then recognises it', async () => {
    publish('bob@kutup.dev', 'B')
    expect(await checkIdentity(me, 'bob@kutup.dev', { driveSigningPublicKey: 'B-sign' })).toEqual({ kind: 'ok', verified: false })
    expect(storedPins()).toMatchObject([{ account: 'bob@kutup.dev', authorityPublicKey: 'B' }])
    expect(await checkIdentity(me, 'bob@kutup.dev', { driveHpkePublicKey: 'B-hpke' })).toEqual({ kind: 'ok', verified: false })
    expect(server.puts).toBe(1)
  })

  it('warns when the server hands out keys the account did not sign', async () => {
    publish('bob@kutup.dev', 'B')
    // A share signed with a key that is not Bob's.
    expect(await checkIdentity(me, 'bob@kutup.dev', { driveSigningPublicKey: 'EVIL-sign' })).toEqual({ kind: 'invalid' })
    // A recipient key that is not Bob's.
    expect(await checkIdentity(me, 'bob@kutup.dev', { driveHpkePublicKey: 'EVIL-hpke' })).toEqual({ kind: 'invalid' })
    // A binding by another authority than the one published.
    server.people.set('eve@kutup.dev', { account: 'eve@kutup.dev', accountAuthorityPublicKey: 'E', driveHpkePublicKey: 'x', driveSigningPublicKey: 'y', driveKeyBinding: 'bound-by-B' })
    expect(await checkIdentity(me, 'eve@kutup.dev')).toEqual({ kind: 'invalid' })
    // An incarnation that is not this authority's.
    expect(await checkIdentity(me, 'bob@kutup.dev', { incarnationId: 'inc-OTHER' })).toEqual({ kind: 'invalid' })
    expect(server.pins).toBeNull()
  })

  it('warns when the address now has another authority, until accepted', async () => {
    publish('bob@kutup.dev', 'B')
    await checkIdentity(me, 'bob@kutup.dev')
    resetIdentityPinsForTesting()
    // Bob's account was wiped and set up again (or the server lies).
    publish('bob@kutup.dev', 'B2')
    expect(await checkIdentity(me, 'bob@kutup.dev')).toEqual({ kind: 'changed' })
    await acceptIdentity(me, 'bob@kutup.dev')
    expect(storedPins()).toMatchObject([{ account: 'bob@kutup.dev', authorityPublicKey: 'B2', replaced: ['inc-B'] }])
    expect(await checkIdentity(me, 'bob@kutup.dev')).toEqual({ kind: 'ok', verified: false })
  })

  it('says an account that has not signed its keys yet is unproven, and pins nothing', async () => {
    publish('old@kutup.dev', 'O', { bound: false })
    expect(await checkIdentity(me, 'old@kutup.dev')).toEqual({ kind: 'unproven' })
    expect(server.pins).toBeNull()
  })

  it('does not let a server drop the binding of an account already pinned', async () => {
    publish('bob@kutup.dev', 'B')
    await checkIdentity(me, 'bob@kutup.dev')
    resetIdentityPinsForTesting()
    publish('bob@kutup.dev', 'B', { bound: false, hpke: 'EVIL-hpke' })
    expect(await checkIdentity(me, 'bob@kutup.dev')).toEqual({ kind: 'invalid' })
  })

  it('cannot say when the person cannot be looked up', async () => {
    expect(await checkIdentity(me, 'ghost@kutup.dev')).toEqual({ kind: 'unknown' })
  })

  it('merges with a list another app stored first', async () => {
    publish('bob@kutup.dev', 'B')
    server.conflictOnce = true
    expect(await checkIdentity(me, 'bob@kutup.dev')).toEqual({ kind: 'ok', verified: false })
    expect(server.pins!.revision).toBe(2)
    expect(storedPins().map((p) => p.account)).toEqual(['bob@kutup.dev', 'carol@kutup.dev'])
  })

  it('refuses an older list than this browser has seen', async () => {
    publish('bob@kutup.dev', 'B')
    await checkIdentity(me, 'bob@kutup.dev')
    resetIdentityPinsForTesting()
    // The server hands back the list from before Bob was pinned.
    server.pins = null
    expect(await checkIdentity(me, 'bob@kutup.dev')).toEqual({ kind: 'unknown' })
    expect(PinsRolledBack).toBeDefined()
  })

  it('looks up everyone a page asks about at once in one request', async () => {
    for (const name of ['a', 'b', 'c']) publish(`${name}@kutup.dev`, name.toUpperCase())
    await Promise.all(['a', 'b', 'c'].map((name) => checkIdentity(me, `${name}@kutup.dev`)))
    expect(server.batches).toEqual([['a@kutup.dev', 'b@kutup.dev', 'c@kutup.dev']])
  })

  it('trusts the account itself', async () => {
    expect(await checkIdentity(me, me.account)).toEqual({ kind: 'ok', verified: true })
  })
})

describe('verifyPerson', () => {
  it('marks a person verified with their scanned safety QR, for every app', async () => {
    publish('bob@kutup.dev', 'B')
    const number = await personSafetyNumber(me, 'bob@kutup.dev')
    await expect(verifyPerson(me, 'bob@kutup.dev', 'qr:somebody-else')).rejects.toBeInstanceOf(SafetyNumberMismatch)
    await verifyPerson(me, 'bob@kutup.dev', number.qrPayload)
    expect(storedPins()).toMatchObject([{ account: 'bob@kutup.dev', authorityPublicKey: 'B', state: 'verified' }])
    resetIdentityPinsForTesting()
    publish('bob@kutup.dev', 'B')
    expect(await checkIdentity(me, 'bob@kutup.dev')).toEqual({ kind: 'ok', verified: true })
  })

  it('accepts a changed identity once it is compared in person', async () => {
    publish('bob@kutup.dev', 'B')
    await checkIdentity(me, 'bob@kutup.dev')
    resetIdentityPinsForTesting()
    publish('bob@kutup.dev', 'B2')
    expect(await checkIdentity(me, 'bob@kutup.dev')).toEqual({ kind: 'changed' })
    const number = await personSafetyNumber(me, 'bob@kutup.dev')
    await verifyPerson(me, 'bob@kutup.dev', number.qrPayload)
    expect(storedPins()).toMatchObject([{ authorityPublicKey: 'B2', state: 'verified', replaced: ['inc-B'] }])
  })

  it('has nothing to compare for someone whose keys are not signed', async () => {
    publish('old@kutup.dev', 'O', { bound: false })
    await expect(personSafetyNumber(me, 'old@kutup.dev')).rejects.toThrow(/binding/)
  })
})
