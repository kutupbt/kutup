import { beforeEach, describe, expect, it, vi } from 'vitest'

// The crypto is Rust's (kutup-crypto vectors); here, its decisions are stubbed:
// a binding "verifies" when it names the authority it was made with, an
// incarnation is the authority's name, and a sealed list is its JSON, which
// opens only for the key binding and revision it was sealed with.
/** What the next `recordIdentityPin` decides instead of the model (a Rust outcome to react to). */
const recordOverride = vi.hoisted(() => ({ next: null as null | Record<string, unknown> }))

interface Pin {
  account: string
  authorityPublicKey: string
  state: 'seen' | 'verified'
  since: string
  replaced?: string[]
}

vi.mock('@kutup/crypto/identityPins', () => ({
  verifyDriveKeyBinding: vi.fn((_account: string, authority: string, _h: string, _s: string, binding: string) =>
    Promise.resolve(binding === `bound-by-${authority}`),
  ),
  incarnationIdOfAuthority: vi.fn((authority: string) => Promise.resolve(`inc-${authority}`)),
  // The pair's number names both authorities; a scan matches only the current pair.
  deriveSafetyNumber: vi.fn((la: string, pa: string) =>
    Promise.resolve({ fingerprint: `${la}-${pa}`, qrPayload: `qr:${la}:${pa}` }),
  ),
  safetyQrMatches: vi.fn((la: string, pa: string, scanned: string) =>
    Promise.resolve(scanned === `qr:${la}:${pa}`),
  ),
  // Rust's identity_pins::record, modelled: first use pins, accepted or
  // verified replace (the old incarnation kept), the same authority keeps its history.
  recordIdentityPin: vi.fn(
    (current: { text: string; list: { pins: Pin[] } }, account: string, authority: string, update: 'firstSeen' | 'accepted' | 'verified', since: string) => {
      const list = current.list
      const out = (next: Record<string, unknown>, changed: boolean, result: Record<string, unknown>) =>
        Promise.resolve({ pins: { text: JSON.stringify(next), list: next }, changed, result })
      if (recordOverride.next) {
        const result = recordOverride.next
        recordOverride.next = null
        return out(list, false, result)
      }
      const pins = list.pins.map((pin) => ({ ...pin }))
      const at = pins.findIndex((pin) => pin.account === account)
      const state = update === 'verified' ? 'verified' : 'seen'
      const unchanged = out({ ...list, pins }, false, { kind: 'unchanged' })
      const pinned = () => out({ ...list, pins }, true, { kind: 'pinned' })
      if (at < 0) {
        pins.push({ account, authorityPublicKey: authority, state, since })
        pins.sort((a, b) => (a.account < b.account ? -1 : 1))
        return pinned()
      }
      const pin = pins[at]
      if (pin.authorityPublicKey === authority) {
        if (update !== 'verified' || pin.state === 'verified') return unchanged
        pins[at] = { ...pin, state: 'verified', since }
        return pinned()
      }
      if (update === 'firstSeen') return unchanged
      const replaced = [...(pin.replaced ?? []), `inc-${pin.authorityPublicKey}`].slice(-10)
      pins[at] = { account, authorityPublicKey: authority, state, since, replaced }
      return pinned()
    },
  ),
  EMPTY_PINS: { text: '{"pins":[]}', list: { pins: [] } },
  sealIdentityPins: vi.fn((_m: string, binding: string, revision: number, pins: { text: string }) =>
    Promise.resolve(JSON.stringify({ binding, revision, list: JSON.parse(pins.text) as unknown })),
  ),
  openIdentityPins: vi.fn((_m: string, binding: string, sealed: string) => {
    const parsed = JSON.parse(sealed) as { binding: string; revision: number; list: unknown }
    return parsed.binding === binding
      ? Promise.resolve({ pins: { text: JSON.stringify(parsed.list), list: parsed.list }, revision: parsed.revision })
      : Promise.reject(new Error('another account'))
  }),
}))

/** The account's key binding: the list is sealed to it, never to the address. */
const ME_BINDING = '0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b'

const server = {
  people: new Map<string, Record<string, unknown>>(),
  pins: null as { revision: number; envelope: string } | null,
  puts: 0,
  conflictOnce: false,
  batches: [] as string[][],
  heads: [] as (string | undefined)[],
}

// The account head (docs/plans/rollback-protection.md), its rules kept
// small: an index of the one `pins` value, covered or not, and listed writes
// redone on a conflict as the real client does. Its own tests are in
// @kutup/session/accountHead.test.ts.
const head = vi.hoisted(() => ({ covered: false, revision: 0, blocked: false, sent: [] as string[] }))
vi.mock('@kutup/session/accountHead', async () => {
  const actual = await vi.importActual<typeof import('@kutup/session/accountHead')>('@kutup/session/accountHead')
  const index = () => new actual.VerifiedIndex('pins', head.covered, head.covered ? [['pins', head.revision]] : [], null)
  const conflicted = (error: unknown) => {
    const code = (error as { response?: { status?: number; data?: { code?: string } } }).response?.data?.code
    return code === 'head_conflict' || code === 'revision_conflict'
  }
  const client = {
    verifiedIndex: () => (head.blocked ? Promise.reject(new actual.HeadBlockedError('fork')) : Promise.resolve(index())),
    listedWrite: async <T,>(_scope: string, edit: (i: InstanceType<typeof actual.VerifiedIndex>, attempt: number) => Promise<{ changes: [string, number | null][]; send: (h: string) => Promise<T> } | null>) => {
      for (let attempt = 1; ; attempt++) {
        if (head.blocked) throw new actual.HeadBlockedError('fork')
        const change = await edit(index(), attempt)
        if (!change) return undefined
        try {
          const sealed = `head-${head.sent.length + 1}`
          const result = await change.send(sealed)
          head.sent.push(sealed)
          head.revision = change.changes[0][1] ?? 0
          return result
        } catch (error) {
          if (conflicted(error) && attempt < 5) continue
          throw error
        }
      }
    },
  }
  return { ...actual, accountHead: () => Promise.resolve(client) }
})

vi.mock('@kutup/session/client', () => {
  const notFound = () => Object.assign(new Error('404'), { isAxiosError: true, response: { status: 404 } })
  const conflict = () =>
    Object.assign(new Error('409'), { isAxiosError: true, response: { status: 409, data: { code: 'revision_conflict' } } })
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
      put: vi.fn((_url: string, body: { baseRevision: number; envelope: string; head?: string }) => {
        server.puts++
        server.heads.push(body.head)
        if (server.conflictOnce) {
          server.conflictOnce = false
          // Another app stored revision 1 with a pin of its own.
          server.pins = {
            revision: 1,
            envelope: JSON.stringify({ binding: ME_BINDING, revision: 1, list: { pins: [{ account: 'carol@kutup.dev', authorityPublicKey: 'C', state: 'seen', since: '2026-10-10T00:00:00Z' }] } }),
          }
          return Promise.reject(conflict())
        }
        // Stored only on top of the revision the write started from, newer than it.
        const revision = (JSON.parse(body.envelope) as { revision: number }).revision
        if (body.baseRevision !== (server.pins?.revision ?? 0) || revision <= body.baseRevision) return Promise.reject(conflict())
        server.pins = { revision, envelope: body.envelope }
        return Promise.resolve({ data: null })
      }),
    },
  }
})

import { resetRevisionGuardsForTesting } from '@kutup/crypto/revisionGuard'
import { acceptIdentity, checkIdentity, personSafetyNumber, PinsRolledBack, resetIdentityPinsForTesting, SafetyNumberMismatch, verifyPerson } from './identityPins'
import type { DriveIdentity } from './identity'

const me: DriveIdentity = {
  userId: 'me-id',
  account: 'me@kutup.dev',
  binding: ME_BINDING,
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
  recordOverride.next = null
  resetIdentityPinsForTesting()
  server.people.clear()
  server.pins = null
  server.puts = 0
  server.conflictOnce = false
  server.batches = []
  server.heads = []
  Object.assign(head, { covered: false, revision: 0, blocked: false, sent: [] })
  resetRevisionGuardsForTesting()
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
    expect(server.pins!.revision).toBeGreaterThan(1)
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

  it('refuses a list sealed at an older revision than this browser has seen', async () => {
    publish('bob@kutup.dev', 'B')
    await checkIdentity(me, 'bob@kutup.dev')
    resetIdentityPinsForTesting()
    // The server replays an older list, sealed at revision 1 (it cannot relabel it).
    server.pins = { revision: 1, envelope: JSON.stringify({ binding: ME_BINDING, revision: 1, list: { pins: [] } }) }
    expect(await checkIdentity(me, 'bob@kutup.dev')).toEqual({ kind: 'unknown' })
  })

  it('writes the list with the next account head', async () => {
    publish('bob@kutup.dev', 'B')
    await checkIdentity(me, 'bob@kutup.dev')
    expect(server.heads.at(-1)).toMatch(/^head-\d+$/)
  })

  it('refuses a list the account head does not vouch for', async () => {
    publish('bob@kutup.dev', 'B')
    await checkIdentity(me, 'bob@kutup.dev')
    resetIdentityPinsForTesting()
    // The head lists another revision than the list the server hands out
    // (one this browser never saw, so its own guard alone would take it).
    resetRevisionGuardsForTesting()
    head.covered = true
    head.revision = server.pins!.revision + 1
    expect(await checkIdentity(me, 'bob@kutup.dev')).toEqual({ kind: 'unknown' })
    head.revision = server.pins!.revision
    resetIdentityPinsForTesting()
    expect(await checkIdentity(me, 'bob@kutup.dev')).toEqual({ kind: 'ok', verified: false })
  })

  it('reads go on while this app is blocked on another history; writes stop', async () => {
    publish('bob@kutup.dev', 'B')
    await checkIdentity(me, 'bob@kutup.dev')
    resetIdentityPinsForTesting()
    head.blocked = true
    const puts = server.puts
    expect(await checkIdentity(me, 'bob@kutup.dev')).toEqual({ kind: 'ok', verified: false })
    publish('dave@kutup.dev', 'D')
    await checkIdentity(me, 'dave@kutup.dev')
    expect(server.puts).toBe(puts)
  })

  it('seals the list to the key binding, not to the address', async () => {
    publish('bob@kutup.dev', 'B')
    await checkIdentity(me, 'bob@kutup.dev')
    expect((JSON.parse(server.pins!.envelope) as { binding: string }).binding).toBe(ME_BINDING)
    // Another account's list (another binding, the same address) does not open.
    resetIdentityPinsForTesting()
    resetRevisionGuardsForTesting()
    expect(await checkIdentity({ ...me, binding: '7d3f1a2b-9c4e-4f6a-8b1d-2e5c7a9f0b3d' }, 'bob@kutup.dev')).toEqual({ kind: 'unknown' })
  })

  it('looks up everyone a page asks about at once in one request', async () => {
    for (const name of ['a', 'b', 'c']) publish(`${name}@kutup.dev`, name.toUpperCase())
    await Promise.all(['a', 'b', 'c'].map((name) => checkIdentity(me, `${name}@kutup.dev`)))
    expect(server.batches).toEqual([['a@kutup.dev', 'b@kutup.dev', 'c@kutup.dev']])
  })

  it('warns, and pins nothing, when someone the user knew had this address before', async () => {
    publish('alice@kutup.dev', 'M')
    recordOverride.next = { kind: 'formerAddressTaken', pins: [{ pin: { account: 'alicia@kutup.dev' }, now: 'alicia@kutup.dev' }] }
    expect(await checkIdentity(me, 'alice@kutup.dev')).toEqual({ kind: 'changed' })
    expect(server.pins).toBeNull()
  })

  it('warns about an identity the user replaced, wherever it turns up', async () => {
    publish('carol@kutup.dev', 'A')
    recordOverride.next = { kind: 'replacedIdentity', pin: { account: 'bob@kutup.dev', authorityPublicKey: 'A', state: 'seen', detachedBy: 'replaced' } }
    expect(await checkIdentity(me, 'carol@kutup.dev')).toEqual({ kind: 'changed' })
    expect(server.pins).toBeNull()
  })

  it('recognises an account pinned under another of its names', async () => {
    publish('alicia@kutup.dev', 'A')
    recordOverride.next = { kind: 'knownElsewhere', pin: { account: 'alice@kutup.dev', authorityPublicKey: 'A', state: 'verified' } }
    expect(await checkIdentity(me, 'alicia@kutup.dev')).toEqual({ kind: 'ok', verified: true })
    expect(server.pins).toBeNull()
  })

  it('says when the identity to accept is someone known under another address', async () => {
    publish('bob@kutup.dev', 'B')
    await checkIdentity(me, 'bob@kutup.dev')
    publish('bob@kutup.dev', 'A')
    recordOverride.next = { kind: 'knownElsewhere', pin: { account: 'alice@kutup.dev', authorityPublicKey: 'A', state: 'seen' } }
    await expect(acceptIdentity(me, 'bob@kutup.dev')).rejects.toMatchObject({ other: 'alice@kutup.dev' })
  })

  it('writes back what it does not know: detached pins and later fields', async () => {
    const detached = [{ account: 'erin@kutup.dev', authorityPublicKey: 'E', state: 'verified', since: '2026-10-10T00:00:00Z' }]
    server.pins = { revision: 1, envelope: JSON.stringify({ binding: ME_BINDING, revision: 1, list: { pins: [], detached, laterList: { a: 1 } } }) }
    publish('bob@kutup.dev', 'B')
    await checkIdentity(me, 'bob@kutup.dev')
    const stored = (JSON.parse(server.pins.envelope) as { list: Record<string, unknown> }).list
    expect(stored.detached).toEqual(detached)
    expect(stored.laterList).toEqual({ a: 1 })
    expect(storedPins()).toMatchObject([{ account: 'bob@kutup.dev' }])
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
