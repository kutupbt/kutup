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
  formerly?: string[]
}

interface Rename {
  incarnationId: string
  sequence: number
  previous: string
  current: string
  issuedAtMs: number
  signature: string
}

// Rust's names::fold_address, modelled.
function fold(address: string): string | null {
  const at = address.lastIndexOf('@')
  return at > 0 ? `${address.slice(0, at).replace(/[._-]/g, '').toLowerCase()}@${address.slice(at + 1).toLowerCase()}` : null
}

// Rust's account_rename::verify_chain, modelled: a statement "verifies" when
// signed by the authority, and each starts where the one before ended.
function verifyChain(authority: string, chain: Rename[]) {
  if (chain.length === 0) throw new Error('empty chain')
  chain.forEach((statement, i) => {
    if (statement.signature !== `signed-by-${authority}` || statement.sequence !== i + 1) throw new Error('chain does not verify')
    if (i > 0 && statement.previous !== chain[i - 1].current) throw new Error('chain does not verify')
  })
  const addresses = [chain[0].previous, ...chain.map((statement) => statement.current)]
  return { incarnationId: `inc-${authority}`, first: addresses[0], current: addresses.at(-1)!, addresses, sequence: chain.length, digests: [] }
}

vi.mock('@kutup/crypto/accountRename', () => ({
  foldAddress: vi.fn((address: string) => Promise.resolve(fold(address))),
  verifyAccountRenameChain: vi.fn((authority: string, chain: Rename[]) => Promise.resolve(verifyChain(authority, chain))),
}))

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
  // Rust's identity_pins::lookup, modelled: addresses compared folded.
  lookupIdentityPin: vi.fn((current: { list: { pins: Pin[]; detached?: Pin[] } }, address: string, authority?: string) => {
    const pin = current.list.pins.find((known) => fold(known.account) === fold(address))
    if (pin) return Promise.resolve({ kind: 'pinned', pin, sameAuthority: pin.authorityPublicKey === authority })
    const elsewhere = authority ? current.list.pins.find((known) => known.authorityPublicKey === authority) : undefined
    if (elsewhere) return Promise.resolve({ kind: 'renamed', pin: elsewhere })
    const back = (current.list.detached ?? []).find((known) => fold(known.account) === fold(address))
    if (back) return Promise.resolve({ kind: 'returned', pin: back })
    // Someone pinned had this address before (their rename) and is elsewhere now.
    const left = current.list.pins.filter((known) => (known.formerly ?? []).some((former) => fold(former) === fold(address)))
    if (left.length > 0) return Promise.resolve({ kind: 'moved', pins: left.map((known) => ({ pin: known, now: known.account })) })
    return Promise.resolve({ kind: 'new' })
  }),
  // Rust's identity_pins::apply_rename, modelled: the pin of that authority
  // moves to the chain's current address, its old one kept in `formerly`.
  applyAccountRenameToPins: vi.fn((current: { list: { pins: Pin[] } }, authority: string, chain: Rename[]) => {
    const view = verifyChain(authority, chain)
    const pins = current.list.pins.map((pin) => ({ ...pin }))
    const at = pins.findIndex((pin) => pin.authorityPublicKey === authority)
    if (at < 0) return Promise.reject(new Error('concerns no pinned account'))
    const pin = pins[at]
    const from = pin.account
    if (fold(from) === fold(view.current)) {
      return Promise.resolve({ pins: { text: JSON.stringify(current.list), list: current.list }, applied: { from, to: view.current, changed: false, displaced: null } })
    }
    if (!view.addresses.some((address) => fold(address) === fold(from))) return Promise.reject(new Error('the chain does not name the pin'))
    pins[at] = { ...pin, account: view.current, formerly: [...(pin.formerly ?? []), from] }
    const list = { ...current.list, pins }
    return Promise.resolve({ pins: { text: JSON.stringify(list), list }, applied: { from, to: view.current, changed: true, displaced: null } })
  }),
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
  /** `GET /users/renames/:address`, by address. */
  renames: new Map<string, unknown>(),
  /** Lookups answering `409 renamed` with these chains, by address. */
  heldNames: new Map<string, unknown>(),
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
        if (url.startsWith('/users/renames/')) {
          const found = server.renames.get(decodeURIComponent(url.slice('/users/renames/'.length)))
          return Promise.resolve({ data: found ?? { version: 1, chains: [] } })
        }
        const held = server.heldNames.get(decodeURIComponent(url.split('/').pop()!))
        if (held) {
          return Promise.reject(
            Object.assign(new Error('409'), { isAxiosError: true, response: { status: 409, data: { code: 'renamed', renames: held } } }),
          )
        }
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
import {
  acceptIdentity,
  checkIdentity,
  currentAddressOf,
  personSafetyNumber,
  pinnedVerdict,
  PinsRolledBack,
  recipientError,
  RecipientRenamed,
  resetIdentityPinsForTesting,
  SafetyNumberMismatch,
  verifyPerson,
} from './identityPins'
import type { DriveIdentity } from './identity'

const me: DriveIdentity = {
  userId: 'me-id',
  account: 'me@kutup.dev',
  accountRef: { server: 'kutup.dev', accountId: 'me-id' },
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
  server.renames.clear()
  server.heldNames.clear()
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

/** The chain of `authority`'s account through `addresses`, oldest first, signed by it (or `by`). */
function chainOf(authority: string, addresses: string[], by = authority): Rename[] {
  return addresses.slice(1).map((current, i) => ({
    incarnationId: `inc-${authority}`,
    sequence: i + 1,
    previous: addresses[i],
    current,
    issuedAtMs: 1000 + i,
    signature: `signed-by-${by}`,
  }))
}

function chains(authority: string, addresses: string[], { by = authority, state = 'current', version = 1 } = {}) {
  return {
    version,
    chains: [{ incarnationId: `inc-${authority}`, authorityPublicKey: authority, current: addresses.at(-1)!, state, chain: chainOf(authority, addresses, by) }],
  }
}

describe('renames (docs/plans/username-renames.md)', () => {
  /** Ada met as ada.l, pinned. */
  async function metAda() {
    publish('ada.l@kutup.dev', 'A')
    expect(await checkIdentity(me, 'ada.l@kutup.dev')).toEqual({ kind: 'ok', verified: false })
    // Then renamed: the old name is held (not found here), the new one published.
    server.people.clear()
    publish('ada.lovelace@kutup.dev', 'A')
    resetLookups()
  }

  /** A new page: nothing looked up yet, the pins read again. */
  function resetLookups() {
    const pins = server.pins
    resetIdentityPinsForTesting()
    server.pins = pins
  }

  it('finds a pin in any spelling of its address', async () => {
    publish('ada.l@kutup.dev', 'A')
    await checkIdentity(me, 'ada.l@kutup.dev')
    publish('Ada_L@kutup.dev', 'A')
    expect(await checkIdentity(me, 'Ada_L@kutup.dev')).toEqual({ kind: 'ok', verified: false })
    expect(storedPins()).toHaveLength(1)
  })

  it('says where someone pinned at a name they left is now, and moves the pin', async () => {
    await metAda()
    server.renames.set('ada.l@kutup.dev', chains('A', ['ada.l@kutup.dev', 'ada.lovelace@kutup.dev']))
    expect(await checkIdentity(me, 'ada.l@kutup.dev')).toEqual({ kind: 'renamed', now: 'ada.lovelace@kutup.dev', verified: false })
    expect(storedPins()).toMatchObject([{ account: 'ada.lovelace@kutup.dev', authorityPublicKey: 'A', formerly: ['ada.l@kutup.dev'] }])
    resetLookups()
    expect(await checkIdentity(me, 'ada.lovelace@kutup.dev')).toEqual({ kind: 'ok', verified: false, formerly: 'ada.l@kutup.dev' })
  })

  it('follows the chain from the new address too: formerly the old one', async () => {
    await metAda()
    server.renames.set('ada.lovelace@kutup.dev', chains('A', ['ada.l@kutup.dev', 'ada.lovelace@kutup.dev']))
    expect(await checkIdentity(me, 'ada.lovelace@kutup.dev')).toEqual({ kind: 'ok', verified: false, formerly: 'ada.l@kutup.dev' })
    expect(storedPins()).toMatchObject([{ account: 'ada.lovelace@kutup.dev', formerly: ['ada.l@kutup.dev'] }])
  })

  it('never moves a pin on a chain its authority did not sign, nor on an unknown format', async () => {
    await metAda()
    server.renames.set('ada.l@kutup.dev', chains('A', ['ada.l@kutup.dev', 'mallory@kutup.dev'], { by: 'M' }))
    expect(await checkIdentity(me, 'ada.l@kutup.dev')).toEqual({ kind: 'unknown' })
    server.renames.set('ada.l@kutup.dev', chains('A', ['ada.l@kutup.dev', 'ada.lovelace@kutup.dev'], { version: 2 }))
    resetLookups()
    expect(await checkIdentity(me, 'ada.l@kutup.dev')).toEqual({ kind: 'unknown' })
    expect(storedPins()).toMatchObject([{ account: 'ada.l@kutup.dev', authorityPublicKey: 'A' }])
  })

  it('keeps the pin when the server cannot say, or names another authority', async () => {
    await metAda()
    server.renames.set('ada.l@kutup.dev', { version: 1, chains: [], unavailable: true })
    expect(await checkIdentity(me, 'ada.l@kutup.dev')).toEqual({ kind: 'unknown' })
    server.renames.set('ada.l@kutup.dev', chains('M', ['ada.l@kutup.dev', 'mallory@kutup.dev']))
    resetLookups()
    expect(await checkIdentity(me, 'ada.l@kutup.dev')).toEqual({ kind: 'unknown' })
    expect(storedPins()).toMatchObject([{ account: 'ada.l@kutup.dev', authorityPublicKey: 'A' }])
  })

  it('follows a federated 409 renamed for a pinned person', async () => {
    publish('bob@other.dev', 'B')
    await checkIdentity(me, 'bob@other.dev')
    server.people.clear()
    resetLookups()
    server.heldNames.set('bob', chains('B', ['bob@other.dev', 'robert@other.dev']))
    expect(await checkIdentity(me, 'bob@other.dev')).toEqual({ kind: 'renamed', now: 'robert@other.dev', verified: false })
  })

  it('tells a share to a name its person left where they are now, for someone never met', async () => {
    const renamed = Object.assign(new Error('409'), {
      isAxiosError: true,
      response: { status: 409, data: { code: 'renamed', renames: chains('C', ['carol@kutup.dev', 'caroline@kutup.dev']) } },
    })
    const error = await recipientError(me, 'carol@kutup.dev', renamed)
    expect(error).toBeInstanceOf(RecipientRenamed)
    expect(error).toMatchObject({ account: 'carol@kutup.dev', now: 'caroline@kutup.dev' })
    expect(server.pins).toBeNull()
    // A chain that does not verify, or another error, is passed on as it is.
    const forged = { ...renamed, response: { status: 409, data: { code: 'renamed', renames: chains('C', ['carol@kutup.dev', 'x@kutup.dev'], { by: 'M' }) } } }
    expect(await recipientError(me, 'carol@kutup.dev', forged)).toBe(forged)
    const other = new Error('offline')
    expect(await recipientError(me, 'carol@kutup.dev', other)).toBe(other)
  })
})

describe('pinnedVerdict (Mail’s key checks)', () => {
  /** A new page: nothing looked up yet, the pins read again. */
  function resetForNewPage() {
    const pins = server.pins
    resetIdentityPinsForTesting()
    server.pins = pins
  }

  async function met(account: string, authority: string) {
    publish(account, authority)
    await checkIdentity(me, account)
  }

  it('says pinned, changed or unknown for an address', async () => {
    await met('bob@kutup.dev', 'B')
    expect(await pinnedVerdict(me, 'bob@kutup.dev', 'B')).toEqual({ kind: 'pinned' })
    expect(await pinnedVerdict(me, 'bob@kutup.dev', 'M')).toEqual({ kind: 'changed' })
    expect(await pinnedVerdict(me, 'carol@kutup.dev', 'C')).toEqual({ kind: 'unknown' })
  })

  it('takes an address the pinned person left only with a chain naming both', async () => {
    await met('ada_lovelace@kutup.dev', 'A')
    // Ada's old address, signed by her authority, which is pinned elsewhere.
    expect(await pinnedVerdict(me, 'ada_l@kutup.dev', 'A')).toEqual({ kind: 'changed' })
    server.renames.set('ada_l@kutup.dev', chains('A', ['ada_l@kutup.dev', 'ada_lovelace@kutup.dev']))
    expect(await pinnedVerdict(me, 'ada_l@kutup.dev', 'A')).toEqual({ kind: 'renamed', now: 'ada_lovelace@kutup.dev' })
    // A chain its authority did not sign covers nothing.
    server.renames.set('ada_l@kutup.dev', chains('A', ['ada_l@kutup.dev', 'ada_lovelace@kutup.dev'], { by: 'M' }))
    expect(await pinnedVerdict(me, 'ada_l@kutup.dev', 'A')).toEqual({ kind: 'changed' })
  })

  it('refuses someone else at an address a pinned person left, naming where that person is', async () => {
    // Ada renamed (followed); her old name was freed and Mallory took it.
    await met('ada_l@kutup.dev', 'A')
    server.renames.set('ada_l@kutup.dev', chains('A', ['ada_l@kutup.dev', 'ada_lovelace@kutup.dev']))
    server.people.clear()
    publish('ada_lovelace@kutup.dev', 'A')
    resetForNewPage()
    await checkIdentity(me, 'ada_l@kutup.dev')
    expect(storedPins()).toMatchObject([{ account: 'ada_lovelace@kutup.dev' }])
    expect(await pinnedVerdict(me, 'ada_l@kutup.dev', 'M')).toEqual({ kind: 'changed', now: 'ada_lovelace@kutup.dev' })
    // Ada herself at her new name is who she was.
    expect(await pinnedVerdict(me, 'ada_lovelace@kutup.dev', 'A')).toEqual({ kind: 'pinned' })
  })

  it('takes a detached pin back only with its own authority', async () => {
    const detached = [{ account: 'erin@kutup.dev', authorityPublicKey: 'E', state: 'seen', since: '2026-10-10T00:00:00Z' }]
    server.pins = { revision: 1, envelope: JSON.stringify({ binding: ME_BINDING, revision: 1, list: { pins: [], detached } }) }
    expect(await pinnedVerdict(me, 'erin@kutup.dev', 'E')).toEqual({ kind: 'pinned' })
    expect(await pinnedVerdict(me, 'erin@kutup.dev', 'M')).toEqual({ kind: 'changed' })
  })

  it('names where an old address’s account is now', async () => {
    server.renames.set('ada_l@kutup.dev', chains('A', ['ada_l@kutup.dev', 'ada_lovelace@kutup.dev']))
    expect(await currentAddressOf('ada_l@kutup.dev', 'A')).toBe('ada_lovelace@kutup.dev')
    expect(await currentAddressOf('ada_l@kutup.dev', 'M')).toBe('ada_l@kutup.dev')
    expect(await currentAddressOf('grace@kutup.dev', 'G')).toBe('grace@kutup.dev')
  })
})
