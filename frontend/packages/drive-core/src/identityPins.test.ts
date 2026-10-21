import { beforeEach, describe, expect, it, vi } from 'vitest'

// The crypto is Rust's (kutup-crypto vectors); here, its decisions are
// modelled: a binding "verifies" when it names the authority it was made
// with, an incarnation is the authority's name, and a sealed list is its
// JSON, which opens only for the key binding and revision it was sealed with.

interface Ref {
  server: string
  accountId: string
}

interface Label {
  address: string
  seenAt: string
}

interface Pin {
  account: Ref
  authorityPublicKey: string
  state: 'seen' | 'verified'
  since: string
  replaced?: string[]
  addresses?: Label[]
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

const sameRef = (a: Ref, b: Ref) => a.server === b.server && a.accountId === b.accountId
const had = (pin: Pin, address: string) => (pin.addresses ?? []).find((label) => fold(label.address) === fold(address))
const holds = (pin: Pin, address: string) => {
  const last = pin.addresses?.at(-1)
  return Boolean(last && fold(last.address) === fold(address))
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

// Rust's IdentityPinsV2::at: those holding the address first, by when seen.
function at(list: { pins: Pin[] }, address: string): Pin[] {
  return list.pins
    .filter((pin) => had(pin, address))
    .sort((a, b) => Number(holds(b, address)) - Number(holds(a, address)) || had(b, address)!.seenAt.localeCompare(had(a, address)!.seenAt))
}

// Rust's other_holders: other pins that hold the address now.
function holders(list: { pins: Pin[] }, account: Ref, address: string): Pin[] {
  return at(list, address).filter((other) => !sameRef(other.account, account) && holds(other, address))
}

interface GroupPinModel {
  server: string
  groupId: string
  signerPublicKey: string
  since: string
  anchor: { sequence: number; digest: string }
  replaced?: string[]
}

function continues(pin: GroupPinModel, chain: { signers: string[]; digests: string[] }): boolean {
  return chain.signers.includes(pin.signerPublicKey) && chain.digests[pin.anchor.sequence - 1] === pin.anchor.digest
}

vi.mock('@kutup/crypto/accountRename', () => ({
  foldAddress: vi.fn((address: string) => Promise.resolve(fold(address))),
  verifyAccountRenameChain: vi.fn((authority: string, chain: Rename[]) => Promise.resolve(verifyChain(authority, chain))),
}))

vi.mock('@kutup/crypto/accountRef', () => ({ sameAccount: (a: Ref, b: Ref) => sameRef(a, b) }))

vi.mock('@kutup/crypto/identityPins', () => ({
  // Every binding here is the first, at epoch 1.
  verifyDriveKeyBinding: vi.fn((_account: string, authority: string, _h: string, _s: string, binding: string, epoch: number) =>
    Promise.resolve(binding === `bound-by-${authority}` && epoch === 1),
  ),
  incarnationIdOfAuthority: vi.fn((authority: string) => Promise.resolve(`inc-${authority}`)),
  // The number names both accounts' authorities; each side's code names its own first.
  deriveSafetyNumber: vi.fn((_l: Ref, la: string, _p: Ref, pa: string) => Promise.resolve({ fingerprint: `${la}-${pa}`, qrPayload: `qr:${la}:${pa}` })),
  // A scan matches only the peer's own code for this pair.
  safetyQrMatches: vi.fn((_l: Ref, la: string, _p: Ref, pa: string, scanned: string) => Promise.resolve(scanned === `qr:${pa}:${la}`)),
  pinAddress: (pin: Pin) => pin.addresses?.at(-1)?.address,
  // Rust's identity_pins::record, modelled: a new account is pinned with the
  // address it was met at (not on first sight when others were known there);
  // accepted or verified replace the authority; no address is ever written
  // onto an account already pinned.
  recordIdentityPin: vi.fn(
    (current: { list: { pins: Pin[] } }, account: Ref, address: string | undefined, authority: string, update: 'firstSeen' | 'accepted' | 'verified', since: string) => {
      const list = current.list
      const out = (next: Record<string, unknown>, changed: boolean, result: Record<string, unknown>) =>
        Promise.resolve({ pins: { text: JSON.stringify(next), list: next }, changed, result })
      const elsewhere = list.pins.find((pin) => pin.authorityPublicKey === authority && !sameRef(pin.account, account))
      if (elsewhere) return out(list, false, { kind: 'authorityElsewhere', pin: elsewhere })
      const pins = list.pins.map((pin) => ({ ...pin }))
      const i = pins.findIndex((pin) => sameRef(pin.account, account))
      const state = update === 'verified' ? 'verified' : 'seen'
      if (i < 0) {
        const others = address && update === 'firstSeen' ? at(list, address) : []
        if (others.length > 0) return out(list, false, { kind: 'addressHadOthers', pins: others })
        pins.push({ account, authorityPublicKey: authority, state, since, ...(address ? { addresses: [{ address, seenAt: since }] } : {}) })
        pins.sort((a, b) => `${a.account.server}|${a.account.accountId}`.localeCompare(`${b.account.server}|${b.account.accountId}`))
        return out({ ...list, pins }, true, { kind: 'updated' })
      }
      if (update !== 'firstSeen' && address) {
        const others = holders(list, account, address)
        if (others.length > 0) return out(list, false, { kind: 'addressHeldByOthers', pins: others })
      }
      const pin = pins[i]
      if (pin.authorityPublicKey === authority) {
        if (update !== 'verified' || pin.state === 'verified') return out(list, false, { kind: 'unchanged' })
        pins[i] = { ...pin, state: 'verified', since }
        return out({ ...list, pins }, true, { kind: 'updated' })
      }
      if (update === 'firstSeen') return out(list, false, { kind: 'unchanged' })
      const replaced = [...(pin.replaced ?? []).filter((id) => id !== `inc-${authority}`), `inc-${pin.authorityPublicKey}`].slice(-10)
      pins[i] = { ...pin, authorityPublicKey: authority, state, since, replaced }
      return out({ ...list, pins }, true, { kind: 'updated' })
    },
  ),
  // Rust's identity_pins::lookup, modelled.
  lookupIdentityPin: vi.fn((current: { list: { pins: Pin[] } }, account: Ref, address: string | undefined, authority?: string) => {
    const pin = current.list.pins.find((known) => sameRef(known.account, account))
    if (!pin) {
      const others = address ? at(current.list, address) : []
      return Promise.resolve(others.length > 0 ? { kind: 'someoneElse', pins: others } : { kind: 'new' })
    }
    const check = authority === undefined ? 'unknown' : authority === pin.authorityPublicKey ? 'same' : (pin.replaced ?? []).includes(`inc-${authority}`) ? 'earlier' : 'changed'
    return Promise.resolve({ kind: 'pinned', pin, authority: check, others: address ? holders(current.list, account, address) : [], knownAt: Boolean(address && had(pin, address)) })
  }),
  identityPinsAt: vi.fn((current: { list: { pins: Pin[] } }, address: string) => Promise.resolve(at(current.list, address))),
  // Rust's identity_pins::apply_rename, modelled: the chain, signed by the
  // pinned authority, labels the pin; its current address last.
  applyAccountRenameToPins: vi.fn((current: { list: { pins: Pin[] } }, account: Ref, chain: Rename[], since: string) => {
    const pins = current.list.pins.map((pin) => ({ ...pin }))
    const i = pins.findIndex((pin) => sameRef(pin.account, account))
    if (i < 0) return Promise.reject(new Error('no pin for this account'))
    const pin = pins[i]
    let view
    try {
      view = verifyChain(pin.authorityPublicKey, chain)
    } catch (error) {
      return Promise.reject(error instanceof Error ? error : new Error(String(error)))
    }
    const from = pin.addresses?.at(-1)?.address ?? null
    const known = pin.addresses ?? []
    const labels = known.filter((label) => !view.addresses.some((a) => fold(a) === fold(label.address)))
    for (const address of view.addresses) labels.push({ address, seenAt: known.find((l) => fold(l.address) === fold(address))?.seenAt ?? since })
    pins[i] = { ...pin, addresses: labels }
    const list = { ...current.list, pins }
    const changed = JSON.stringify(list) !== JSON.stringify(current.list)
    return Promise.resolve({ pins: { text: JSON.stringify(changed ? list : current.list), list: changed ? list : current.list }, applied: { from, to: view.current, changed } })
  }),
  // Rust's lookup_group and record_group, modelled: a chain continues a pin
  // when the pinned signer is in its line and the anchored list is in place.
  lookupGroupPin: vi.fn((current: { list: { groups?: GroupPinModel[] } }, server: string, groupId: string, chain: { signers: string[]; digests: string[] }) => {
    const pin = (current.list.groups ?? []).find((g) => g.server === server && g.groupId === groupId)
    if (!pin) return Promise.resolve({ kind: 'new' })
    return Promise.resolve({ kind: continues(pin, chain) ? 'same' : 'changed', pin })
  }),
  recordGroupPin: vi.fn((current: { list: { pins: Pin[]; groups?: GroupPinModel[] } }, server: string, groupId: string, chain: { signers: string[]; digests: string[] }, update: string, since: string) => {
    const groups = (current.list.groups ?? []).map((g) => ({ ...g }))
    const fresh = { server, groupId, signerPublicKey: chain.signers.at(-1)!, since, anchor: { sequence: chain.digests.length, digest: chain.digests.at(-1)! } }
    const i = groups.findIndex((g) => g.server === server && g.groupId === groupId)
    if (i < 0) groups.push(fresh)
    else if (continues(groups[i], chain)) groups[i] = { ...groups[i], signerPublicKey: fresh.signerPublicKey, anchor: fresh.anchor }
    else if (update === 'accepted') groups[i] = { ...fresh, replaced: [...(groups[i].replaced ?? []), groups[i].signerPublicKey] }
    const list = { ...current.list, groups }
    const changed = JSON.stringify(list) !== JSON.stringify(current.list)
    return Promise.resolve({ pins: { text: JSON.stringify(changed ? list : current.list), list: changed ? list : current.list }, changed })
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
            envelope: JSON.stringify({ binding: ME_BINDING, revision: 1, list: { pins: [{ account: { server: 'kutup.dev', accountId: 'acct-C' }, authorityPublicKey: 'C', state: 'seen', since: '2026-10-10T00:00:00Z', addresses: [{ address: 'carol@kutup.dev', seenAt: '2026-10-10T00:00:00Z' }] }] } }),
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
  confirmRecipient,
  acceptGroup,
  checkGroup,
  currentAddressOf,
  IdentityNotConfirmed,
  holdsAddress,
  KeysPendingUpgrade,
  MembersPendingUpgrade,
  pendingUpgradeRemoval,
  sealableDriveKey,
  followAccountRenames,
  type AccountAnswer,
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

/**
 * The server's answer for `address`: the account it belongs to (by default
 * the one whose authority it is: `acct-<authority>`) and its keys.
 */
function publish(
  address: string,
  authority: string,
  { bound = true, hpke = `${authority}-hpke`, signing = `${authority}-sign`, id = `acct-${authority}`, suite = 2 } = {},
) {
  server.people.set(address, {
    account: address,
    server: address.split('@')[1],
    accountId: id,
    accountAuthorityPublicKey: authority,
    driveHpkePublicKey: hpke,
    driveSigningPublicKey: signing,
    driveKeyBinding: bound ? `bound-by-${authority}` : undefined,
    identitySuite: suite,
    driveKeyBindingEpoch: 1,
  })
}

/** The stored list, each pin by its account id and its addresses. */
function storedPins(): { id: string; authorityPublicKey: string; state: string; replaced?: string[]; addresses: string[] }[] {
  return (JSON.parse(server.pins!.envelope) as { list: { pins: Pin[] } }).list.pins.map((pin) => ({
    id: pin.account.accountId,
    authorityPublicKey: pin.authorityPublicKey,
    state: pin.state,
    ...(pin.replaced ? { replaced: pin.replaced } : {}),
    addresses: (pin.addresses ?? []).map((label) => label.address),
  }))
}

/** A new page: nothing looked up yet, the pins read again. */
function newPage() {
  const pins = server.pins
  resetIdentityPinsForTesting()
  server.pins = pins
}

beforeEach(() => {
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
  it('pins an account the first time, at the address it was met at, then recognises it', async () => {
    publish('bob@kutup.dev', 'B')
    expect(await checkIdentity(me, 'bob@kutup.dev', { driveSigningPublicKey: 'B-sign' })).toEqual({ kind: 'ok', verified: false })
    expect(storedPins()).toMatchObject([{ id: 'acct-B', authorityPublicKey: 'B', addresses: ['bob@kutup.dev'] }])
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
    server.people.set('eve@kutup.dev', { account: 'eve@kutup.dev', server: 'kutup.dev', accountId: 'acct-E', accountAuthorityPublicKey: 'E', driveHpkePublicKey: 'x', driveSigningPublicKey: 'y', driveKeyBinding: 'bound-by-B', identitySuite: 2, driveKeyBindingEpoch: 1 })
    expect(await checkIdentity(me, 'eve@kutup.dev')).toEqual({ kind: 'invalid' })
    // An incarnation that is not this authority's.
    expect(await checkIdentity(me, 'bob@kutup.dev', { incarnationId: 'inc-OTHER' })).toEqual({ kind: 'invalid' })
    expect(server.pins).toBeNull()
  })

  it('refuses an answer for an account on another server than the address', async () => {
    publish('bob@kutup.dev', 'B')
    server.people.set('bob@kutup.dev', { ...server.people.get('bob@kutup.dev'), server: 'evil.dev' })
    expect(await checkIdentity(me, 'bob@kutup.dev')).toEqual({ kind: 'unknown' })
  })

  it('warns when the account now has another authority (a reset), until accepted', async () => {
    publish('bob@kutup.dev', 'B')
    await checkIdentity(me, 'bob@kutup.dev')
    newPage()
    // Bob's account was reset (same account id), or the server lies.
    publish('bob@kutup.dev', 'B2', { id: 'acct-B' })
    expect(await checkIdentity(me, 'bob@kutup.dev')).toEqual({ kind: 'changed' })
    await acceptIdentity(me, 'bob@kutup.dev')
    expect(storedPins()).toMatchObject([{ id: 'acct-B', authorityPublicKey: 'B2', replaced: ['inc-B'], addresses: ['bob@kutup.dev'] }])
    expect(await checkIdentity(me, 'bob@kutup.dev')).toEqual({ kind: 'ok', verified: false })
  })

  it('says an account that has not signed its keys yet is unproven, and pins nothing', async () => {
    publish('old@kutup.dev', 'O', { bound: false })
    expect(await checkIdentity(me, 'old@kutup.dev')).toEqual({ kind: 'unproven' })
    expect(server.pins).toBeNull()
  })

  it('says an account not on X-Wing keys yet is unproven, even one pinned before, and pins nothing', async () => {
    publish('old@kutup.dev', 'O', { suite: 1 })
    expect(await checkIdentity(me, 'old@kutup.dev')).toEqual({ kind: 'unproven' })
    expect(server.pins).toBeNull()
  })

  it('takes a binding only at the epoch it was signed at', async () => {
    publish('bob@kutup.dev', 'B')
    server.people.set('bob@kutup.dev', { ...server.people.get('bob@kutup.dev')!, driveKeyBindingEpoch: 2 })
    expect(await checkIdentity(me, 'bob@kutup.dev')).toEqual({ kind: 'invalid' })
  })

  it('does not let a server drop the binding of an account already pinned', async () => {
    publish('bob@kutup.dev', 'B')
    await checkIdentity(me, 'bob@kutup.dev')
    newPage()
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
    expect(storedPins().map((p) => p.id)).toEqual(['acct-B', 'acct-C'])
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

  it('writes back what it does not know: later fields', async () => {
    server.pins = { revision: 1, envelope: JSON.stringify({ binding: ME_BINDING, revision: 1, list: { pins: [], laterList: { a: 1 } } }) }
    publish('bob@kutup.dev', 'B')
    await checkIdentity(me, 'bob@kutup.dev')
    const stored = (JSON.parse(server.pins.envelope) as { list: Record<string, unknown> }).list
    expect(stored.laterList).toEqual({ a: 1 })
    expect(storedPins()).toMatchObject([{ id: 'acct-B' }])
  })

  it('refuses keys of an account already pinned handed out for another', async () => {
    publish('bob@kutup.dev', 'B')
    await checkIdentity(me, 'bob@kutup.dev')
    // Eve's account, with Bob's authority.
    publish('eve@kutup.dev', 'B', { id: 'acct-E' })
    expect(await checkIdentity(me, 'eve@kutup.dev')).toEqual({ kind: 'invalid' })
    expect(storedPins()).toHaveLength(1)
  })
})

/** One lookup answer for `address`: the account of `authority`, under the label the server gives. */
function answer(address: string, authority: string, label = address): AccountAnswer {
  return {
    username: label.split('@')[0],
    account: label,
    server: address.split('@')[1],
    accountId: `acct-${authority}`,
    accountIncarnationId: `inc-${authority}`,
    accountAuthorityPublicKey: authority,
    driveHpkePublicKey: `${authority}-hpke`,
    driveSigningPublicKey: `${authority}-sign`,
    driveKeyBinding: `bound-by-${authority}`,
    identitySuite: 2,
    driveKeyBindingEpoch: 1,
  }
}

describe('a share is checked by the address typed, against the one answer it seals to', () => {
  it('stops a pinned person’s address answered with another account under its own label, writing nothing', async () => {
    publish('ada@kutup.dev', 'A')
    await checkIdentity(me, 'ada@kutup.dev')
    newPage()
    const puts = server.puts
    // The server answers ada@ with Mal's account, labelled as Mal.
    const error = await confirmRecipient(me, 'ada@kutup.dev', answer('ada@kutup.dev', 'M', 'mal@kutup.dev')).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(IdentityNotConfirmed)
    expect((error as IdentityNotConfirmed).status.kind).toBe('someoneElse')
    expect(server.puts).toBe(puts)
  })

  it('seals nothing to an account not on X-Wing keys yet: it signs in again first', async () => {
    const error = await confirmRecipient(me, 'old@kutup.dev', { ...answer('old@kutup.dev', 'O'), identitySuite: 1 }).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(KeysPendingUpgrade)
    expect((error as KeysPendingUpgrade).code).toBe('keysPendingUpgrade')
    expect(() => sealableDriveKey('old@kutup.dev', 'key', 1)).toThrow(KeysPendingUpgrade)
    expect(sealableDriveKey('new@kutup.dev', 'key', 2)).toBe('key')
  })

  it('refuses an answer whose incarnation its authority does not name, or on another server', async () => {
    const forged = { ...answer('bob@kutup.dev', 'B'), accountIncarnationId: 'inc-X' }
    await expect(confirmRecipient(me, 'bob@kutup.dev', forged)).rejects.toMatchObject({ status: { kind: 'invalid' } })
    const elsewhere = { ...answer('bob@kutup.dev', 'B'), server: 'other.dev' }
    await expect(confirmRecipient(me, 'bob@kutup.dev', elsewhere)).rejects.toMatchObject({ status: { kind: 'invalid' } })
  })

  it('takes a first-met account and pins it at the typed address', async () => {
    await expect(confirmRecipient(me, 'cat@kutup.dev', answer('cat@kutup.dev', 'C'))).resolves.toEqual({ kind: 'ok', verified: false })
    expect(storedPins()).toMatchObject([{ id: 'acct-C', addresses: ['cat@kutup.dev'] }])
  })
})

describe('an address only finds an account (Signal’s model)', () => {
  it('shows an account found at someone else’s address by its own name, with their notice, and writes nothing', async () => {
    publish('ada@kutup.dev', 'A')
    publish('mal@kutup.dev', 'M')
    await checkIdentity(me, 'ada@kutup.dev')
    await checkIdentity(me, 'mal@kutup.dev')
    newPage()
    const puts = server.puts
    // The server says ada@ is Mal's.
    publish('ada@kutup.dev', 'M')
    expect(await checkIdentity(me, 'ada@kutup.dev')).toEqual({ kind: 'someoneElse', name: 'mal@kutup.dev' })
    await expect(confirmRecipient(me, 'ada@kutup.dev', answer('ada@kutup.dev', 'M'))).rejects.toBeInstanceOf(IdentityNotConfirmed)
    expect(server.puts).toBe(puts)
    expect(storedPins()).toMatchObject([
      { id: 'acct-A', addresses: ['ada@kutup.dev'] },
      { id: 'acct-M', addresses: ['mal@kutup.dev'] },
    ])
  })

  it('a key change through someone else’s address is their notice, never offered to accept', async () => {
    publish('ada@kutup.dev', 'A')
    publish('bob@kutup.dev', 'B')
    await checkIdentity(me, 'ada@kutup.dev')
    await checkIdentity(me, 'bob@kutup.dev')
    newPage()
    // The server says ada@ is Bob's account, with a key it minted.
    publish('ada@kutup.dev', 'EVIL', { id: 'acct-B' })
    expect(await checkIdentity(me, 'ada@kutup.dev')).toEqual({ kind: 'someoneElse', name: 'bob@kutup.dev' })
    await expect(acceptIdentity(me, 'ada@kutup.dev')).rejects.toThrow(/someone else/)
    await expect(verifyPerson(me, 'ada@kutup.dev', 'qr:EVIL:ME')).rejects.toBeInstanceOf(SafetyNumberMismatch)
    expect(storedPins()).toMatchObject([{ id: 'acct-A' }, { id: 'acct-B', authorityPublicKey: 'B' }])
  })

  it('shows an account found at an address nobody known has by its own name, and writes nothing', async () => {
    publish('mal@kutup.dev', 'M')
    await checkIdentity(me, 'mal@kutup.dev')
    newPage()
    const puts = server.puts
    publish('nobody@kutup.dev', 'M')
    expect(await checkIdentity(me, 'nobody@kutup.dev')).toEqual({ kind: 'ok', verified: false, name: 'mal@kutup.dev' })
    expect(server.puts).toBe(puts)
  })

  it('takes a new address of a known account only from its own signed rename chain', async () => {
    publish('ada.l@kutup.dev', 'A')
    await checkIdentity(me, 'ada.l@kutup.dev')
    newPage()
    publish('ada.lovelace@kutup.dev', 'A')
    // A chain its authority did not sign proves nothing: shown by its own name.
    server.renames.set('ada.lovelace@kutup.dev', chains('A', ['ada.l@kutup.dev', 'ada.lovelace@kutup.dev'], { by: 'M' }))
    expect(await checkIdentity(me, 'ada.lovelace@kutup.dev')).toEqual({ kind: 'ok', verified: false, name: 'ada.l@kutup.dev' })
    // Its own chain: a rename, followed.
    newPage()
    server.renames.set('ada.lovelace@kutup.dev', chains('A', ['ada.l@kutup.dev', 'ada.lovelace@kutup.dev']))
    expect(await checkIdentity(me, 'ada.lovelace@kutup.dev')).toEqual({ kind: 'ok', verified: false, formerly: 'ada.l@kutup.dev' })
    expect(storedPins()).toMatchObject([{ id: 'acct-A', addresses: ['ada.l@kutup.dev', 'ada.lovelace@kutup.dev'] }])
  })

  it('a reused name is a new account: someone else, pinned only when accepted', async () => {
    // Alice, met at alice@, renamed to alicia@ (her chain followed).
    publish('alice@kutup.dev', 'A')
    await checkIdentity(me, 'alice@kutup.dev')
    newPage()
    publish('alicia@kutup.dev', 'A')
    server.renames.set('alicia@kutup.dev', chains('A', ['alice@kutup.dev', 'alicia@kutup.dev']))
    await checkIdentity(me, 'alicia@kutup.dev')
    // Mallory, another account, takes alice@.
    newPage()
    publish('alice@kutup.dev', 'X')
    expect(await checkIdentity(me, 'alice@kutup.dev')).toEqual({ kind: 'someoneElse', now: 'alicia@kutup.dev' })
    expect(storedPins().map((p) => p.id)).toEqual(['acct-A'])
    await acceptIdentity(me, 'alice@kutup.dev')
    expect(storedPins()).toMatchObject([{ id: 'acct-A', addresses: ['alice@kutup.dev', 'alicia@kutup.dev'] }, { id: 'acct-X', addresses: ['alice@kutup.dev'] }])
    newPage()
    expect(await checkIdentity(me, 'alice@kutup.dev')).toEqual({ kind: 'ok', verified: false })
    // Alice is still who she was, at her name.
    expect(await checkIdentity(me, 'alicia@kutup.dev')).toEqual({ kind: 'ok', verified: false, formerly: 'alice@kutup.dev' })
  })
})

describe('verifyPerson', () => {
  it('marks a person verified with their scanned safety QR, for every app', async () => {
    publish('bob@kutup.dev', 'B')
    const number = await personSafetyNumber(me, 'bob@kutup.dev')
    expect(number.qrPayload).toBe('qr:ME:B')
    await expect(verifyPerson(me, 'bob@kutup.dev', number.qrPayload)).rejects.toBeInstanceOf(SafetyNumberMismatch)
    await verifyPerson(me, 'bob@kutup.dev', 'qr:B:ME')
    expect(storedPins()).toMatchObject([{ id: 'acct-B', authorityPublicKey: 'B', state: 'verified' }])
    newPage()
    publish('bob@kutup.dev', 'B')
    expect(await checkIdentity(me, 'bob@kutup.dev')).toEqual({ kind: 'ok', verified: true })
  })

  it('accepts a changed identity once it is compared in person', async () => {
    publish('bob@kutup.dev', 'B')
    await checkIdentity(me, 'bob@kutup.dev')
    newPage()
    publish('bob@kutup.dev', 'B2', { id: 'acct-B' })
    expect(await checkIdentity(me, 'bob@kutup.dev')).toEqual({ kind: 'changed' })
    await verifyPerson(me, 'bob@kutup.dev', 'qr:B2:ME')
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
  /** Ada met as ada.l, pinned; then renamed: the old name held (not found here). */
  async function metAda() {
    publish('ada.l@kutup.dev', 'A')
    expect(await checkIdentity(me, 'ada.l@kutup.dev')).toEqual({ kind: 'ok', verified: false })
    server.people.clear()
    publish('ada.lovelace@kutup.dev', 'A')
    newPage()
  }

  it('finds a pin in any spelling of its address', async () => {
    publish('ada.l@kutup.dev', 'A')
    await checkIdentity(me, 'ada.l@kutup.dev')
    publish('Ada_L@kutup.dev', 'A')
    expect((await checkIdentity(me, 'Ada_L@kutup.dev')).kind).toBe('ok')
    expect(storedPins()).toHaveLength(1)
  })

  it('says where someone pinned at a name they left is now, labelling their pin', async () => {
    await metAda()
    server.renames.set('ada.l@kutup.dev', chains('A', ['ada.l@kutup.dev', 'ada.lovelace@kutup.dev']))
    expect(await checkIdentity(me, 'ada.l@kutup.dev')).toEqual({ kind: 'renamed', now: 'ada.lovelace@kutup.dev', verified: false })
    expect(storedPins()).toMatchObject([{ id: 'acct-A', authorityPublicKey: 'A', addresses: ['ada.l@kutup.dev', 'ada.lovelace@kutup.dev'] }])
    newPage()
    expect(await checkIdentity(me, 'ada.lovelace@kutup.dev')).toEqual({ kind: 'ok', verified: false, formerly: 'ada.l@kutup.dev' })
  })

  it('never follows a chain its authority did not sign, nor an unknown format', async () => {
    await metAda()
    server.renames.set('ada.l@kutup.dev', chains('A', ['ada.l@kutup.dev', 'mallory@kutup.dev'], { by: 'M' }))
    expect(await checkIdentity(me, 'ada.l@kutup.dev')).toEqual({ kind: 'unknown' })
    server.renames.set('ada.l@kutup.dev', chains('A', ['ada.l@kutup.dev', 'ada.lovelace@kutup.dev'], { version: 2 }))
    newPage()
    expect(await checkIdentity(me, 'ada.l@kutup.dev')).toEqual({ kind: 'unknown' })
    expect(storedPins()).toMatchObject([{ id: 'acct-A', addresses: ['ada.l@kutup.dev'] }])
  })

  it('keeps the pin when the server cannot say, or names another authority', async () => {
    await metAda()
    server.renames.set('ada.l@kutup.dev', { version: 1, chains: [], unavailable: true })
    expect(await checkIdentity(me, 'ada.l@kutup.dev')).toEqual({ kind: 'unknown' })
    server.renames.set('ada.l@kutup.dev', chains('M', ['ada.l@kutup.dev', 'mallory@kutup.dev']))
    newPage()
    expect(await checkIdentity(me, 'ada.l@kutup.dev')).toEqual({ kind: 'unknown' })
    expect(storedPins()).toMatchObject([{ id: 'acct-A', addresses: ['ada.l@kutup.dev'] }])
  })

  it('follows a federated 409 renamed for a pinned person', async () => {
    publish('bob@other.dev', 'B')
    await checkIdentity(me, 'bob@other.dev')
    server.people.clear()
    newPage()
    server.heldNames.set('bob@other.dev', chains('B', ['bob@other.dev', 'robert@other.dev']))
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
  const ref = (authority: string) => ({ server: 'kutup.dev', accountId: `acct-${authority}` })

  async function met(address: string, authority: string) {
    publish(address, authority)
    await checkIdentity(me, address)
  }

  it('says pinned, changed or unknown for an account', async () => {
    await met('bob@kutup.dev', 'B')
    expect(await pinnedVerdict(me, ref('B'), 'bob@kutup.dev', 'B')).toEqual({ kind: 'pinned' })
    expect(await pinnedVerdict(me, ref('B'), 'bob@kutup.dev', 'M')).toEqual({ kind: 'changed' })
    expect(await pinnedVerdict(me, ref('C'), 'carol@kutup.dev', 'C')).toEqual({ kind: 'unknown' })
  })

  it('names someone else before any key change at their address', async () => {
    await met('ada@kutup.dev', 'A')
    await met('bob@kutup.dev', 'B')
    expect(await pinnedVerdict(me, ref('B'), 'ada@kutup.dev', 'EVIL')).toEqual({ kind: 'someoneElse' })
  })

  it('gives a pinned account found at another address its own name', async () => {
    await met('bob@kutup.dev', 'B')
    expect(await pinnedVerdict(me, ref('B'), 'robert@kutup.dev', 'B')).toEqual({ kind: 'pinned', name: 'bob@kutup.dev' })
  })

  it('refuses someone else at an address a known person holds, naming where they are when they moved on', async () => {
    await met('ada_l@kutup.dev', 'A')
    expect(await pinnedVerdict(me, ref('M'), 'ada_l@kutup.dev', 'M')).toEqual({ kind: 'someoneElse' })
    // Ada's rename followed; Mallory at her old name.
    newPage()
    publish('ada_lovelace@kutup.dev', 'A')
    server.renames.set('ada_lovelace@kutup.dev', chains('A', ['ada_l@kutup.dev', 'ada_lovelace@kutup.dev']))
    await checkIdentity(me, 'ada_lovelace@kutup.dev')
    expect(await pinnedVerdict(me, ref('M'), 'ada_l@kutup.dev', 'M')).toEqual({ kind: 'someoneElse', now: 'ada_lovelace@kutup.dev' })
    expect(await pinnedVerdict(me, ref('A'), 'ada_lovelace@kutup.dev', 'A')).toEqual({ kind: 'pinned' })
  })

  it('names where an old address’s account is now', async () => {
    server.renames.set('ada_l@kutup.dev', chains('A', ['ada_l@kutup.dev', 'ada_lovelace@kutup.dev']))
    expect(await currentAddressOf('ada_l@kutup.dev', 'A')).toBe('ada_lovelace@kutup.dev')
    expect(await currentAddressOf('ada_l@kutup.dev', 'M')).toBe('ada_l@kutup.dev')
    expect(await currentAddressOf('grace@kutup.dev', 'G')).toBe('grace@kutup.dev')
  })
})

describe('shared mailboxes (Mail’s key checks)', () => {
  const group = '2b3c4d5e-6f70-4182-93a4-b5c6d7e8f901'
  const storedGroups = () => (JSON.parse(server.pins!.envelope) as { list: { groups?: GroupPinModel[] } }).list.groups ?? []

  it('pins a mailbox’s signer on first use and follows its own line', async () => {
    expect(await checkGroup(me, 'kutup.dev', group, { signers: ['S1'], digests: ['d1', 'd2'] })).toEqual({ kind: 'new' })
    expect(storedGroups()).toMatchObject([{ groupId: group, signerPublicKey: 'S1', anchor: { sequence: 2, digest: 'd2' } }])
    // Handed over to a new signer and extended: the same mailbox.
    expect(await checkGroup(me, 'kutup.dev', group, { signers: ['S1', 'S2'], digests: ['d1', 'd2', 'd3'] })).toEqual({ kind: 'pinned' })
    expect(storedGroups()).toMatchObject([{ signerPublicKey: 'S2', anchor: { sequence: 3 } }])
  })

  it('says changed for a restarted chain, a rollback, or the old signer after its handover, until accepted', async () => {
    await checkGroup(me, 'kutup.dev', group, { signers: ['S1', 'S2'], digests: ['d1', 'd2', 'd3'] })
    const puts = server.puts
    for (const chain of [
      { signers: ['ADMIN'], digests: ['x1'] },
      { signers: ['S1', 'S2'], digests: ['d1', 'd2'] },
      { signers: ['S1'], digests: ['d1', 'd2', 'o3'] },
    ]) {
      expect(await checkGroup(me, 'kutup.dev', group, chain)).toEqual({ kind: 'changed' })
    }
    expect(server.puts).toBe(puts)
    await acceptGroup(me, 'kutup.dev', group, { signers: ['ADMIN'], digests: ['x1'] })
    expect(storedGroups()).toMatchObject([{ signerPublicKey: 'ADMIN', replaced: ['S2'] }])
    expect(await checkGroup(me, 'kutup.dev', group, { signers: ['ADMIN'], digests: ['x1'] })).toEqual({ kind: 'pinned' })
  })
})

describe('followAccountRenames (Chat\'s rename line)', () => {
  const ADA = { server: 'kutup.dev', accountId: 'acct-A' }
  /** Ada's chain from ada.l to `to`, each step signed `by` at `at` (ms). */
  function chainAt(to: string[], at: number, by = 'A') {
    const addresses = ['ada.l@kutup.dev', ...to]
    const steps = chainOf('A', addresses, by).map((step) => ({ ...step, issuedAtMs: at }))
    return { version: 1, chains: [{ incarnationId: 'inc-A', authorityPublicKey: 'A', current: addresses.at(-1)!, state: 'current', chain: steps }] }
  }

  async function metAda() {
    publish('ada.l@kutup.dev', 'A')
    await checkIdentity(me, 'ada.l@kutup.dev')
    newPage()
  }

  it('follows the pinned account along its own chain and tells the renames since it was met', async () => {
    await metAda()
    server.renames.set('ada.lovelace@kutup.dev', chainAt(['ada.lovelace@kutup.dev'], Date.now() + 60_000))
    expect(await followAccountRenames(me, ADA, 'ada.lovelace@kutup.dev')).toEqual([
      { from: 'ada.l@kutup.dev', to: 'ada.lovelace@kutup.dev', sequence: 1, issuedAtMs: expect.any(Number) as number },
    ])
    expect(storedPins()).toMatchObject([{ id: 'acct-A', addresses: ['ada.l@kutup.dev', 'ada.lovelace@kutup.dev'] }])
    // Already there: nothing more, and nothing asked.
    server.renames.clear()
    expect(await followAccountRenames(me, ADA, 'ada.lovelace@kutup.dev')).toEqual([])
  })

  it('tells nothing of a rename from before it was met (the chain is still followed)', async () => {
    await metAda()
    server.renames.set('ada.lovelace@kutup.dev', chainAt(['ada.lovelace@kutup.dev'], Date.parse('2020-01-01T00:00:00Z')))
    expect(await followAccountRenames(me, ADA, 'ada.lovelace@kutup.dev')).toEqual([])
    expect(storedPins()).toMatchObject([{ id: 'acct-A', addresses: ['ada.l@kutup.dev', 'ada.lovelace@kutup.dev'] }])
  })

  it('never follows a chain another authority signed, or one ending elsewhere, or an account not pinned', async () => {
    await metAda()
    const puts = server.puts
    server.renames.set('ada.lovelace@kutup.dev', chainAt(['ada.lovelace@kutup.dev'], Date.now() + 60_000, 'M'))
    expect(await followAccountRenames(me, ADA, 'ada.lovelace@kutup.dev')).toEqual([])
    server.renames.set('ada.lovelace@kutup.dev', chainAt(['ada.other@kutup.dev'], Date.now() + 60_000))
    expect(await followAccountRenames(me, ADA, 'ada.lovelace@kutup.dev')).toEqual([])
    expect(await followAccountRenames(me, { server: 'kutup.dev', accountId: 'acct-Z' }, 'zed@kutup.dev')).toEqual([])
    expect(server.puts).toBe(puts)
    expect(storedPins()).toMatchObject([{ id: 'acct-A', addresses: ['ada.l@kutup.dev'] }])
  })

  it('follows a pin Chat hasn\'t written yet against its own authority, leaving the list as it is', async () => {
    const met = new Date(Date.now() - 60_000).toISOString()
    server.renames.set('ada.lovelace@kutup.dev', chainAt(['ada.lovelace@kutup.dev'], Date.now()))
    const puts = server.puts
    expect(await followAccountRenames(me, ADA, 'ada.lovelace@kutup.dev', { authorityPublicKey: 'A', since: met })).toEqual([
      { from: 'ada.l@kutup.dev', to: 'ada.lovelace@kutup.dev', sequence: 1, issuedAtMs: expect.any(Number) as number },
    ])
    expect(server.puts).toBe(puts)
    // Another authority's chain, or a rename from before the meeting: nothing.
    expect(await followAccountRenames(me, ADA, 'ada.lovelace@kutup.dev', { authorityPublicKey: 'M', since: met })).toEqual([])
    expect(
      await followAccountRenames(me, ADA, 'ada.lovelace@kutup.dev', { authorityPublicKey: 'A', since: new Date(Date.now() + 60_000).toISOString() }),
    ).toEqual([])
  })
})

describe('this account is itself by its id, never by an address', () => {
  it('treats its own address as self only while the answer is this account', async () => {
    publish('me@kutup.dev', 'ME', { id: 'me-id' })
    expect(await checkIdentity(me, 'me@kutup.dev')).toEqual({ kind: 'ok', verified: true })
  })

  it('its old address, now held by another account, is that account (a tab open since the rename)', async () => {
    // The session still names me@ as its own address; the server says
    // someone else has it now.
    publish('me@kutup.dev', 'X', { id: 'acct-X' })
    const status = await checkIdentity(me, 'me@kutup.dev')
    expect(status).not.toEqual({ kind: 'ok', verified: true })
    expect(status).toEqual({ kind: 'ok', verified: false })
    expect(storedPins()).toMatchObject([{ id: 'acct-X', addresses: ['me@kutup.dev'] }])
  })
})

describe('holdsAddress (a saved contact belongs to an account only when it holds the address)', () => {
  it('is the pinned holder, never someone who took the name', async () => {
    publish('ada@kutup.dev', 'A')
    await checkIdentity(me, 'ada@kutup.dev')
    expect(await holdsAddress(me, { server: 'kutup.dev', accountId: 'acct-A' }, 'ada@kutup.dev')).toBe(true)
    // Mallory at Ada's (left) name: pinned or not, not the holder.
    newPage()
    publish('ada@kutup.dev', 'M', { id: 'acct-M' })
    await checkIdentity(me, 'ada@kutup.dev')
    expect(await holdsAddress(me, { server: 'kutup.dev', accountId: 'acct-M' }, 'ada@kutup.dev')).toBe(false)
    expect(await holdsAddress(me, { server: 'kutup.dev', accountId: 'acct-Z' }, 'zed@kutup.dev')).toBe(false)
  })
})

describe('a removal and the people not yet upgraded (docs/plans/pq-shares.md)', () => {
  const kept = {
    members: [
      { id: 'u1', account: 'new@kutup.dev', identitySuite: 2 },
      { id: 'u2', account: 'old@kutup.dev', identitySuite: 1 },
    ],
    federatedShares: [{ id: 'f1', account: 'far@other.example', identitySuite: 1 }],
  }

  it('names them before anything is removed', () => {
    const error = (() => {
      try {
        pendingUpgradeRemoval(kept, undefined)
      } catch (e) {
        return e
      }
    })()
    expect(error).toBeInstanceOf(MembersPendingUpgrade)
    expect((error as MembersPendingUpgrade).accounts).toEqual(['old@kutup.dev', 'far@other.example'])
    expect((error as MembersPendingUpgrade).removal).toEqual({ members: ['u2'], federatedShares: ['f1'] })
  })

  it('takes them along once the owner confirmed exactly them', () => {
    expect(pendingUpgradeRemoval(kept, { members: ['u2'], federatedShares: ['f1'] })).toEqual({ members: ['u2'], federatedShares: ['f1'] })
  })

  it('asks again when someone else turned up since, and takes nobody who upgraded since', () => {
    expect(() => pendingUpgradeRemoval(kept, { members: ['u2'], federatedShares: [] })).toThrow(MembersPendingUpgrade)
    const upgraded = { members: kept.members.filter((m) => m.id !== 'u2'), federatedShares: [] }
    expect(pendingUpgradeRemoval(upgraded, { members: ['u2'], federatedShares: ['f1'] })).toEqual({ members: [], federatedShares: [] })
  })
})
