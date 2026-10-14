import { createHash } from 'node:crypto'
import { AxiosError, AxiosHeaders, type AxiosResponse } from 'axios'
import { describe, expect, it, vi } from 'vitest'
import type { AccountHeadValue, HeadAnchor, HeadIndex, HeadScope, HeadStatus, LocalHeadState, Reanchored } from '@kutup/crypto/accountHead'
import { memoryRevisionStore } from '@kutup/crypto/revisionGuard'
import {
  AccountHeadClient,
  HeadBlockedError,
  IndexMismatchError,
  NotInVerifiedIndexError,
  VerifiedIndex,
  type HeadEngine,
  type VerifiedHeadLike,
} from './accountHead'

// A stand-in for the Rust head with its rules kept small: heads are base64
// JSON, chained by SHA-256; the real checks are Rust's, tested with vectors.

interface FakeHead {
  sequence: number
  previous: string | null
  writer: string
  scopes: HeadScope[]
}

const seal = (head: FakeHead) => Buffer.from(JSON.stringify(head)).toString('base64')
const unseal = (sealed: string) => JSON.parse(Buffer.from(sealed, 'base64').toString()) as FakeHead
const digest = (sealed: string) => createHash('sha256').update(Buffer.from(sealed, 'base64')).digest('hex')
const anchorOf = (sealed: string): HeadAnchor => ({ sequence: unseal(sealed).sequence, digest: digest(sealed) })

/** A verified head: its sealed bytes; counted while alive, to catch leaks and use after free. */
let alive = 0
class FakeVerified implements VerifiedHeadLike {
  private freed = false
  constructor(readonly sealed: string) {
    alive++
  }
  private live(): void {
    if (this.freed) throw new Error('used after free')
  }
  get anchor(): HeadAnchor {
    this.live()
    return anchorOf(this.sealed)
  }
  get head(): AccountHeadValue {
    this.live()
    return unseal(this.sealed) as unknown as AccountHeadValue
  }
  copy(): FakeVerified {
    this.live()
    return new FakeVerified(this.sealed)
  }
  free(): void {
    this.live()
    this.freed = true
    alive--
  }
}

class FakeEngine implements HeadEngine {
  constructor(readonly name = 'incarnation-a') {}
  writer = (device: string) => `w:${device}`
  scope = (scope: string, index: HeadIndex): HeadScope => ({ scope, count: index.length, digest: JSON.stringify([...index].sort()) })
  /** Runs before a check returns: a test's chance to change what the server shows. */
  onCheck: (() => void) | null = null
  check(anchor: HeadAnchor | null, current: string, segment: readonly string[] | null): { status: HeadStatus; verified: VerifiedHeadLike | null } {
    this.onCheck?.()
    const head = unseal(current)
    let kind: HeadStatus['kind']
    if (!anchor) kind = 'fresh'
    else if (digest(current) === anchor.digest) kind = 'current'
    else if (head.sequence < anchor.sequence) kind = 'rollback'
    else if (segment && segment.length > 0 && digest(segment[0]!) === anchor.digest && segment.at(-1) === current) kind = 'extends'
    else if (segment === null && head.sequence - anchor.sequence > 1000) kind = 'tooOld'
    else kind = 'fork'
    const trusted = kind === 'fresh' || kind === 'current' || kind === 'extends'
    return { status: { kind }, verified: trusted ? new FakeVerified(current) : null }
  }
  reanchor(anchor: HeadAnchor, current: string, segment: readonly string[] | null, confirmed: boolean, atMs: number) {
    const { status, verified } = this.check(anchor, current, segment)
    verified?.free()
    if (status.kind !== 'tooOld' && !confirmed) throw new Error('needs the person')
    return { record: { from: anchor, to: anchorOf(current), status, atMs } as Reanchored, verified: new FakeVerified(current) }
  }
  checkIndex(verified: VerifiedHeadLike, scope: string, index: HeadIndex): 'matches' | 'uncovered' {
    const entry = unseal((verified as FakeVerified).sealed).scopes.find((s) => s.scope === scope)
    if (!entry) return 'uncovered'
    if (entry.digest !== this.scope(scope, index).digest) throw new Error('differs')
    return 'matches'
  }
  next(verified: VerifiedHeadLike, writer: string, scopes: readonly HeadScope[]): string {
    const base = (verified as FakeVerified).sealed
    const before = unseal(base)
    const kept = before.scopes.filter((s) => !scopes.some((n) => n.scope === s.scope))
    return seal({ sequence: before.sequence + 1, previous: digest(base), writer, scopes: [...kept, ...scopes] })
  }
  first = (writer: string, scopes: readonly HeadScope[]) => seal({ sequence: 1, previous: null, writer, scopes: [...scopes] })
  committed(verified: VerifiedHeadLike | null, sealed: string): VerifiedHeadLike {
    const head = unseal(sealed)
    if (verified ? head.previous !== digest((verified as FakeVerified).sealed) : head.sequence !== 1) throw new Error('does not follow')
    return new FakeVerified(sealed)
  }
  localStateName = () => this.name
  newLocalState = (): LocalHeadState => ({ incarnationId: this.name, deviceId: 'dev-1', anchor: null, anchoredAtMs: 0, log: [] })
  openLocalState(sealed: string): LocalHeadState {
    const state = JSON.parse(sealed) as LocalHeadState
    if (state.incarnationId !== this.name) throw new Error('another incarnation')
    return state
  }
  sealLocalState = (state: LocalHeadState) => JSON.stringify(state)
  advanceLocalState(state: LocalHeadState, verified: VerifiedHeadLike, atMs: number) {
    const anchor = verified.anchor
    if (state.anchor && state.anchor.sequence >= anchor.sequence) return { state, changed: false }
    const log = state.anchor ? state.log : [...state.log, { kind: 'startedFresh' as const, anchor, atMs }]
    return { state: { ...state, anchor, anchoredAtMs: atMs, log }, changed: true }
  }
  reanchoredLocalState = (state: LocalHeadState, record: Reanchored, _verified: VerifiedHeadLike): LocalHeadState => ({
    ...state,
    anchor: record.to,
    anchoredAtMs: record.atMs,
    log: [...state.log, { kind: 'reanchored', record }],
  })
  forgottenLocalState = (state: LocalHeadState, atMs: number): LocalHeadState => ({
    ...state,
    anchor: null,
    anchoredAtMs: atMs,
    log: state.anchor ? [...state.log, { kind: 'forgotten', from: state.anchor, atMs }] : state.log,
  })
  close = vi.fn()
}

/** A chain of `n` heads by another device, each adding a contact. */
function chain(n: number, writer = 'w:other'): string[] {
  const heads: string[] = []
  for (let i = 1; i <= n; i++) {
    heads.push(
      seal({
        sequence: i,
        previous: i === 1 ? null : digest(heads[i - 2]!),
        writer,
        scopes: [{ scope: 'contacts', count: i, digest: String(i) }],
      }),
    )
  }
  return heads
}

function conflict409(code: string): AxiosError {
  return refused(409, code)
}

/** A server whose index and head come from `state()`; its chain is every head it has shown. */
function server2(state: () => { head: string; values: [string, number][] }) {
  const all: string[] = []
  const shown = () => {
    const { head } = state()
    if (!all.includes(head)) all.push(head)
    return state()
  }
  const routes: Record<string, Route> = {
    'GET /account/index/contacts': () => ({ head: shown().head, values: shown().values, basis: null }),
    'GET /account/head': () => ({ head: shown().head }),
  }
  for (let from = 1; from <= 10; from++) {
    routes[`GET /account/heads?from=${from}`] = () => ({ heads: all.filter((head) => unseal(head).sequence >= from), next: null })
  }
  return server(routes)
}

function refused(status: number, code?: string): AxiosError {
  const response = { status, data: code ? { error: 'x', code } : { error: 'x' }, headers: {}, config: { headers: new AxiosHeaders() }, statusText: '' } as AxiosResponse
  return new AxiosError('refused', String(status), undefined, undefined, response)
}

type Route = (body?: unknown) => unknown
function server(routes: Record<string, Route>) {
  const calls: Array<[string, string, unknown?]> = []
  const answer = (method: string, url: string, body?: unknown) => {
    calls.push([method, url, body])
    const route = routes[`${method} ${url}`]
    if (!route) return Promise.reject(new Error(`no route ${method} ${url}`))
    try {
      return Promise.resolve({ data: route(body) })
    } catch (error) {
      return Promise.reject(error)
    }
  }
  return {
    calls,
    http: {
      get: <T,>(url: string) => answer('GET', url) as Promise<{ data: T }>,
      post: <T,>(url: string, body: unknown) => answer('POST', url, body) as Promise<{ data: T }>,
    },
  }
}

async function remembering(engine: FakeEngine, store: ReturnType<typeof memoryRevisionStore>, sealed: string) {
  const anchor = anchorOf(sealed)
  await store.put(`account-head:${engine.name}`, JSON.stringify({ ...engine.newLocalState(), anchor, anchoredAtMs: 1 }))
}

async function stateIn(engine: FakeEngine, store: ReturnType<typeof memoryRevisionStore>): Promise<LocalHeadState> {
  return JSON.parse((await store.get(`account-head:${engine.name}`))!) as LocalHeadState
}

describe('reading the head', () => {
  it('trusts the first head on first use, and logs that it started fresh', async () => {
    const heads = chain(2)
    const engine = new FakeEngine()
    const store = memoryRevisionStore()
    const { http } = server({ 'GET /account/head': () => ({ head: heads[1] }) })
    const client = new AccountHeadClient(engine, store, http, () => 100)
    await client.verifiedHead()
    expect(client.current()).toEqual({ kind: 'trusted', notice: null })
    const state = await stateIn(engine, store)
    expect(state.anchor?.sequence).toBe(2)
    expect(state.log).toEqual([{ kind: 'startedFresh', anchor: anchorOf(heads[1]!), atMs: 100 }])
  })

  it('follows a later head through every page of the chain', async () => {
    const heads = chain(3)
    const engine = new FakeEngine()
    const store = memoryRevisionStore()
    await remembering(engine, store, heads[0]!)
    const { http, calls } = server({
      'GET /account/head': () => ({ head: heads[2] }),
      'GET /account/heads?from=1': () => ({ heads: heads.slice(0, 2), next: 3 }),
      'GET /account/heads?from=3': () => ({ heads: [heads[2]], next: null }),
    })
    const client = new AccountHeadClient(engine, store, http)
    await client.verifiedHead()
    expect(client.current().kind).toBe('trusted')
    expect((await stateIn(engine, store)).anchor?.sequence).toBe(3)
    expect(calls.map(([, url]) => url)).toEqual(['/account/head', '/account/heads?from=1', '/account/heads?from=3'])
  })

  it('asks for no chain when the head is the one remembered', async () => {
    const heads = chain(2)
    const engine = new FakeEngine()
    const store = memoryRevisionStore()
    await remembering(engine, store, heads[1]!)
    const { http, calls } = server({ 'GET /account/head': () => ({ head: heads[1] }) })
    await new AccountHeadClient(engine, store, http).verifiedHead()
    expect(calls).toHaveLength(1)
  })

  it('a rollback blocks listed writes until the person continues, which is logged', async () => {
    const heads = chain(3)
    const engine = new FakeEngine()
    const store = memoryRevisionStore()
    await remembering(engine, store, heads[2]!)
    const { http, calls } = server({
      'GET /account/head': () => ({ head: heads[1] }),
      'GET /account/heads?from=3': () => ({ heads: [], next: null }),
      'GET /account/index/pins': () => ({ head: heads[1], values: [], basis: null }),
    })
    const client = new AccountHeadClient(engine, store, http, () => 500)
    const seen: string[] = []
    client.subscribe((condition) => seen.push(condition.kind))
    await expect(client.verifiedHead()).rejects.toEqual(new HeadBlockedError('rollback'))
    expect(client.current()).toEqual({ kind: 'blocked', reason: 'rollback' })
    // Nothing is sent while blocked.
    const before = calls.length
    await expect(client.listedWrite('pins', () => Promise.reject(new Error('not reached')))).rejects.toBeInstanceOf(HeadBlockedError)
    expect(calls).toHaveLength(before)
    await client.continueWithServer()
    expect(client.current().kind).toBe('trusted')
    const state = await stateIn(engine, store)
    expect(state.anchor?.sequence).toBe(2)
    expect(state.log.at(-1)).toMatchObject({ kind: 'reanchored', record: { status: { kind: 'rollback' }, atMs: 500 } })
    expect(seen).toEqual(['unknown', 'blocked', 'trusted'])
  })

  it('a fork blocks too', async () => {
    const mine = chain(2, 'w:dev-1')
    const theirs = chain(3)
    const engine = new FakeEngine()
    const store = memoryRevisionStore()
    await remembering(engine, store, mine[1]!)
    const { http } = server({
      'GET /account/head': () => ({ head: theirs[2] }),
      'GET /account/heads?from=2': () => ({ heads: theirs.slice(1), next: null }),
    })
    const client = new AccountHeadClient(engine, store, http)
    await expect(client.verifiedHead()).rejects.toEqual(new HeadBlockedError('fork'))
  })

  it('a server with no head, though one was remembered, blocks; continuing forgets it, logged', async () => {
    const heads = chain(2)
    const engine = new FakeEngine()
    const store = memoryRevisionStore()
    await remembering(engine, store, heads[1]!)
    const { http } = server({ 'GET /account/head': () => ({ head: null }) })
    const client = new AccountHeadClient(engine, store, http, () => 9)
    await expect(client.verifiedHead()).rejects.toEqual(new HeadBlockedError('rollback'))
    await client.continueWithServer()
    const state = await stateIn(engine, store)
    expect(state.anchor).toBeNull()
    expect(state.log.at(-1)).toEqual({ kind: 'forgotten', from: anchorOf(heads[1]!), atMs: 9 })
  })

  it('an anchor further back than the server keeps re-anchors with a notice, never blocking', async () => {
    const heads = chain(1)
    const far = seal({ sequence: 1500, previous: 'x', writer: 'w:other', scopes: [] })
    const engine = new FakeEngine()
    const store = memoryRevisionStore()
    await remembering(engine, store, heads[0]!)
    const { http } = server({
      'GET /account/head': () => ({ head: far }),
      'GET /account/heads?from=1': () => {
        throw refused(410, 'tooOld')
      },
    })
    const client = new AccountHeadClient(engine, store, http)
    await client.verifiedHead()
    expect(client.current()).toEqual({ kind: 'trusted', notice: 'tooOld' })
    expect((await stateIn(engine, store)).anchor?.sequence).toBe(1500)
    client.dismissNotice()
    expect(client.current()).toEqual({ kind: 'trusted', notice: null })
  })

  it('a stored state that does not open is a fresh device', async () => {
    const heads = chain(1)
    const engine = new FakeEngine()
    const store = memoryRevisionStore()
    await store.put('account-head:incarnation-a', '{"incarnationId":"incarnation-b"}')
    const { http } = server({ 'GET /account/head': () => ({ head: heads[0] }) })
    await new AccountHeadClient(engine, store, http).verifiedHead()
    expect((await stateIn(engine, store)).log[0]?.kind).toBe('startedFresh')
  })

  it('two incarnations keep apart', async () => {
    const heads = chain(2)
    const store = memoryRevisionStore()
    const before = new FakeEngine('incarnation-a')
    await remembering(before, store, heads[1]!)
    const after = new FakeEngine('incarnation-b')
    const { http } = server({ 'GET /account/head': () => ({ head: chain(1)[0] }) })
    // A new incarnation compares with nothing it remembered before: fresh.
    await new AccountHeadClient(after, store, http).verifiedHead()
    expect((await stateIn(after, store)).anchor?.sequence).toBe(1)
    expect((await stateIn(before, store)).anchor?.sequence).toBe(2)
  })
})

describe('indexes', () => {
  it('checks an index against the head it came with; a difference is refused', async () => {
    const engine = new FakeEngine()
    const store = memoryRevisionStore()
    const head = seal({ sequence: 1, previous: null, writer: 'w:other', scopes: [engine.scope('pins', [['pins', 5]])] })
    let values: [string, number][] = [['pins', 5]]
    const { http } = server({ 'GET /account/index/pins': () => ({ head, values, basis: null }) })
    const client = new AccountHeadClient(engine, store, http)
    const index = await client.verifiedIndex('pins')
    expect(index.covered).toBe(true)
    expect(index.revision('pins')).toBe(5)
    values = [['pins', 4]]
    await expect(client.verifiedIndex('pins')).rejects.toEqual(new IndexMismatchError('pins'))
  })

  it('a scope the server keeps no index of is uncovered', async () => {
    const engine = new FakeEngine()
    const { http } = server({
      'GET /account/index/settings': () => {
        throw refused(404)
      },
      'GET /account/head': () => ({ head: null }),
    })
    const index = await new AccountHeadClient(engine, memoryRevisionStore(), http).verifiedIndex('settings')
    expect(index.covered).toBe(false)
  })

  it('refuses a value or a listing the covered index does not vouch for', () => {
    const index = new VerifiedIndex('contacts', true, [['a', 1], ['b', 2]], null)
    index.expect('a', 1)
    expect(() => index.expect('a', 0)).toThrow(NotInVerifiedIndexError)
    expect(() => index.expect('c', 1)).toThrow(NotInVerifiedIndexError)
    index.expectListing(['b', 'a'])
    expect(() => index.expectListing(['a'])).toThrow(NotInVerifiedIndexError)
    expect(() => index.expectListing(['a', 'b', 'c'])).toThrow(NotInVerifiedIndexError)
    expect(() => index.expectListing(['a', 'a'])).toThrow(NotInVerifiedIndexError)
    // Uncovered: nothing to hold it to yet.
    new VerifiedIndex('contacts', false, [], null).expectListing(['x'])
    // One kind of a scope that holds several.
    const names = new VerifiedIndex('mailNames', true, [['folder:a', 1], ['label:b', 2], ['folder:c', 3]], null)
    names.expectListing(['folder:c', 'folder:a'], 'folder:')
    names.expectListing(['label:b'], 'label:')
    names.expectListing([], 'filter:')
    expect(() => names.expectListing(['folder:a'], 'folder:')).toThrow(NotInVerifiedIndexError)
    expect(() => names.expectListing(['folder:a', 'folder:c', 'label:b'], 'folder:')).toThrow(NotInVerifiedIndexError)
  })
})

describe('listed writes', () => {
  it('starts the chain on the index basis, then sends the write with the next head', async () => {
    const engine = new FakeEngine()
    const store = memoryRevisionStore()
    const sent: string[] = []
    const { http, calls } = server({
      'GET /account/index/pins': () => ({ head: null, values: [['pins', 5]], basis: 'basis-1' }),
      'POST /account/head': () => ({}),
    })
    const client = new AccountHeadClient(engine, store, http)
    const result = await client.listedWrite('pins', async (index) => {
      expect(index.revision('pins')).toBe(5)
      return {
        changes: [['pins', 6]],
        send: (head) => {
          sent.push(head)
          return Promise.resolve('stored')
        },
      }
    })
    expect(result).toBe('stored')
    const start = calls.find(([method]) => method === 'POST')![2] as { head: string; basis: string }
    expect(start.basis).toBe('basis-1')
    expect(unseal(start.head)).toMatchObject({ sequence: 1, writer: 'w:dev-1', scopes: [engine.scope('pins', [['pins', 5]])] })
    expect(unseal(sent[0]!)).toMatchObject({ sequence: 2, previous: digest(start.head), scopes: [engine.scope('pins', [['pins', 6]])] })
    expect((await stateIn(engine, store)).anchor).toEqual(anchorOf(sent[0]!))
  })

  it('redoes the edit when another device wrote first, and gives up after five tries', async () => {
    const engine = new FakeEngine()
    const store = memoryRevisionStore()
    const head = seal({ sequence: 1, previous: null, writer: 'w:other', scopes: [] })
    const { http } = server({ 'GET /account/index/pins': () => ({ head, values: [['pins', 5]], basis: null }) })
    const client = new AccountHeadClient(engine, store, http)
    let edits = 0
    await expect(
      client.listedWrite('pins', async () => {
        edits++
        return { changes: [['pins', 6]], send: () => Promise.reject(refused(409, edits < 3 ? 'head_conflict' : 'revision_conflict')) }
      }),
    ).rejects.toBeInstanceOf(AxiosError)
    expect(edits).toBe(5)
    edits = 0
    await expect(
      client.listedWrite('pins', async () => {
        edits++
        return { changes: [['pins', 6]], send: () => (edits < 2 ? Promise.reject(refused(409, 'head_conflict')) : Promise.resolve('ok')) }
      }),
    ).resolves.toBe('ok')
    expect(edits).toBe(2)
  })

  it('removes a value from the index the head describes', async () => {
    const engine = new FakeEngine()
    const head = seal({ sequence: 1, previous: null, writer: 'w:other', scopes: [engine.scope('passSecrets', [['v1', 1], ['v2', 2]])] })
    const { http } = server({ 'GET /account/index/passSecrets': () => ({ head, values: [['v1', 1], ['v2', 2]], basis: null }) })
    let sent = ''
    await new AccountHeadClient(engine, memoryRevisionStore(), http).listedWrite('passSecrets', async () => ({
      changes: [['v1', null]],
      send: (h) => {
        sent = h
        return Promise.resolve()
      },
    }))
    expect(unseal(sent).scopes).toEqual([engine.scope('passSecrets', [['v2', 2]])])
  })

  it('an edit with nothing to change sends nothing, and starts no chain', async () => {
    const engine = new FakeEngine()
    const { http, calls } = server({ 'GET /account/index/pins': () => ({ head: null, values: [], basis: 'b' }) })
    await expect(new AccountHeadClient(engine, memoryRevisionStore(), http).listedWrite('pins', () => Promise.resolve(null))).resolves.toBeUndefined()
    expect(calls.filter(([method]) => method === 'POST')).toHaveLength(0)
  })

  it('a refusal other than a conflict is not retried', async () => {
    const engine = new FakeEngine()
    const head = seal({ sequence: 1, previous: null, writer: 'w:other', scopes: [] })
    const { http } = server({ 'GET /account/index/pins': () => ({ head, values: [], basis: null }) })
    let edits = 0
    await expect(
      new AccountHeadClient(engine, memoryRevisionStore(), http).listedWrite('pins', async () => {
        edits++
        return { changes: [], send: () => Promise.reject(refused(400)) }
      }),
    ).rejects.toBeInstanceOf(AxiosError)
    expect(edits).toBe(1)
  })
})

describe('data state', () => {
  it('says whether this app wrote the verified head', async () => {
    const engine = new FakeEngine()
    const store = memoryRevisionStore()
    const head = seal({ sequence: 1, previous: null, writer: 'w:other', scopes: [] })
    const { http } = server({ 'GET /account/index/pins': () => ({ head, values: [], basis: null }) })
    const client = new AccountHeadClient(engine, store, http, () => 77)
    await client.verifiedIndex('pins')
    expect(await client.dataState()).toMatchObject({ sequence: 1, lastByThisApp: false, anchoredAtMs: 77 })
    await client.listedWrite('pins', async () => ({ changes: [['pins', 1]], send: () => Promise.resolve() }))
    expect(await client.dataState()).toMatchObject({ sequence: 2, lastByThisApp: true })
  })
})

describe('races (the #202 review)', () => {
  it('a write keeps the head it verified while another check in the page moves on, and redoes its edit on the newer one', async () => {
    const before = alive
    const engine = new FakeEngine()
    const store = memoryRevisionStore()
    // The server: head 1 covers contact a@1.
    const h1 = seal({ sequence: 1, previous: null, writer: 'w:other', scopes: [engine.scope('contacts', [['a', 1]])] })
    let server = { head: h1, values: [['a', 1]] as [string, number][] }
    const sent: string[] = []
    const { http } = server2(() => server)
    const client = new AccountHeadClient(engine, store, http)
    let edits = 0
    const written = client.listedWrite('contacts', async () => {
      edits++
      if (edits === 1) {
        // While this edit is made, another device writes contact a@2 (head 2),
        // and another read in this page verifies it.
        const h2 = seal({ sequence: 2, previous: digest(h1), writer: 'w:other', scopes: [engine.scope('contacts', [['a', 2]])] })
        server = { head: h2, values: [['a', 2]] }
        await client.verifiedIndex('contacts')
      }
      return {
        changes: [['b', 7]],
        send: (head: string) => {
          sent.push(head)
          // The server takes a head only on top of its newest.
          if (unseal(head).previous !== digest(server.head)) return Promise.reject(conflict409('head_conflict'))
          server = { head, values: [...server.values, ['b', 7]] }
          return Promise.resolve('ok')
        },
      }
    })
    await expect(written).resolves.toBe('ok')
    // First try: built on the head it verified (1), with that head's values; refused.
    expect(unseal(sent[0]!)).toMatchObject({ sequence: 2, previous: digest(h1) })
    expect(unseal(sent[0]!).scopes).toEqual([engine.scope('contacts', [['a', 1], ['b', 7]])])
    // Second try: on head 2, with the other device's change kept.
    expect(unseal(sent[1]!)).toMatchObject({ sequence: 3 })
    expect(unseal(sent[1]!).scopes).toEqual([engine.scope('contacts', [['a', 2], ['b', 7]])])
    // Every verified head it made is freed (none used after free either).
    client.close()
    expect(alive).toBe(before)
  })

  it('a chain that grew past the head being checked is cut at it, not taken for a fork', async () => {
    const heads = chain(3)
    const engine = new FakeEngine()
    const store = memoryRevisionStore()
    await remembering(engine, store, heads[0]!)
    const { http } = server({
      // The index was read at head 2; head 3 was written before the chain was asked for.
      'GET /account/index/contacts': () => ({ head: heads[1], values: [['c', 1], ['d', 2]], basis: null }),
      'GET /account/heads?from=1': () => ({ heads, next: null }),
    })
    const client = new AccountHeadClient(engine, store, http)
    await client.verifiedIndex('contacts').catch(() => undefined)
    expect(client.current().kind).toBe('trusted')
    expect((await stateIn(engine, store)).anchor?.sequence).toBe(2)
  })

  it('a rollback seen once (another tab moved on between two reads) is read again, not blocked', async () => {
    const heads = chain(2)
    const engine = new FakeEngine()
    const store = memoryRevisionStore()
    await remembering(engine, store, heads[1]!)
    let reads = 0
    const { http } = server({
      'GET /account/head': () => ({ head: reads++ === 0 ? heads[0] : heads[1] }),
      'GET /account/heads?from=2': () => ({ heads: [heads[1]], next: null }),
    })
    const client = new AccountHeadClient(engine, store, http)
    const seen: string[] = []
    client.subscribe((condition) => seen.push(condition.kind))
    await client.verifiedHead()
    expect(seen).toEqual(['unknown', 'trusted'])
  })
})
