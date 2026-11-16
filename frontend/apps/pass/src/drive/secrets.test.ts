import { firstMasterKeys, masterKeysBytes } from '@kutup/crypto/masterKeys'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { resetRevisionGuardsForTesting } from '@kutup/crypto/revisionGuard'
import type { Session } from '@kutup/session/store'
import type { VaultHandle } from '../vault/client'

const T = 1_791_633_600_000
const get = vi.fn<(...args: unknown[]) => Promise<unknown>>()
vi.mock('@kutup/session/client', () => ({ default: { get: (...a: unknown[]) => get(...a) } }))
// The account head and its records (docs/plans/account-records.md), kept
// small: the records the test says per attempt, batches planned on them by
// the real ScopeRecords and redone on a conflict as the real client does
// (its own tests: @kutup/session).
const head = vi.hoisted(() => ({
  records: (_attempt: number): [string, number, string][] => [],
  blocked: false,
  send: null as unknown as (batch: unknown) => Promise<void>,
}))
vi.mock('@kutup/session/accountHead', async () => {
  const actual = await vi.importActual<typeof import('@kutup/session/accountHead')>('@kutup/session/accountHead')
  const { ScopeRecords } = await vi.importActual<typeof import('@kutup/session/accountRecords')>('@kutup/session/accountRecords')
  const copyAt = (attempt: number) => {
    const copy = new ScopeRecords('passSecrets')
    for (const [id, revision, envelope] of head.records(attempt)) copy.records.set(id, { revision, envelope })
    return copy
  }
  const client = {
    records: () => (head.blocked ? Promise.reject(new actual.HeadBlockedError('fork')) : Promise.resolve(copyAt(1))),
    recordsWrite: async <T,>(_scope: string, edit: (copy: InstanceType<typeof ScopeRecords>, attempt: number) => Promise<{ puts: { id: string; revision: number; envelope: string }[]; deletes: string[]; done: T } | null>) => {
      for (let attempt = 1; ; attempt++) {
        const copy = copyAt(attempt)
        const change = await edit(copy, attempt)
        if (!change) return undefined
        const batch = copy.plan(change)
        if (batch.puts.length === 0 && batch.deletes.length === 0) return change.done
        try {
          await head.send(batch)
          return change.done
        } catch (error) {
          const code = (error as { response?: { data?: { code?: string } } }).response?.data?.code
          if ((code === 'head_conflict' || code === 'revision_conflict') && attempt < 5) continue
          throw error
        }
      }
    },
  }
  return { ...actual, accountHead: () => Promise.resolve(client) }
})
// A fake sealed key is "<kind>:<binding>:<fileId>:<revision>"; "AAEC" is
// base64 of [0, 1, 2], the password hash the fake keeps.
vi.mock('../vault/client', () => ({
  openKept: vi.fn((envelope: string, _key: Uint8Array, binding: string, fileId: string) => {
    const [kind, sealedBinding, sealedFile, revision] = envelope.split(':')
    if (sealedBinding !== binding || sealedFile !== fileId) return Promise.reject(new Error('auth failed'))
    return Promise.resolve({
      passwordHash: 'AAEC',
      keyFile: null,
      generatedPassword: kind === 'generated' ? 'k7m2q-9xd4t' : null,
      revision: Number(revision),
    })
  }),
  resealKeptKey: vi.fn((envelope: string, _key: Uint8Array, binding: string, from: string, to: string, revision: number) => {
    const [kind, sealedBinding, sealedFile] = envelope.split(':')
    if (sealedBinding !== binding || sealedFile !== from) return Promise.reject(new Error('auth failed'))
    return Promise.resolve(`${kind}:${binding}:${to}:${revision}`)
  }),
}))

import { forgetVaultKey, keepCopiedKey, keepVaultKey, keptGeneratedPassword, keptKey, keptKeyKind, loadVaultSecrets, putKeptKey } from './secrets'
import { testRoots } from '@kutup/crypto/accountRoots.testing'

const BINDING = '5f0c2f6e-1d2b-4c3a-8e9f-0a1b2c3d4e5f'
const session = { userId: 'u1', masterKey: new Uint8Array(32), masterKeys: firstMasterKeys(new Uint8Array(32)), roots: testRoots(0), envelopeBinding: BINDING } as unknown as Session
const row = (kind: string, binding: string, revision = T) => ({ fileId: 'v', envelope: `${kind}:${binding}:v:${revision}`, state: 'open' as const, revision })
const kept = (id: string, kind: string, revision: number): [string, number, string] => [id, revision, `${kind}:${BINDING}:${id}:${revision}`]
const conflict = (revision: number): Error => Object.assign(new Error('409'), { isAxiosError: true, response: { status: 409, data: { code: 'revision_conflict', revision } } })

/** A vault handle whose keepKey seals the fake way, at the revision asked. */
function handle(mine: string[] = []) {
  const keepKey = vi.fn((_m: Uint8Array, binding: string, fileId: string, revision: number, generated: boolean) =>
    Promise.resolve(`${generated ? 'generated' : 'sealed'}:${binding}:${fileId}:${revision}`),
  )
  // The kept keys that are this vault's own key.
  const keptKeyIsMine = vi.fn((envelope: string) => Promise.resolve(mine.includes(envelope)))
  return { keepKey, vault: { keepKey, keptKeyIsMine } as unknown as VaultHandle }
}

type Batch = { puts: { id: string; baseRevision: number; revision: number; envelope: string }[]; deletes: { id: string; baseRevision: number }[] }
let sent: Batch[]
const send = vi.fn<(batch: Batch) => Promise<void>>()

/** Every batch sent is recorded; the test may make one fail first. */
function recording() {
  get.mockReset()
  send.mockReset()
  sent = []
  send.mockImplementation((batch) => {
    sent.push(batch)
    return Promise.resolve()
  })
  head.send = send as unknown as typeof head.send
  head.records = () => []
  head.blocked = false
  resetRevisionGuardsForTesting()
}

describe('kept vault keys', () => {
  beforeEach(recording)

  it('opens with the password as its hash, never the password', async () => {
    expect(await keptKey(session, [row('sealed', BINDING)], 'v')).toEqual({ password: null, passwordHash: new Uint8Array([0, 1, 2]), keyFile: null })
    expect(await keptGeneratedPassword(session, [row('sealed', BINDING)], 'v')).toBeNull()
  })

  it('shows a generated key, which is kept as it is', async () => {
    expect(await keptGeneratedPassword(session, [row('generated', BINDING)], 'v')).toBe('k7m2q-9xd4t')
  })

  it('treats a key that does not open, none kept, or an older one than seen as none', async () => {
    expect(await keptKey(session, [row('sealed', 'someone-else')], 'v')).toBeNull()
    expect(await keptKey(session, [], 'v')).toBeNull()
    // Seen at T + 5; the server then hands back the key kept at T.
    expect(await keptKey(session, [row('sealed', BINDING, T + 5)], 'v')).not.toBeNull()
    expect(await keptKey(session, [row('sealed', BINDING, T)], 'v')).toBeNull()
  })

  it('tells generated, chosen, unreadable and none apart', async () => {
    expect(await keptKeyKind(session, [row('generated', BINDING)], 'v')).toBe('generated')
    expect(await keptKeyKind(session, [row('sealed', BINDING)], 'v')).toBe('chosen')
    expect(await keptKeyKind(session, [row('sealed', 'someone-else')], 'v')).toBe('unknown')
    expect(await keptKeyKind(session, [], 'v')).toBe('none')
  })

  it('keeps the open vault key on top of the one kept now, sealed in the worker', async () => {
    head.records = () => [kept('v', 'sealed', T)]
    const { keepKey, vault } = handle()
    await keepVaultKey(session, 'v', vault, true)
    const revision = keepKey.mock.calls[0][3]
    expect(revision).toBeGreaterThan(T)
    expect(keepKey).toHaveBeenCalledWith(masterKeysBytes(session.masterKeys), BINDING, 'v', revision, true)
    expect(sent).toEqual([{ scope: 'passSecrets', puts: [{ id: 'v', baseRevision: T, revision, envelope: `generated:${BINDING}:v:${revision}` }], deletes: [] }])
  })

  it('stops when the key another device kept first is this same key', async () => {
    const theirs = kept('v', 'sealed', T + 9)
    head.records = (attempt) => (attempt > 1 ? [theirs] : [])
    send.mockRejectedValueOnce(conflict(T + 9))
    const { vault } = handle([theirs[2]])
    await keepVaultKey(session, 'v', vault)
    expect(send).toHaveBeenCalledTimes(1)
  })

  it('keeps once more on top of another key another device kept first', async () => {
    head.records = (attempt) => (attempt > 1 ? [kept('v', 'sealed', T + 9)] : [])
    send.mockRejectedValueOnce(conflict(T + 9))
    const { vault } = handle()
    await keepVaultKey(session, 'v', vault)
    expect(send).toHaveBeenCalledTimes(2)
    expect(sent[0]?.puts[0]?.baseRevision).toBe(T + 9)
  })

  it('counts a keep whose answer was lost as kept when tried again, sending nothing more', async () => {
    // The first try was stored (with its head); its answer never came. The
    // records then hold the key at its own revision.
    send.mockRejectedValueOnce(conflict(T + 3))
    head.records = (attempt) => (attempt > 1 ? [kept('v', 'sealed', T + 3)] : [])
    await expect(putKeptKey(session, 'v', { envelope: `sealed:${BINDING}:v:${T + 3}`, revision: T + 3, base: 0 })).resolves.toBeUndefined()
    expect(send).toHaveBeenCalledTimes(1)
    // Another key there, newer than this one: refused before anything is sent.
    send.mockReset()
    head.records = () => [kept('v', 'sealed', T + 6)]
    await expect(putKeptKey(session, 'v', { envelope: `sealed:${BINDING}:v:${T + 5}`, revision: T + 5, base: T + 3 })).rejects.toThrow(/revision/)
    expect(send).not.toHaveBeenCalled()
  })

  it('forgets a kept key with the next head, and nothing when it is gone already', async () => {
    head.records = () => [kept('v', 'sealed', T)]
    await forgetVaultKey(session, 'v')
    expect(sent).toEqual([{ scope: 'passSecrets', puts: [], deletes: [{ id: 'v', baseRevision: T }] }])
    head.records = () => []
    await forgetVaultKey(session, 'v')
    expect(send).toHaveBeenCalledTimes(1)
  })

  it('lists the verified records at their revisions, only those of vaults open to the account', async () => {
    head.records = () => [kept('v', 'sealed', T), kept('t', 'sealed', T), kept('g', 'sealed', T), kept('x', 'sealed', T)]
    get.mockImplementation((url) => {
      expect(url).toBe('/pass/vault-states')
      return Promise.resolve({ data: [{ fileId: 'v', state: 'open' }, { fileId: 't', state: 'trashed' }, { fileId: 'g', state: 'gone' }] })
    })
    const rows = await loadVaultSecrets(session)
    // A record the server gives no state for counts as gone.
    expect(rows.map((r) => [r.fileId, r.vouched])).toEqual([['v', T]])
    expect(await keptKey(session, rows, 'v')).not.toBeNull()
  })

  it('while blocked on another history, reads the records unverified, held to its own guard', async () => {
    head.blocked = true
    get.mockImplementation((url) =>
      Promise.resolve(
        url === '/pass/vault-states'
          ? { data: [{ fileId: 'v', state: 'open' }] }
          : { data: { records: [{ id: 'v', revision: T, envelope: `sealed:${BINDING}:v:${T}`, seq: 1 }], deleted: [], next: 1, more: false, resync: false, head: 'h', basis: null } },
      ),
    )
    const rows = await loadVaultSecrets(session)
    expect(rows.map((r) => [r.fileId, r.vouched])).toEqual([['v', undefined]])
    expect(get).toHaveBeenCalledWith('/account/records/passSecrets?after=0')
  })
})

describe('keepCopiedKey', () => {
  beforeEach(recording)

  it("keeps the vault's kept secret, as it is, for its copy", async () => {
    expect(await keepCopiedKey(session, [row('generated', BINDING)], 'v', 'copy')).toBe(true)
    expect(send).toHaveBeenCalledTimes(1)
    const put = sent[0]?.puts[0]
    expect(put?.id).toBe('copy')
    expect(put?.baseRevision).toBe(0)
    expect(put?.envelope).toMatch(new RegExp(`^generated:${BINDING}:copy:\\d+$`))
  })

  it('keeps nothing when nothing usable is kept for the vault', async () => {
    expect(await keepCopiedKey(session, [], 'v', 'copy')).toBe(false)
    expect(await keepCopiedKey(session, [row('chosen', 'another-binding')], 'v', 'copy')).toBe(false)
    expect(send).not.toHaveBeenCalled()
  })
})
