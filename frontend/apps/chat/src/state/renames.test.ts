import { beforeEach, describe, expect, it, vi } from 'vitest'

const moved = vi.hoisted(() => ({ marks: [] as [string, string][], drafts: [] as [string, string][] }))
vi.mock('@kutup/crypto/accountRename', () => ({
  // As Rust's names::fold_address.
  foldAddress: (address: string) => {
    const at = address.lastIndexOf('@')
    return Promise.resolve(at > 0 ? `${address.slice(0, at).replace(/[._-]/g, '').toLowerCase()}@${address.slice(at + 1).toLowerCase()}` : null)
  },
}))
vi.mock('./readState', () => ({ moveReadMark: (from: string, to: string) => moved.marks.push([from, to]) }))
vi.mock('../lib/drafts', () => ({ moveDraft: (from: string, to: string) => moved.drafts.push([from, to]) }))

const { currentKey, followRenamedState } = await import('./renames')

const aliases = { 'adal@kutup.test': { to: 'ada_lovelace@kutup.test', incarnationId: 'i', movedAtMs: 0 } }

beforeEach(() => {
  moved.marks = []
  moved.drafts = []
})

describe('a peer that renamed', () => {
  it('has its thread under the new address, in any spelling of the old one', async () => {
    expect(await currentKey('direct:ada_l@kutup.test', aliases)).toBe('direct:ada_lovelace@kutup.test')
    expect(await currentKey('direct:Ada-L@kutup.test', aliases)).toBe('direct:ada_lovelace@kutup.test')
    expect(await currentKey('direct:ada_lovelace@kutup.test', aliases)).toBeNull()
    expect(await currentKey('direct:grace@kutup.test', aliases)).toBeNull()
    expect(await currentKey('group:abc', aliases)).toBeNull()
    // Someone else holds the name now: their thread, not hers.
    const reused = { 'adal@kutup.test': { ...aliases['adal@kutup.test'], reusedAtMs: 5 } }
    expect(await currentKey('direct:ada_l@kutup.test', reused)).toBeNull()
  })

  it('tells a change of the log by its content, not its size', async () => {
    const { aliasesDigest } = await import('./renames')
    const back = { 'adal@kutup.test': { to: 'ada_king@kutup.test', incarnationId: 'i', movedAtMs: 1 } }
    expect(aliasesDigest(back)).not.toBe(aliasesDigest(aliases))
  })

  it('takes this device’s read mark and draft along, once each', async () => {
    await followRenamedState(['direct:ada_l@kutup.test', 'direct:grace@kutup.test', 'direct:ada_l@kutup.test'], aliases)
    expect(moved.marks).toEqual([['direct:ada_l@kutup.test', 'direct:ada_lovelace@kutup.test']])
    expect(moved.drafts).toEqual([['direct:ada_l@kutup.test', 'direct:ada_lovelace@kutup.test']])
  })
})
