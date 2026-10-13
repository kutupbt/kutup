import { beforeEach, describe, expect, it, vi } from 'vitest'
import { resetRevisionGuardsForTesting } from '@kutup/crypto/revisionGuard'
import type { Session } from '@kutup/session/store'
import type { VaultHandle } from '../vault/client'

const T = 1_791_633_600_000
const get = vi.fn<(...args: unknown[]) => Promise<unknown>>()
const put = vi.fn<(...args: unknown[]) => Promise<unknown>>()
vi.mock('@kutup/session/client', () => ({ default: { get: (...a: unknown[]) => get(...a), put: (...a: unknown[]) => put(...a) } }))
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
}))

import { keepVaultKey, keptGeneratedPassword, keptKey, keptKeyKind, putKeptKey } from './secrets'

const BINDING = '5f0c2f6e-1d2b-4c3a-8e9f-0a1b2c3d4e5f'
const session = { userId: 'u1', masterKey: new Uint8Array(32), envelopeBinding: BINDING } as unknown as Session
const row = (kind: string, binding: string, revision = T) => ({ fileId: 'v', envelope: `${kind}:${binding}:v:${revision}`, revision, updatedAt: '' })
const conflict = (revision: number) => Object.assign(new Error('409'), { isAxiosError: true, response: { status: 409, data: { code: 'revision_conflict', revision } } })

/** A vault handle whose keepKey seals the fake way, at the revision asked. */
function handle(mine: string[] = []) {
  const keepKey = vi.fn((_m: Uint8Array, binding: string, fileId: string, revision: number, generated: boolean) =>
    Promise.resolve(`${generated ? 'generated' : 'sealed'}:${binding}:${fileId}:${revision}`),
  )
  // The kept keys that are this vault's own key.
  const keptKeyIsMine = vi.fn((envelope: string) => Promise.resolve(mine.includes(envelope)))
  return { keepKey, vault: { keepKey, keptKeyIsMine } as unknown as VaultHandle }
}

describe('kept vault keys', () => {
  beforeEach(() => {
    get.mockReset()
    put.mockReset()
    resetRevisionGuardsForTesting()
  })

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
    get.mockResolvedValue({ data: [row('sealed', BINDING, T)] })
    put.mockResolvedValue({})
    const { keepKey, vault } = handle()
    await keepVaultKey(session, 'v', vault, true)
    const revision = keepKey.mock.calls[0][3]
    expect(revision).toBeGreaterThan(T)
    expect(keepKey).toHaveBeenCalledWith(session.masterKey, BINDING, 'v', revision, true)
    expect(put.mock.calls).toEqual([['/pass/vault-secrets/v', { envelope: `generated:${BINDING}:v:${revision}`, baseRevision: T }]])
  })

  it('stops when the key another device kept first is this same key', async () => {
    const theirs = row('sealed', BINDING, T + 9)
    get.mockResolvedValueOnce({ data: [] }).mockResolvedValueOnce({ data: [theirs] })
    put.mockRejectedValueOnce(conflict(T + 9))
    const { vault } = handle([theirs.envelope])
    await keepVaultKey(session, 'v', vault)
    expect(put).toHaveBeenCalledTimes(1)
  })

  it('keeps once more on top of another key another device kept first', async () => {
    get.mockResolvedValueOnce({ data: [] }).mockResolvedValueOnce({ data: [row('sealed', BINDING, T + 9)] })
    put.mockRejectedValueOnce(conflict(T + 9)).mockResolvedValueOnce({})
    const { vault } = handle()
    await keepVaultKey(session, 'v', vault)
    expect(put).toHaveBeenCalledTimes(2)
    expect((put.mock.calls[1][1] as { baseRevision: number }).baseRevision).toBe(T + 9)
  })

  it('counts a keep whose answer was lost as kept when tried again', async () => {
    // The first try was stored; its answer never came. Trying again finds
    // the key at its own revision.
    put.mockRejectedValueOnce(conflict(T + 3))
    await expect(putKeptKey(session, 'v', { envelope: `sealed:${BINDING}:v:${T + 3}`, revision: T + 3, base: 0 })).resolves.toBeUndefined()
    put.mockRejectedValueOnce(conflict(T + 4))
    await expect(putKeptKey(session, 'v', { envelope: `sealed:${BINDING}:v:${T + 5}`, revision: T + 5, base: T + 3 })).rejects.toThrow('409')
  })
})
