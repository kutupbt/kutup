import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Session } from '@kutup/session/store'
import type { VaultHandle } from '../vault/client'

const put = vi.fn<(...args: unknown[]) => Promise<unknown>>()
vi.mock('@kutup/session/client', () => ({ default: { get: vi.fn(), put: (...a: unknown[]) => put(...a) } }))
// "AAEC" is base64 of [0, 1, 2]: the password hash the fake keeps.
vi.mock('../vault/client', () => ({
  openKept: vi.fn((envelope: string, _key: Uint8Array, binding: string, fileId: string) => {
    if (envelope === `sealed:${binding}:${fileId}`) return Promise.resolve({ passwordHash: 'AAEC', keyFile: null, generatedPassword: null })
    if (envelope === `generated:${binding}:${fileId}`) return Promise.resolve({ passwordHash: 'AAEC', keyFile: null, generatedPassword: 'k7m2q-9xd4t' })
    return Promise.reject(new Error('auth failed'))
  }),
}))

import { keepVaultKey, keptGeneratedPassword, keptKey, keptKeyKind } from './secrets'

const BINDING = '5f0c2f6e-1d2b-4c3a-8e9f-0a1b2c3d4e5f'
const session = { masterKey: new Uint8Array(32), envelopeBinding: BINDING } as unknown as Session
const row = (kind: string, binding: string) => ({ fileId: 'v', envelope: `${kind}:${binding}:v`, updatedAt: '' })

describe('kept vault keys', () => {
  beforeEach(() => put.mockReset())

  it('opens with the password as its hash, never the password', async () => {
    expect(await keptKey(session, [row('sealed', BINDING)], 'v')).toEqual({ password: null, passwordHash: new Uint8Array([0, 1, 2]), keyFile: null })
    expect(await keptGeneratedPassword(session, [row('sealed', BINDING)], 'v')).toBeNull()
  })

  it('shows a generated key, which is kept as it is', async () => {
    expect(await keptGeneratedPassword(session, [row('generated', BINDING)], 'v')).toBe('k7m2q-9xd4t')
  })

  it('treats a key that does not open, or none kept, as none', async () => {
    expect(await keptKey(session, [row('sealed', 'someone-else')], 'v')).toBeNull()
    expect(await keptKey(session, [], 'v')).toBeNull()
  })

  it('tells generated, chosen, unreadable and none apart', async () => {
    expect(await keptKeyKind(session, [row('generated', BINDING)], 'v')).toBe('generated')
    expect(await keptKeyKind(session, [row('sealed', BINDING)], 'v')).toBe('chosen')
    expect(await keptKeyKind(session, [row('sealed', 'someone-else')], 'v')).toBe('unknown')
    expect(await keptKeyKind(session, [], 'v')).toBe('none')
  })

  it('keeps the key the open vault was opened with, sealed in the worker', async () => {
    put.mockResolvedValue({})
    const keepKey = vi.fn((..._args: unknown[]) => Promise.resolve('envelope'))
    await keepVaultKey(session, 'v', { keepKey } as unknown as VaultHandle, true)
    expect(keepKey).toHaveBeenCalledWith(session.masterKey, BINDING, 'v', true)
    expect(put.mock.calls).toEqual([['/pass/vault-secrets/v', { envelope: 'envelope' }]])
  })
})
