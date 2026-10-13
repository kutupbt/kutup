import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Session } from '@kutup/session/store'

const put = vi.fn<(...args: unknown[]) => Promise<unknown>>()
const seal = vi.fn<(...args: unknown[]) => Promise<string>>()
vi.mock('@kutup/session/client', () => ({ default: { get: vi.fn(), put: (...a: unknown[]) => put(...a) } }))
vi.mock('../vault/client', () => ({ keyFileSecret: vi.fn() }))
// "AAEC" is base64 of [0, 1, 2]: the password hash the fake keeps.
vi.mock('@kutup/crypto/passVault', () => ({
  openPassVaultSecret: vi.fn((envelope: string, _key: string, binding: string, fileId: string) => {
    if (envelope === `sealed:${binding}:${fileId}`) return Promise.resolve({ passwordHash: 'AAEC', generatedPassword: null, keyFile: null })
    if (envelope === `generated:${binding}:${fileId}`) return Promise.resolve({ passwordHash: 'AAEC', generatedPassword: 'k7m2q-9xd4t', keyFile: null })
    return Promise.reject(new Error('auth failed'))
  }),
  sealPassVaultSecret: (...args: unknown[]) => seal(...args),
}))

import { keepVaultKey, keptGeneratedPassword, keptKey } from './secrets'

const BINDING = '5f0c2f6e-1d2b-4c3a-8e9f-0a1b2c3d4e5f'
const session = { masterKey: new Uint8Array(32), envelopeBinding: BINDING } as unknown as Session
const row = (kind: string, binding: string) => ({ fileId: 'v', envelope: `${kind}:${binding}:v`, updatedAt: '' })

describe('kept vault keys', () => {
  beforeEach(() => {
    put.mockReset()
    seal.mockReset()
    seal.mockResolvedValue('envelope')
  })

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

  it('keeps a key sealed for the account key binding, marking a generated one', async () => {
    put.mockResolvedValue({})
    await keepVaultKey(session, 'v', { password: 'kasa', keyFile: null })
    await keepVaultKey(session, 'v', { password: 'k7m2q-9xd4t', keyFile: null }, true)
    expect(seal.mock.calls.map((call) => call.slice(1))).toEqual([
      [BINDING, 'v', { password: 'kasa', keyFile: null, generated: false }],
      [BINDING, 'v', { password: 'k7m2q-9xd4t', keyFile: null, generated: true }],
    ])
    expect(put.mock.calls).toEqual([
      ['/pass/vault-secrets/v', { envelope: 'envelope' }],
      ['/pass/vault-secrets/v', { envelope: 'envelope' }],
    ])
  })

  it('does not keep a key it only has as a hash', async () => {
    await expect(keepVaultKey(session, 'v', { password: null, passwordHash: new Uint8Array(32), keyFile: null })).rejects.toThrow()
    expect(put).not.toHaveBeenCalled()
  })
})
