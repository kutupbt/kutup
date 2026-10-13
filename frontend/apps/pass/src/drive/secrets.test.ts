import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Session } from '@kutup/session/store'

const put = vi.fn<(...args: unknown[]) => Promise<unknown>>()
vi.mock('@kutup/session/client', () => ({ default: { get: vi.fn(), put: (...a: unknown[]) => put(...a) } }))
vi.mock('../vault/client', () => ({ keyFileSecret: vi.fn() }))
vi.mock('@kutup/crypto/passVault', () => ({
  openPassVaultSecret: vi.fn((envelope: string, _key: string, binding: string, fileId: string) =>
    envelope === `sealed:${binding}:${fileId}` ? Promise.resolve({ password: 'kasa', keyFile: null }) : Promise.reject(new Error('auth failed')),
  ),
  sealPassVaultSecret: vi.fn((_key: string, binding: string, fileId: string) => Promise.resolve(`sealed:${binding}:${fileId}`)),
}))

import { keepVaultKey, keptKey } from './secrets'

const BINDING = '5f0c2f6e-1d2b-4c3a-8e9f-0a1b2c3d4e5f'
const session = { masterKey: new Uint8Array(32), envelopeBinding: BINDING } as unknown as Session
const row = (binding: string) => ({ fileId: 'v', envelope: `sealed:${binding}:v`, updatedAt: '' })

describe('kept vault keys', () => {
  beforeEach(() => put.mockReset())

  it('opens with the account key binding', async () => {
    expect(await keptKey(session, [row(BINDING)], 'v')).toEqual({ password: 'kasa', keyFile: null })
  })

  it('treats a key that does not open, or none kept, as none', async () => {
    expect(await keptKey(session, [row('someone-else')], 'v')).toBeNull()
    expect(await keptKey(session, [], 'v')).toBeNull()
  })

  it('keeps a key sealed for the account key binding', async () => {
    put.mockResolvedValue({})
    await keepVaultKey(session, 'v', { password: 'kasa', keyFile: null })
    expect(put.mock.calls).toEqual([['/pass/vault-secrets/v', { envelope: `sealed:${BINDING}:v` }]])
  })
})
