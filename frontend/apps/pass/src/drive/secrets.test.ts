import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Session } from '@kutup/session/store'

const get = vi.fn<(...args: unknown[]) => Promise<unknown>>()
const put = vi.fn<(...args: unknown[]) => Promise<unknown>>()
const refresh = vi.fn<() => Promise<string>>()
vi.mock('@kutup/session/client', () => ({ default: { get: (...a: unknown[]) => get(...a), put: (...a: unknown[]) => put(...a) } }))
vi.mock('@kutup/session/binding', () => ({
  refreshEnvelopeBinding: () => refresh(),
  isBindingChanged: (error: { code?: string }) => error?.code === 'bindingChanged',
}))
vi.mock('../vault/client', () => ({ keyFileSecret: vi.fn() }))
vi.mock('@kutup/crypto/passVault', () => ({
  openPassVaultSecret: vi.fn((envelope: string, _key: string, binding: string, fileId: string) =>
    envelope === `sealed:${binding}:${fileId}` ? Promise.resolve({ password: 'kasa', keyFile: null }) : Promise.reject(new Error('auth failed')),
  ),
  sealPassVaultSecret: vi.fn((_key: string, binding: string, fileId: string) => Promise.resolve(`sealed:${binding}:${fileId}`)),
}))

import { keepVaultKey, keptKey } from './secrets'

const OLD = 'ayse@example.org'
const NEW = '5f0c2f6e-1d2b-4c3a-8e9f-0a1b2c3d4e5f'
const session = { masterKey: new Uint8Array(32), envelopeBinding: OLD } as unknown as Session
const row = (binding: string) => ({ fileId: 'v', envelope: `sealed:${binding}:v`, updatedAt: '' })

describe('kept vault keys across a re-seal', () => {
  beforeEach(() => {
    get.mockReset()
    put.mockReset()
    refresh.mockReset()
  })

  it('opens with the binding this page has, asking nothing more', async () => {
    expect(await keptKey(session, [row(OLD)], 'v')).toEqual({ password: 'kasa', keyFile: null })
    expect(refresh).not.toHaveBeenCalled()
  })

  it('reads the binding and the list again once when the account was re-sealed meanwhile', async () => {
    refresh.mockResolvedValue(NEW)
    get.mockResolvedValue({ data: [row(NEW)] })
    expect(await keptKey(session, [row(NEW)], 'v')).toEqual({ password: 'kasa', keyFile: null })
    expect(refresh).toHaveBeenCalledTimes(1)
    expect(get).toHaveBeenCalledWith('/pass/vault-secrets')
  })

  it('treats a key that still does not open, or an unreachable Kutup, as none', async () => {
    refresh.mockResolvedValue(NEW)
    get.mockResolvedValue({ data: [{ ...row(NEW), envelope: 'sealed:someone-else:v' }] })
    expect(await keptKey(session, [row('someone-else')], 'v')).toBeNull()
    refresh.mockRejectedValue(new Error('offline'))
    expect(await keptKey(session, [row('someone-else')], 'v')).toBeNull()
    expect(await keptKey(session, [], 'v')).toBeNull()
  })

  it('keeping a key seals again for the new binding once when the server says it changed', async () => {
    put.mockRejectedValueOnce({ code: 'bindingChanged' }).mockResolvedValueOnce({})
    refresh.mockResolvedValue(NEW)
    await keepVaultKey(session, 'v', { password: 'kasa', keyFile: null })
    expect(put.mock.calls).toEqual([
      ['/pass/vault-secrets/v', { envelope: `sealed:${OLD}:v` }],
      ['/pass/vault-secrets/v', { envelope: `sealed:${NEW}:v` }],
    ])
  })

  it('does not retry other refusals, nor a second change', async () => {
    put.mockRejectedValueOnce({ code: 'other' })
    await expect(keepVaultKey(session, 'v', { password: 'kasa', keyFile: null })).rejects.toEqual({ code: 'other' })
    expect(refresh).not.toHaveBeenCalled()
    put.mockReset()
    put.mockRejectedValue({ code: 'bindingChanged' })
    refresh.mockResolvedValue(NEW)
    await expect(keepVaultKey(session, 'v', { password: 'kasa', keyFile: null })).rejects.toEqual({ code: 'bindingChanged' })
    expect(put).toHaveBeenCalledTimes(2)
  })
})
