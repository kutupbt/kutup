import { beforeEach, describe, expect, it, vi } from 'vitest'

const get = vi.fn()
vi.mock('./client', () => ({ default: { get: (...args: unknown[]) => get(...args) } }))
vi.mock('@kutup/crypto/passVault', () => ({
  openPassVaultSecret: vi.fn(async (envelope: string, _key: string, binding: string, fileId: string) => {
    if (envelope !== `sealed:${binding}:${fileId}` && !envelope.startsWith(`sealed:${binding}:${fileId}:`)) throw new Error('auth failed')
    return { password: `pw-${fileId}`, keyFile: null }
  }),
  sealPassVaultSecret: vi.fn(async (_key: string, binding: string, fileId: string, secret: { password: string }) =>
    // A sealing that would not open again (to test the check).
    fileId === 'broken' ? 'garbage' : `sealed:${binding}:${fileId}:${secret.password}`,
  ),
}))

import { rebindPassVaultSecrets, UnreadableVaultKeys } from './passRebind'

describe('rebindPassVaultSecrets', () => {
  beforeEach(() => get.mockReset())

  it('re-seals every kept vault key, the trash included, and drops one that did not open', async () => {
    get.mockResolvedValue({
      data: [
        { fileId: 'a', envelope: 'sealed:ayse@example.org:a' },
        { fileId: 'b', envelope: 'sealed:ayse@example.org:b', inTrash: true },
        { fileId: 'c', envelope: 'sealed:someone-else@example.org:c' },
      ],
    })
    // Not without agreeing to forget the one that does not open.
    await expect(rebindPassVaultSecrets(new Uint8Array(32), 'ayse@example.org', '0b9f4c0e-6a51-4d2f-9a33-5e1f6c7d8e90')).rejects.toBeInstanceOf(UnreadableVaultKeys)
    const rows = await rebindPassVaultSecrets(new Uint8Array(32), 'ayse@example.org', '0b9f4c0e-6a51-4d2f-9a33-5e1f6c7d8e90', true)
    expect(get).toHaveBeenLastCalledWith('/pass/vault-secrets', { params: { all: true } })
    expect(rows).toEqual([
      { fileId: 'a', envelope: 'sealed:0b9f4c0e-6a51-4d2f-9a33-5e1f6c7d8e90:a:pw-a' },
      { fileId: 'b', envelope: 'sealed:0b9f4c0e-6a51-4d2f-9a33-5e1f6c7d8e90:b:pw-b' },
      { fileId: 'c', envelope: null },
    ])
  })

  it('refuses to send a re-sealed key that does not open again', async () => {
    get.mockResolvedValue({ data: [{ fileId: 'broken', envelope: 'sealed:ayse@example.org:broken' }] })
    await expect(rebindPassVaultSecrets(new Uint8Array(32), 'ayse@example.org', 'id')).rejects.toThrow(/does not open/)
  })

  it('has nothing to send for an account that keeps no vault keys', async () => {
    get.mockResolvedValue({ data: [] })
    expect(await rebindPassVaultSecrets(new Uint8Array(32), 'a@b', 'id')).toEqual([])
  })
})
