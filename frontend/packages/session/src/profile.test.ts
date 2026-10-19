import { beforeEach, describe, expect, it, vi } from 'vitest'

const get = vi.fn()
const post = vi.fn()
// The identity suite upgrade has its own tests (identitySuite.test.ts).
vi.mock('./identitySuite', () => ({ upgradedKeys: (keys: unknown) => Promise.resolve(keys) }))
vi.mock('./client', () => ({
  default: { get: (...a: unknown[]) => get(...a), post: (...a: unknown[]) => post(...a) },
}))

import { activateSession, KeyBindingMismatchError } from './profile'
import { clearSession, getSession } from './store'

const binding = '0b9f4c0e-6a51-4d2f-9a33-5e1f6c7d8e90'
const keys = {
  userId: 'u1',
  masterKey: new Uint8Array(32),
  privateKey: new Uint8Array(32),
  publicKey: 'p',
  keyBinding: binding,
}
const me = {
  id: 'u1',
  address: 'ada@kutup.dev',
  envelopeBinding: binding,
  username: 'ada',
  publicKey: 'p',
  totpEnabled: false,
  storageQuotaBytes: 1,
  storageUsedBytes: 0,
  isAdmin: false,
  color: '',
  renames: { sequence: 0 },
}

beforeEach(() => {
  clearSession()
  get.mockReset()
  post.mockReset()
  post.mockResolvedValue({ data: { ok: true } })
})

describe('activateSession', () => {
  it('seals under the binding the keys were verified with', async () => {
    await activateSession(keys, 'AT', 'S1', me)
    expect(getSession()?.envelopeBinding).toBe(binding)
  })

  it('refuses a profile that names another binding', async () => {
    const other = { ...me, envelopeBinding: '1c9f4c0e-6a51-4d2f-9a33-5e1f6c7d8e91' }
    const refused = { ...keys, masterKey: new Uint8Array(32).fill(7), privateKey: new Uint8Array(32).fill(8) }
    await expect(activateSession(refused, 'AT', 'S1', other)).rejects.toBeInstanceOf(KeyBindingMismatchError)
    expect(getSession()).toBeNull()
    // Ended on the server, and the keys dropped.
    expect(post).toHaveBeenCalledWith('/auth/logout')
    expect(refused.masterKey.every((b) => b === 0)).toBe(true)
    expect(refused.privateKey.every((b) => b === 0)).toBe(true)
  })
})
