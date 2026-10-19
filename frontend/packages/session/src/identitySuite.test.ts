import { AxiosError, AxiosHeaders, type AxiosResponse } from 'axios'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { SessionKeys } from './keys'

const post = vi.hoisted(() => vi.fn())
vi.mock('./client', () => ({ default: { post } }))
const currentDriveKeys = vi.hoisted(() =>
  vi.fn(() => Promise.resolve({ publicKey: 'xwing', privateKey: new Uint8Array(32).fill(7), drivePrivateKeyEnvelope: 'sealed-seed' })),
)
vi.mock('@kutup/crypto', () => ({ currentDriveKeys, toBase64: () => 'master' }))
const signDriveKeyBinding = vi.hoisted(() => vi.fn(() => Promise.resolve('binding')))
vi.mock('@kutup/crypto/identityPins', () => ({ signDriveKeyBinding, FIRST_DRIVE_KEY_BINDING_EPOCH: 1 }))

const { upgradedKeys } = await import('./identitySuite')

function refused(status: number, code?: string): AxiosError {
  const response = { status, data: code ? { error: 'refused', code } : { error: 'down' }, headers: {}, config: { headers: new AxiosHeaders() }, statusText: '' } as AxiosResponse
  return new AxiosError('failed', String(status), undefined, undefined, response)
}

const keys = (): SessionKeys => ({
  userId: 'u',
  masterKey: new Uint8Array(32),
  privateKey: new Uint8Array(32).fill(1),
  publicKey: 'x25519',
  keyBinding: 'kb',
})

beforeEach(() => {
  post.mockReset()
  signDriveKeyBinding.mockClear()
})

describe('the identity suite upgrade where a session starts (docs/plans/pq-shares.md)', () => {
  it('moves an account whose server still publishes the X25519 key, once, and uses the X-Wing keys', async () => {
    post.mockResolvedValue({ status: 204 })
    const upgraded = await upgradedKeys(keys(), { id: 'u', server: 'kutup.dev', publicKey: 'x25519' }, 'token')
    expect(signDriveKeyBinding).toHaveBeenCalledWith('master', { server: 'kutup.dev', accountId: 'u' }, 1)
    expect(post).toHaveBeenCalledWith(
      '/account/identity-suite',
      { publicKey: 'xwing', driveKeyBinding: 'binding', driveKeyBindingEpoch: 1, drivePrivateKeyEnvelope: 'sealed-seed' },
      { headers: { Authorization: 'Bearer token' } },
    )
    // Sealed under the binding the keys were verified under.
    expect(currentDriveKeys).toHaveBeenLastCalledWith(expect.any(Uint8Array), 'kb')
    expect(upgraded.publicKey).toBe('xwing')
    expect(upgraded.privateKey).toEqual(new Uint8Array(32).fill(7))
  })

  it('another device upgraded first: the same keys', async () => {
    post.mockRejectedValue(refused(409, 'identitySuiteCurrent'))
    expect((await upgradedKeys(keys(), { id: 'u', server: 'kutup.dev', publicKey: 'x25519' }, 'token')).publicKey).toBe('xwing')
  })

  it('a failure keeps the keys, for the next session start to try again', async () => {
    post.mockRejectedValue(refused(503))
    const given = keys()
    expect(await upgradedKeys(given, { id: 'u', server: 'kutup.dev', publicKey: 'x25519' }, 'token')).toBe(given)
  })

  it('an account already on X-Wing keys posts nothing; a session older than the upgrade takes them', async () => {
    const current = { ...keys(), publicKey: 'xwing' }
    expect(await upgradedKeys(current, { id: 'u', server: 'kutup.dev', publicKey: 'xwing' }, 'token')).toBe(current)
    const older = await upgradedKeys(keys(), { id: 'u', server: 'kutup.dev', publicKey: 'xwing' }, 'token')
    expect(older.publicKey).toBe('xwing')
    expect(post).not.toHaveBeenCalled()
  })
})
