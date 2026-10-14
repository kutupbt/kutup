import { beforeEach, describe, expect, it, vi } from 'vitest'

const post = vi.hoisted(() => vi.fn())
vi.mock('./client', () => ({ default: { post } }))

const signIn = vi.hoisted(() => ({
  request: 'ke1',
  finish: vi.fn((response: string) => Promise.resolve(`ke3-for-${response}`)),
  openMasterKey: vi.fn(),
  close: vi.fn(),
}))
const registration = vi.hoisted(() => ({
  request: 'reg-request',
  finish: vi.fn((response: string) => Promise.resolve(`record-for-${response}`)),
  sealMasterKey: vi.fn(() => Promise.resolve('envelope')),
  close: vi.fn(),
}))
vi.mock('@kutup/crypto/opaqueWorker', () => ({
  startOpaqueSignIn: vi.fn(() => Promise.resolve(signIn)),
  startOpaqueRegistration: vi.fn(() => Promise.resolve(registration)),
}))

import { opaqueLogin, opaqueRegister, opaqueReregister } from './opaque'

beforeEach(() => {
  post.mockReset()
  for (const fn of [signIn.finish, signIn.close, registration.finish, registration.sealMasterKey, registration.close]) fn.mockClear()
})

describe('opaqueLogin', () => {
  it('starts, finishes with the finalization, and keeps the sign-in open for the caller', async () => {
    post.mockImplementation((path: string) =>
      Promise.resolve({ data: path === '/auth/login/start' ? { loginId: 'L', credentialResponse: 'ke2', suite: 1 } : { grant: 'g' } }),
    )
    const { data, signIn: opened } = await opaqueLogin<{ grant: string }>('alice', 'pw', { purpose: 'reauth', for: 'pass' })
    expect(post.mock.calls).toEqual([
      ['/auth/login/start', { name: 'alice', credentialRequest: 'ke1', purpose: 'reauth', for: 'pass' }],
      ['/auth/login/finish', { loginId: 'L', credentialFinalization: 'ke3-for-ke2' }],
    ])
    expect(data).toEqual({ grant: 'g' })
    expect(opened.close).not.toHaveBeenCalled()
  })

  it('closes the sign-in when anything fails, and sends no finish for a wrong password', async () => {
    post.mockResolvedValueOnce({ data: { loginId: 'L', credentialResponse: 'ke2', suite: 1 } })
    signIn.finish.mockRejectedValueOnce(new Error('the password is not right'))
    await expect(opaqueLogin('alice', 'wrong', { purpose: 'session' })).rejects.toThrow('not right')
    expect(post).toHaveBeenCalledTimes(1)
    expect(signIn.close).toHaveBeenCalled()
  })
})

describe('opaqueRegister', () => {
  it('sends a grant in the body, a setup token as the bearer, nothing for a new account', async () => {
    post.mockResolvedValue({ data: { registrationResponse: 'resp', serverKeyId: 3 } })
    const key = new Uint8Array(32)
    expect(await opaqueRegister('pw', 'kb', key, { grant: 'g' })).toEqual({
      opaqueRecord: 'record-for-resp',
      opaqueServerKeyId: 3,
      masterKeyEnvelope: 'envelope',
    })
    expect(post.mock.calls[0]).toEqual(['/auth/opaque/register/start', { keyBinding: 'kb', registrationRequest: 'reg-request', grant: 'g' }, undefined])
    await opaqueRegister('pw', 'kb', key, { setupToken: 'setup' })
    expect(post.mock.calls[1][2]).toEqual({ headers: { Authorization: 'Bearer setup' } })
    expect(post.mock.calls[1][1]).not.toHaveProperty('grant')
    await opaqueRegister('pw', 'kb', key, null)
    expect(post.mock.calls[2][1]).toEqual({ keyBinding: 'kb', registrationRequest: 'reg-request' })
    expect(registration.close).toHaveBeenCalledTimes(3)
  })

  it('seals no envelope for a temporary password', async () => {
    post.mockResolvedValue({ data: { registrationResponse: 'resp', serverKeyId: 1 } })
    expect(await opaqueRegister('temp', 'kb', null, null)).toEqual({ opaqueRecord: 'record-for-resp', opaqueServerKeyId: 1 })
    expect(registration.sealMasterKey).not.toHaveBeenCalled()
  })

  it('re-registers with the grant at finish', async () => {
    post.mockResolvedValue({ data: { registrationResponse: 'resp', serverKeyId: 2 } })
    await opaqueReregister('new', 'kb', new Uint8Array(32), 'g')
    expect(post.mock.calls[1]).toEqual([
      '/auth/opaque/register/finish',
      { grant: 'g', keyBinding: 'kb', opaqueRecord: 'record-for-resp', opaqueServerKeyId: 2, masterKeyEnvelope: 'envelope' },
    ])
  })
})
