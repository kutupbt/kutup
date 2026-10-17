import { AxiosError, AxiosHeaders, type AxiosResponse } from 'axios'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const post = vi.hoisted(() => vi.fn())
vi.mock('./client', () => ({ default: { post } }))

const signIn = vi.hoisted(() => ({
  request: 'ke1',
  finish: vi.fn((response: string) => Promise.resolve(`ke3-for-${response}`)),
  openMasterKey: vi.fn(),
  register: vi.fn(),
  close: vi.fn(),
}))
const registration = vi.hoisted(() => ({
  request: 'reg-request',
  finish: vi.fn((response: string) => Promise.resolve(`record-for-${response}`)),
  sealMasterKey: vi.fn(() => Promise.resolve('envelope')),
}))
const registrar = vi.hoisted(() => ({
  register: vi.fn(() => Promise.resolve(registration)),
  close: vi.fn(),
}))
vi.mock('@kutup/crypto/opaqueWorker', () => ({
  startOpaqueSignIn: vi.fn(() => Promise.resolve(signIn)),
  startOpaqueRegistration: vi.fn(() => Promise.resolve(registrar)),
}))

import { conflictCode, opaqueLogin, opaqueRegister, opaqueReregister, registerWith, reregisterWith } from './opaque'

function refused(status: number, code?: string): AxiosError {
  const response = { status, data: code ? { error: 'refused', code } : { error: 'refused' }, headers: {}, config: { headers: new AxiosHeaders() }, statusText: '' } as AxiosResponse
  return new AxiosError('refused', String(status), undefined, undefined, response)
}

beforeEach(() => {
  post.mockReset()
  for (const fn of [signIn.finish, signIn.close, registration.finish, registration.sealMasterKey, registrar.register, registrar.close]) fn.mockClear()
})

describe('opaqueLogin', () => {
  it('starts, finishes with the finalization, and keeps the sign-in open for the caller; a reauth names no account', async () => {
    post.mockImplementation((path: string) =>
      Promise.resolve({ data: path === '/auth/login/start' ? { loginId: 'L', credentialResponse: 'ke2', suite: 1 } : { grant: 'g' } }),
    )
    const { data, signIn: opened } = await opaqueLogin<{ grant: string }>('pw', { purpose: 'reauth', for: 'pass' })
    expect(post.mock.calls).toEqual([
      ['/auth/login/start', { credentialRequest: 'ke1', purpose: 'reauth', for: 'pass' }],
      ['/auth/login/finish', { loginId: 'L', credentialFinalization: 'ke3-for-ke2' }],
    ])
    expect(data).toEqual({ grant: 'g' })
    expect(opened.close).not.toHaveBeenCalled()
  })

  it('closes the sign-in when anything fails, and sends no finish for a wrong password', async () => {
    post.mockResolvedValueOnce({ data: { loginId: 'L', credentialResponse: 'ke2', suite: 1 } })
    signIn.finish.mockRejectedValueOnce(new Error('the password is not right'))
    await expect(opaqueLogin('wrong', { purpose: 'session', name: 'alice' })).rejects.toThrow('not right')
    expect(post).toHaveBeenCalledTimes(1)
    expect(post.mock.calls[0]?.[1]).toMatchObject({ purpose: 'session', name: 'alice' })
    expect(signIn.close).toHaveBeenCalled()
  })
})

describe('registerWith', () => {
  it('sends a grant in the body, a setup token as the bearer, nothing for a new account; the registrar stays open', async () => {
    post.mockResolvedValue({ data: { registrationResponse: 'resp', serverKeyId: 3 } })
    const key = new Uint8Array(32)
    expect(await registerWith(registrar, 'kb', key, { grant: 'g' })).toEqual({
      opaqueRecord: 'record-for-resp',
      opaqueServerKeyId: 3,
      masterKeyEnvelope: 'envelope',
    })
    expect(post.mock.calls[0]).toEqual(['/auth/opaque/register/start', { keyBinding: 'kb', registrationRequest: 'reg-request', grant: 'g' }, undefined])
    await registerWith(registrar, 'kb', key, { setupToken: 'setup' })
    expect(post.mock.calls[1][2]).toEqual({ headers: { Authorization: 'Bearer setup' } })
    expect(post.mock.calls[1][1]).not.toHaveProperty('grant')
    await registerWith(registrar, 'kb', key, null)
    expect(post.mock.calls[2][1]).toEqual({ keyBinding: 'kb', registrationRequest: 'reg-request' })
    expect(registrar.register).toHaveBeenCalledTimes(3)
    expect(registrar.close).not.toHaveBeenCalled()
  })

  it('seals no envelope for a temporary password, and its worker ends with it', async () => {
    post.mockResolvedValue({ data: { registrationResponse: 'resp', serverKeyId: 1 } })
    expect(await opaqueRegister('temp', 'kb', null, null)).toEqual({ opaqueRecord: 'record-for-resp', opaqueServerKeyId: 1 })
    expect(registration.sealMasterKey).not.toHaveBeenCalled()
    expect(registrar.close).toHaveBeenCalledTimes(1)
  })
})

describe('reregisterWith', () => {
  it('re-registers with the grant at finish', async () => {
    post.mockResolvedValue({ data: { registrationResponse: 'resp', serverKeyId: 2 } })
    await opaqueReregister('new', 'kb', new Uint8Array(32), 'g')
    expect(post.mock.calls[1]).toEqual([
      '/auth/opaque/register/finish',
      { grant: 'g', keyBinding: 'kb', opaqueRecord: 'record-for-resp', opaqueServerKeyId: 2, masterKeyEnvelope: 'envelope' },
    ])
    expect(registrar.close).toHaveBeenCalledTimes(1)
  })

  it('makes a record refused as stale again, once, from the same held password', async () => {
    let finishes = 0
    post.mockImplementation((path: string) => {
      if (path === '/auth/opaque/register/finish' && finishes++ === 0) return Promise.reject(refused(409, 'opaqueKeyStale'))
      return Promise.resolve({ data: { registrationResponse: 'resp', serverKeyId: 4 } })
    })
    await reregisterWith(registrar, 'kb', new Uint8Array(32), 'g')
    expect(post.mock.calls.map(([path]) => path as string)).toEqual([
      '/auth/opaque/register/start',
      '/auth/opaque/register/finish',
      '/auth/opaque/register/start',
      '/auth/opaque/register/finish',
    ])
    expect(registrar.register).toHaveBeenCalledTimes(2)
  })

  it('gives up after a second stale answer, and on any other refusal at once', async () => {
    post.mockImplementation((path: string) =>
      path === '/auth/opaque/register/finish'
        ? Promise.reject(refused(409, 'opaqueKeyStale'))
        : Promise.resolve({ data: { registrationResponse: 'resp', serverKeyId: 4 } }),
    )
    await expect(reregisterWith(registrar, 'kb', new Uint8Array(32), 'g')).rejects.toBeInstanceOf(AxiosError)
    expect(registrar.register).toHaveBeenCalledTimes(2)
    registrar.register.mockClear()
    post.mockImplementation((path: string) =>
      path === '/auth/opaque/register/finish'
        ? Promise.reject(refused(401))
        : Promise.resolve({ data: { registrationResponse: 'resp', serverKeyId: 4 } }),
    )
    await expect(reregisterWith(registrar, 'kb', new Uint8Array(32), 'g')).rejects.toBeInstanceOf(AxiosError)
    expect(registrar.register).toHaveBeenCalledTimes(1)
  })
})

describe('conflictCode', () => {
  it('reads the code of a 409 only', () => {
    expect(conflictCode(refused(409, 'keyBindingTaken'))).toBe('keyBindingTaken')
    expect(conflictCode(refused(409))).toBeNull()
    expect(conflictCode(refused(400, 'keyBindingTaken'))).toBeNull()
    expect(conflictCode(new Error('x'))).toBeNull()
  })
})
