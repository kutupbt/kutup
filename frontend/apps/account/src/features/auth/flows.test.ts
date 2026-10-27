import { AxiosError, AxiosHeaders, type AxiosResponse } from 'axios'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { AccountKeys } from './flows'

const post = vi.hoisted(() => vi.fn())
vi.mock('@kutup/session/client', () => ({ default: { post, get: vi.fn() } }))
vi.mock('@kutup/session/persist', () => ({ persistKeys: vi.fn() }))
const crypto_ = vi.hoisted(() => ({
  toBase64: () => 'master',
  driveKeysOf: vi.fn(() => Promise.resolve({ publicKey: 'p', privateKey: new Uint8Array(32) })),
  generateAccountKeySet: vi.fn((binding: string) => Promise.resolve({ mnemonic: 'words', masterKey: new Uint8Array(32), recoveryProof: `proof-${binding}` })),
  rebindAccountKeySet: vi.fn((keys: { mnemonic: string }, binding: string) =>
    Promise.resolve({ mnemonic: keys.mnemonic, masterKey: new Uint8Array(32), recoveryProof: `proof-${binding}`, recoveryKeyEnvelope: `recovery-${binding}` }),
  ),
}))
vi.mock('@kutup/crypto', () => crypto_)
const registrar = vi.hoisted(() => ({ register: vi.fn(), close: vi.fn() }))
vi.mock('@kutup/crypto/opaqueWorker', () => ({ startOpaqueRegistration: vi.fn(() => Promise.resolve(registrar)) }))
const signDriveKeyBinding = vi.hoisted(() => vi.fn(() => Promise.resolve('binding')))
vi.mock('@kutup/crypto/identityPins', () => ({ signDriveKeyBinding, FIRST_DRIVE_KEY_BINDING_EPOCH: 1 }))
vi.mock('@kutup/session/apps', () => ({ loadServerSettings: vi.fn(() => Promise.resolve({ chat: { serverName: 'kutup.dev' } })) }))
const opaque = vi.hoisted(() => ({
  opaqueLogin: vi.fn(),
  opaqueReregister: vi.fn(),
  registerWith: vi.fn(),
  reregisterWith: vi.fn(),
  conflictCode: (error: unknown) =>
    (error as { response?: { status: number; data: { code?: string } } }).response?.status === 409
      ? ((error as { response: { data: { code?: string } } }).response.data.code ?? null)
      : null,
}))
vi.mock('@kutup/session/opaque', () => opaque)
// What it activated: the keys given (the session layer's upgrade is tested there).
const activateSession = vi.hoisted(() => vi.fn((keys: unknown) => Promise.resolve(keys)))
vi.mock('@kutup/session/profile', () => ({ activateSession }))

import { abandonTotp, completeTotp, generateAccountKeys, registerAndSignIn, RegistrationConflictError, signIn } from './flows'

function refused(status: number, code?: string): AxiosError {
  const response = { status, data: code ? { error: 'refused', code } : { error: 'slow down' }, headers: {}, config: { headers: new AxiosHeaders() }, statusText: '' } as AxiosResponse
  return new AxiosError('failed', String(status), undefined, undefined, response)
}

const keys = () =>
  ({
    opaqueRecord: 'record',
    opaqueServerKeyId: 1,
    masterKeyEnvelope: 'envelope',
    accountId: '11111111-1111-4111-8111-111111111111',
    accountIdProof: 'proof',
    mnemonic: 'words',
    masterKey: new Uint8Array(32),
    privateKey: new Uint8Array(32),
    publicKey: new Uint8Array(32),
    keyBinding: '3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70',
    registrar,
    auth: null,
  }) as unknown as AccountKeys

beforeEach(() => {
  post.mockReset()
  activateSession.mockClear()
  registrar.close.mockClear()
  opaque.registerWith.mockReset()
  opaque.reregisterWith.mockReset()
  opaque.opaqueLogin.mockReset()
  crypto_.rebindAccountKeySet.mockClear()
})

function openSignIn() {
  return { request: 'ke1', finish: vi.fn(), openMasterKey: vi.fn(() => Promise.resolve(new Uint8Array(32))), register: vi.fn(), close: vi.fn() }
}

const session = { accessToken: 'a', sessionId: 's', userId: 'u', username: 'alice', masterKeyEnvelope: 'm', publicKey: 'p', keyBinding: 'kb' }

describe('signIn', () => {
  it('registers nothing again unless the server asks, and ends the sign-in', async () => {
    const opened = openSignIn()
    opaque.opaqueLogin.mockResolvedValue({ data: session, signIn: opened })
    await expect(signIn('alice', 'pw')).resolves.toEqual({ kind: 'signedIn' })
    expect(opaque.reregisterWith).not.toHaveBeenCalled()
    expect(opened.close).toHaveBeenCalled()
  })

  it('rotates through the sign-in itself (its worker holds the password), and a failed rotation still signs in', async () => {
    const opened = openSignIn()
    opaque.opaqueLogin.mockResolvedValue({ data: { ...session, rotate: true, grant: 'kg1_rotate' }, signIn: opened })
    opaque.reregisterWith.mockRejectedValue(new Error('offline'))
    await expect(signIn('alice', 'pw')).resolves.toEqual({ kind: 'signedIn' })
    expect(opaque.reregisterWith).toHaveBeenCalledWith(opened, 'kb', expect.any(Uint8Array), 'kg1_rotate')
    expect(opened.close).toHaveBeenCalled()
  })

  it('a second factor keeps the open sign-in, never the password; the code finishes it, rotation included', async () => {
    const opened = openSignIn()
    opaque.opaqueLogin.mockResolvedValue({ data: { requiresTotp: true, preAuthToken: 'pre' }, signIn: opened })
    const result = await signIn('alice', 'pw')
    if (result.kind !== 'totp') throw new Error('expected a code step')
    expect(Object.keys(result.challenge).sort()).toEqual(['name', 'preAuthToken', 'signIn'])
    expect(JSON.stringify(result.challenge)).not.toContain('pw')
    expect(opened.close).not.toHaveBeenCalled()
    post.mockResolvedValue({ data: { ...session, rotate: true, grant: 'kg1_rotate' } })
    opaque.reregisterWith.mockResolvedValue(undefined)
    await completeTotp(result.challenge, '123456')
    expect(opaque.reregisterWith).toHaveBeenCalledWith(opened, 'kb', expect.any(Uint8Array), 'kg1_rotate')
    expect(opened.close).toHaveBeenCalled()
  })

  it('a sign-in given up at its code is ended', async () => {
    const opened = openSignIn()
    opaque.opaqueLogin.mockResolvedValue({ data: { requiresTotp: true, preAuthToken: 'pre' }, signIn: opened })
    const result = await signIn('alice', 'pw')
    if (result.kind !== 'totp') throw new Error('expected a code step')
    abandonTotp(result.challenge)
    expect(opened.close).toHaveBeenCalled()
  })
})

describe('generateAccountKeys', () => {
  it('draws another binding when the first is taken', async () => {
    opaque.registerWith
      .mockRejectedValueOnce(refused(409, 'keyBindingTaken'))
      .mockResolvedValue({ opaqueRecord: 'record', opaqueServerKeyId: 1, masterKeyEnvelope: 'envelope' })
    const made = await generateAccountKeys('pw')
    const [first, second] = opaque.registerWith.mock.calls.map((call) => call[1] as string)
    expect(first).not.toBe(second)
    expect(made.keyBinding).toBe(second)
    expect(made.registrar).toBe(registrar)
    expect(registrar.close).not.toHaveBeenCalled()
  })

  it('ends the worker when the keys cannot be made', async () => {
    opaque.registerWith.mockRejectedValue(refused(429))
    await expect(generateAccountKeys('pw')).rejects.toBeInstanceOf(AxiosError)
    expect(registrar.close).toHaveBeenCalled()
  })
})

describe('registerAndSignIn', () => {
  it('creates the account once, and its session comes with it; the password worker ends', async () => {
    post.mockResolvedValue({ data: { userId: 'u1', accessToken: 'a', sessionId: 's' } })
    activateSession.mockRejectedValueOnce(new Error('storage'))
    const k = keys()
    await expect(registerAndSignIn('a', k)).rejects.toThrow('storage')
    expect(registrar.close).not.toHaveBeenCalled()
    await registerAndSignIn('a', k)
    expect(post.mock.calls.map(([path]) => path as string)).toEqual(['/auth/register'])
    expect(activateSession).toHaveBeenCalledTimes(2)
    expect(registrar.close).toHaveBeenCalled()
    // The password registered with the keys, the id the server minted for
    // the sign-up and the Drive key binding for that id go with it
    // (docs/plans/opaque.md, account-ids.md).
    expect(signDriveKeyBinding).toHaveBeenCalledWith(
      expect.any(String),
      { server: 'kutup.dev', accountId: '11111111-1111-4111-8111-111111111111' },
      1,
    )
    expect(post.mock.calls[0][1]).toMatchObject({
      username: 'a',
      accountId: '11111111-1111-4111-8111-111111111111',
      accountIdProof: 'proof',
      driveKeyBinding: 'binding',
      opaqueRecord: 'record',
      opaqueServerKeyId: 1,
      masterKeyEnvelope: 'envelope',
    })
  })

  it('registers again after a failed registration', async () => {
    post.mockRejectedValueOnce(refused(429)).mockResolvedValue({ data: { userId: 'u1', accessToken: 'a' } })
    const k = keys()
    await expect(registerAndSignIn('a', k)).rejects.toBeInstanceOf(AxiosError)
    await registerAndSignIn('a', k)
    expect(post.mock.calls.map(([path]) => path as string)).toEqual(['/auth/register', '/auth/register'])
  })

  it('a record made under a server key since changed is made again, same binding, and sent once more', async () => {
    post.mockRejectedValueOnce(refused(409, 'opaqueKeyStale')).mockResolvedValue({ data: { userId: 'u1', accessToken: 'a' } })
    const second = '22222222-2222-4222-8222-222222222222'
    opaque.registerWith.mockResolvedValue({ opaqueRecord: 'record-2', opaqueServerKeyId: 2, masterKeyEnvelope: 'envelope-2', accountId: second, accountIdProof: 'proof-2' })
    const k = keys()
    await registerAndSignIn('a', k)
    expect(opaque.registerWith).toHaveBeenCalledWith(registrar, k.keyBinding, k.masterKey, null)
    // The new start minted a new id: the binding names that one.
    expect(post.mock.calls[1][1]).toMatchObject({ keyBinding: k.keyBinding, opaqueRecord: 'record-2', opaqueServerKeyId: 2, accountId: second, accountIdProof: 'proof-2' })
    expect(signDriveKeyBinding).toHaveBeenLastCalledWith(expect.any(String), { server: 'kutup.dev', accountId: second }, 1)
    expect(crypto_.rebindAccountKeySet).not.toHaveBeenCalled()
  })

  it('a binding taken meanwhile is drawn again: the records sealed again, the phrase kept', async () => {
    post.mockRejectedValueOnce(refused(409, 'keyBindingTaken')).mockResolvedValue({ data: { userId: 'u1', accessToken: 'a' } })
    opaque.registerWith.mockResolvedValue({ opaqueRecord: 'record-2', opaqueServerKeyId: 1, masterKeyEnvelope: 'envelope-2' })
    const k = keys()
    await registerAndSignIn('a', k)
    const binding = (post.mock.calls[1][1] as { keyBinding: string }).keyBinding
    expect(binding).not.toBe(k.keyBinding)
    expect(crypto_.rebindAccountKeySet).toHaveBeenCalledWith(k, binding)
    expect(post.mock.calls[1][1]).toMatchObject({ recoveryKeyEnvelope: `recovery-${binding}`, recoveryProof: `proof-${binding}`, opaqueRecord: 'record-2' })
    // The session holds the keys the server took.
    expect(activateSession.mock.calls[0][0]).toMatchObject({ keyBinding: binding })
  })

  it('refused twice for the same reason: says so', async () => {
    post.mockRejectedValue(refused(409, 'opaqueKeyStale'))
    opaque.registerWith.mockResolvedValue({ opaqueRecord: 'record-2', opaqueServerKeyId: 2, masterKeyEnvelope: 'envelope-2' })
    await expect(registerAndSignIn('a', keys())).rejects.toEqual(new RegistrationConflictError('opaqueKeyStale'))
    expect(post).toHaveBeenCalledTimes(2)
  })
})

describe('completeSetup', () => {
  it('sends the new keys with their Drive key binding', async () => {
    post.mockResolvedValue({ data: { userId: 'u1', accessToken: 'a', sessionId: 's' } })
    const { completeSetup } = await import('./flows')
    const accountId = '33333333-3333-4333-8333-333333333333'
    await completeSetup({ name: 'a@kutup.dev', username: 'a', accountId, setupToken: 'setup' }, keys())
    expect(post.mock.calls[0][0]).toBe('/auth/complete-setup')
    expect(post.mock.calls[0][1]).toMatchObject({ keyBinding: keys().keyBinding, driveKeyBinding: 'binding' })
    // The binding names the account by its id; the setup sends no minted id.
    expect(signDriveKeyBinding).toHaveBeenLastCalledWith(expect.any(String), { server: 'kutup.dev', accountId }, 1)
    expect(post.mock.calls[0][1]).not.toHaveProperty('accountId')
    expect(post.mock.calls[0][2]).toMatchObject({ headers: { Authorization: 'Bearer setup' } })
  })
})
