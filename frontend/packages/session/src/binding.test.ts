import { beforeEach, describe, expect, it, vi } from 'vitest'

const get = vi.fn()
vi.mock('./client', () => ({ default: { get: (...args: unknown[]) => get(...args) } }))
const { refreshEnvelopeBinding, isBindingChanged } = await import('./binding')
const { getSession, setSession } = await import('./store')

const session = {
  sessionId: 's',
  userId: 'u1',
  address: 'dev@kutup.dev',
  envelopeBinding: 'dev@old.example',
  username: 'dev',
  isAdmin: false,
  storageQuotaBytes: 0,
  storageUsedBytes: 0,
  totpEnabled: false,
  color: null,
  publicKey: '',
  masterKey: new Uint8Array(32),
  privateKey: new Uint8Array(32),
  currentDeviceId: null,
}

beforeEach(() => {
  get.mockReset()
  setSession({ ...session }, 'token')
})

describe('refreshEnvelopeBinding', () => {
  it('takes the server’s binding into the session', async () => {
    get.mockResolvedValue({ data: { id: 'u1', envelopeBinding: '3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70' } })
    await expect(refreshEnvelopeBinding()).resolves.toBe('3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70')
    expect(getSession()?.envelopeBinding).toBe('3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70')
  })

  it('leaves another account’s session alone', async () => {
    get.mockResolvedValue({ data: { id: 'u2', envelopeBinding: 'x' } })
    await refreshEnvelopeBinding()
    expect(getSession()?.envelopeBinding).toBe('dev@old.example')
  })
})

describe('isBindingChanged', () => {
  it('knows the refusal by its status and code only', () => {
    expect(isBindingChanged({ response: { status: 409, data: { code: 'bindingChanged' } } })).toBe(true)
    expect(isBindingChanged({ response: { status: 409, data: { code: 'other' } } })).toBe(false)
    expect(isBindingChanged({ response: { status: 400, data: { code: 'bindingChanged' } } })).toBe(false)
    expect(isBindingChanged(new Error('x'))).toBe(false)
  })
})
