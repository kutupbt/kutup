import { AxiosError, AxiosHeaders } from 'axios'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const listDevices = vi.fn()
const registerDevice = vi.fn()
const renewDevice = vi.fn()
vi.mock('./api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./api')>()
  return {
    isDeviceNotAuthorized: actual.isDeviceNotAuthorized,
    isTooManyDevices: actual.isTooManyDevices,
    listDevices: () => listDevices(),
    registerDevice: (...a: unknown[]) => registerDevice(...a),
    renewDevice: (...a: unknown[]) => renewDevice(...a),
  }
})
const persistDevice = vi.fn()
vi.mock('@kutup/session/persist', () => ({ persistDevice: (d: unknown) => persistDevice(d) }))
let session: { device: unknown } | null = null
vi.mock('@kutup/session/store', () => ({ getSession: () => session }))
vi.mock('./devices', () => ({
  generateDeviceKeypair: async () => ({ publicKey: new Uint8Array(32).fill(9), privateKey: new Uint8Array(64).fill(8) }),
  encodePubKeyB64: () => 'PUB',
}))

import {
  currentDevice,
  deviceRefused,
  RENEW_AFTER_MS,
  renewRequested,
  resetCurrentDeviceForTesting,
  TooManyDevicesError,
} from './currentDevice'

function httpError(status: number, code: string) {
  return new AxiosError('x', 'ERR', undefined, undefined, {
    status,
    statusText: '',
    data: { code },
    headers: {},
    config: { headers: new AxiosHeaders() },
  })
}
const kept = (issuedAtMs = Date.now()) => ({
  id: 5,
  publicKey: new Uint8Array(32).fill(1),
  privateKey: new Uint8Array(64).fill(2),
  issuedAtMs,
})

beforeEach(() => {
  vi.clearAllMocks()
  resetCurrentDeviceForTesting()
  session = { device: null }
  // What persistDevice does to the session.
  persistDevice.mockImplementation(async (d: unknown) => {
    if (session) session.device = d
  })
  registerDevice.mockResolvedValue({ deviceId: 11, issuedAtMs: 1000 })
})

describe('currentDevice', () => {
  it('registers one device per sign-in and keeps it with the keys', async () => {
    const [a, b] = await Promise.all([currentDevice(), currentDevice()])
    expect(registerDevice).toHaveBeenCalledTimes(1)
    expect(a.deviceId).toBe(11)
    expect(b.deviceId).toBe(11)
    expect(persistDevice).toHaveBeenCalledWith(expect.objectContaining({ id: 11, issuedAtMs: 1000 }))
  })

  it('reuses the kept device once the server still trusts it', async () => {
    session = { device: kept() }
    listDevices.mockResolvedValue([{ deviceId: 5, trusted: true }])
    expect((await currentDevice()).deviceId).toBe(5)
    expect(await currentDevice()).toMatchObject({ deviceId: 5 })
    expect(listDevices).toHaveBeenCalledTimes(1) // once per page
    expect(registerDevice).not.toHaveBeenCalled()
  })

  it('goes on with the kept device when the list cannot be read', async () => {
    session = { device: kept() }
    listDevices.mockRejectedValue(new Error('offline'))
    expect((await currentDevice()).deviceId).toBe(5)
    expect(registerDevice).not.toHaveBeenCalled()
  })

  it('replaces a device the server no longer trusts', async () => {
    session = { device: kept() }
    listDevices.mockResolvedValue([{ deviceId: 5, trusted: false }])
    expect((await currentDevice()).deviceId).toBe(11)
    expect(persistDevice).toHaveBeenCalledWith(null)
  })

  it('renews a statement after 15 days with the same key', async () => {
    session = { device: kept(Date.now() - RENEW_AFTER_MS - 1) }
    listDevices.mockResolvedValue([{ deviceId: 5, trusted: true }])
    renewDevice.mockResolvedValue(42)
    expect((await currentDevice()).deviceId).toBe(5)
    expect(renewDevice).toHaveBeenCalledWith(5, 'PUB')
    expect(persistDevice).toHaveBeenCalledWith(expect.objectContaining({ id: 5, issuedAtMs: 42 }))
    expect(registerDevice).not.toHaveBeenCalled()
  })

  it('never removes a device for the user at the cap', async () => {
    registerDevice.mockRejectedValue(httpError(409, 'tooManyDevices'))
    await expect(currentDevice()).rejects.toBeInstanceOf(TooManyDevicesError)
    expect(listDevices).not.toHaveBeenCalled()
  })

  it('replaces a refused device once per page', async () => {
    session = { device: kept() }
    expect(await deviceRefused()).toBe(true)
    expect(persistDevice).toHaveBeenCalledWith(null)
    expect(await deviceRefused()).toBe(false)
  })

  it('renews when a shared file’s server asks for this device', async () => {
    session = { device: kept() }
    renewDevice.mockResolvedValue(77)
    await renewRequested([3])
    expect(renewDevice).not.toHaveBeenCalled()
    await renewRequested([5])
    expect(persistDevice).toHaveBeenCalledWith(expect.objectContaining({ id: 5, issuedAtMs: 77 }))
  })
})
