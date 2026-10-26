import { AxiosError, AxiosHeaders } from 'axios'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { AccountDevice } from './devices'
import type { DeviceKeys } from './keys'

const ACCOUNT = 'aci:00000000-0000-4000-8000-000000000001@kutup.example'
const SESSION_HASH = 'ab'.repeat(32)

const listAccountDevices = vi.fn<() => Promise<AccountDevice[]>>()
const fetchManifest = vi.fn()
const registerDevice = vi.fn()
const published: unknown[] = []
/** The head the next publication follows, and what it becomes. */
let head: { sequence: number; devices: { deviceId: number; frameKey?: string; session: string }[] } | null = null
let publishError: unknown = null
vi.mock('./devices', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./devices')>()
  return {
    ...actual,
    ownAccount: async () => ACCOUNT,
    listAccountDevices: () => listAccountDevices(),
    fetchManifest: (account: string) => fetchManifest(account),
    registerDevice: (request: unknown) => registerDevice(request),
    publishNextManifest: async (_account: string, header: string, next: (h: unknown) => Promise<unknown>) => {
      if (publishError) throw publishError
      const manifest = (await next(head)) as typeof head
      published.push({ header, manifest })
      head = manifest
      return manifest
    },
  }
})
vi.mock('@kutup/crypto/accountManifest', () => ({
  listDeviceInManifest: async (current: typeof head, entry: { deviceId: number }) => ({
    sequence: (current?.sequence ?? 0) + 1,
    devices: [...(current?.devices ?? []).filter((d) => d.deviceId !== entry.deviceId), entry],
  }),
}))
vi.mock('@kutup/crypto/signing', () => ({
  generateSigningKey: async () => ({ publicKey: new Uint8Array(32).fill(9), privateKey: new Uint8Array(64).fill(8) }),
}))
const persistDevice = vi.fn()
vi.mock('./persist', () => ({ persistDevice: (d: unknown) => persistDevice(d) }))
let session: { userId: string; masterKey: Uint8Array; device: DeviceKeys | null } | null = null
vi.mock('./store', () => ({ getSession: () => session }))

import {
  currentDevice,
  deviceRefused,
  replaceRefusedDevice,
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

const KEPT_KEY = btoa(String.fromCharCode(...new Uint8Array(32).fill(1)))
const kept = (manifestSequence = 3n): DeviceKeys => ({
  id: 5,
  publicKey: new Uint8Array(32).fill(1),
  privateKey: new Uint8Array(64).fill(2),
  credential: new Uint8Array(32).fill(0xfb),
  manifestSequence,
})
const row = (patch: Partial<AccountDevice> = {}): AccountDevice => ({
  deviceId: 5,
  kind: 'editor',
  name: 'office',
  session: SESSION_HASH,
  thisSignIn: true,
  listed: true,
  expired: false,
  createdAt: '2026-10-01T00:00:00Z',
  ...patch,
})

beforeEach(() => {
  vi.clearAllMocks()
  resetCurrentDeviceForTesting()
  published.length = 0
  publishError = null
  head = { sequence: 4, devices: [{ deviceId: 1, session: 'cd'.repeat(32) }] }
  session = { userId: '00000000-0000-4000-8000-000000000001', masterKey: new Uint8Array(32), device: null }
  // What persistDevice does to the session.
  persistDevice.mockImplementation(async (d: DeviceKeys | null) => {
    if (session) session.device = d
  })
  fetchManifest.mockImplementation(async () => head)
  listAccountDevices.mockResolvedValue([])
  registerDevice.mockResolvedValue({ deviceId: 11, session: SESSION_HASH })
})

describe('currentDevice', () => {
  it('registers one device per sign-in, lists it, and keeps it with the keys', async () => {
    const [a, b] = await Promise.all([currentDevice(), currentDevice()])
    expect(registerDevice).toHaveBeenCalledTimes(1)
    expect(registerDevice).toHaveBeenCalledWith(expect.objectContaining({ kind: 'editor', frameKey: btoa(String.fromCharCode(...new Uint8Array(32).fill(9))) }))
    // 43 characters: 32 bytes as unpadded base64url.
    expect((registerDevice.mock.calls[0]![0] as { credential: string }).credential).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(a).toMatchObject({ deviceId: 11, account: ACCOUNT, manifestSequence: 5n })
    expect(a.header).toMatch(/^11\.[A-Za-z0-9_-]{43}$/)
    expect(b.deviceId).toBe(11)
    // Its entry in the next manifest, published as itself.
    expect(published).toEqual([
      {
        header: a.header,
        manifest: expect.objectContaining({ sequence: 5, devices: expect.arrayContaining([expect.objectContaining({ deviceId: 11, kind: 'editor', session: SESSION_HASH })]) }),
      },
    ])
    // Kept before listing (a cut-short listing is finished later), then with the head's sequence.
    expect(persistDevice).toHaveBeenNthCalledWith(1, expect.objectContaining({ id: 11, manifestSequence: 0n }))
    expect(persistDevice).toHaveBeenLastCalledWith(expect.objectContaining({ id: 11, manifestSequence: 5n }))
  })

  it('reuses the kept device the head lists, checked once per page', async () => {
    session!.device = kept()
    head = { sequence: 9, devices: [{ deviceId: 5, frameKey: KEPT_KEY, session: SESSION_HASH }] }
    listAccountDevices.mockResolvedValue([row()])
    expect(await currentDevice()).toMatchObject({ deviceId: 5, manifestSequence: 9n })
    expect(await currentDevice()).toMatchObject({ deviceId: 5, manifestSequence: 9n })
    expect(listAccountDevices).toHaveBeenCalledTimes(1)
    expect(registerDevice).not.toHaveBeenCalled()
    expect(published).toHaveLength(0)
  })

  it('goes on with the kept device when the list cannot be read', async () => {
    session!.device = kept(3n)
    listAccountDevices.mockRejectedValue(new Error('offline'))
    expect(await currentDevice()).toMatchObject({ deviceId: 5, manifestSequence: 3n })
    expect(registerDevice).not.toHaveBeenCalled()
  })

  it('finishes a listing cut short instead of registering again', async () => {
    session!.device = kept(0n)
    listAccountDevices.mockResolvedValue([row({ listed: false })])
    expect(await currentDevice()).toMatchObject({ deviceId: 5, manifestSequence: 5n })
    expect(registerDevice).not.toHaveBeenCalled()
    expect(published).toHaveLength(1)
  })

  it('replaces a device the account no longer lists', async () => {
    session!.device = kept()
    listAccountDevices.mockResolvedValue([])
    expect((await currentDevice()).deviceId).toBe(11)
    expect(persistDevice).toHaveBeenCalledWith(null)
  })

  it('replaces an idle device, and one whose id is now another key’s', async () => {
    session!.device = kept()
    listAccountDevices.mockResolvedValue([row({ expired: true })])
    expect((await currentDevice()).deviceId).toBe(11)

    resetCurrentDeviceForTesting()
    session!.device = kept()
    head = { sequence: 9, devices: [{ deviceId: 5, frameKey: 'other', session: SESSION_HASH }] }
    listAccountDevices.mockResolvedValue([row()])
    expect((await currentDevice()).deviceId).toBe(11)
  })

  it('never removes a device for the user at the limit', async () => {
    registerDevice.mockRejectedValue(httpError(409, 'deviceLimit'))
    await expect(currentDevice()).rejects.toBeInstanceOf(TooManyDevicesError)
    expect(published).toHaveLength(0)
  })

  it('maps a listing refused at the limit too', async () => {
    publishError = httpError(409, 'deviceLimit')
    await expect(currentDevice()).rejects.toBeInstanceOf(TooManyDevicesError)
    // The row stays kept: a later page lists it.
    expect(session!.device).toMatchObject({ id: 11, manifestSequence: 0n })
  })

  it('replaces a refused device once per page', async () => {
    session!.device = kept()
    expect(await deviceRefused()).toBe(true)
    expect(persistDevice).toHaveBeenCalledWith(null)
    expect(await deviceRefused()).toBe(false)
  })

  it('replaces a refused device only when the account stopped listing it', async () => {
    session!.device = kept()
    head = { sequence: 9, devices: [{ deviceId: 5, frameKey: KEPT_KEY, session: SESSION_HASH }] }
    listAccountDevices.mockResolvedValue([row()])
    const device = await currentDevice()
    expect(await replaceRefusedDevice(device)).toBeNull()

    head = { sequence: 10, devices: [{ deviceId: 1, session: 'cd'.repeat(32) }] }
    listAccountDevices.mockResolvedValue([])
    expect(await replaceRefusedDevice(device)).toMatchObject({ deviceId: 11 })
  })
})
