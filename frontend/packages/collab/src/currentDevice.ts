// This sign-in's collaboration device on this origin
// (docs/plans/device-registration.md): the Ed25519 key its frames are signed
// with and the server's id for it. One device per sign-in, shared by the
// origin's tabs and sealed with the session's keys, so reloads and new tabs
// reuse it; it ends with the sign-in. One place for every editor (notes and
// lists, office documents, whiteboards).
//
// The device is checked once per page against the account's device list: a
// device the server no longer trusts (revoked under Account → Devices, or
// from before an account reset) is replaced, never a reason to sign out.

import { persistDevice } from '@kutup/session/persist'
import { getSession } from '@kutup/session/store'
import type { DeviceKeys } from '@kutup/session/keys'
import { isDeviceNotAuthorized, isTooManyDevices, listDevices, registerDevice, renewDevice } from './api'
import { encodePubKeyB64, generateDeviceKeypair, type DeviceKeypair } from './devices'

/** A statement this old is renewed: other servers trust one 30 days. */
export const RENEW_AFTER_MS = 15 * 24 * 3600 * 1000

export interface CurrentDevice {
  deviceId: number
  keypair: DeviceKeypair
}

/**
 * The account has 20 devices in use: this browser gets none until the user
 * removes one under Account → Devices. Never chosen for them.
 */
export class TooManyDevicesError extends Error {
  constructor() {
    super('too many devices in use for this account')
    this.name = 'TooManyDevicesError'
  }
}

/** The device checked on this page. */
let checked: number | null = null
/** The device being worked out now: concurrent callers share it. */
let pending: Promise<CurrentDevice> | null = null
/** A refusal mid-session sends the page through registration again, once. */
let recheckUsed = false

function asCurrent(device: DeviceKeys): CurrentDevice {
  return { deviceId: device.id, keypair: { publicKey: device.publicKey, privateKey: device.privateKey } }
}

/** Whether the server still trusts `device`; null when that cannot be told now. */
async function stillTrusted(device: DeviceKeys): Promise<boolean | null> {
  try {
    return (await listDevices()).some((row) => row.deviceId === device.id && row.trusted)
  } catch {
    // The list cannot be read now: go on with the device; the socket says
    // if the server refuses it.
    return null
  }
}

async function renewed(device: DeviceKeys): Promise<DeviceKeys | null> {
  try {
    const issuedAtMs = await renewDevice(device.id, encodePubKeyB64(device.publicKey))
    const next = { ...device, issuedAtMs }
    await persistDevice(next)
    return next
  } catch (error) {
    if (isDeviceNotAuthorized(error)) return null
    if (isTooManyDevices(error)) throw new TooManyDevicesError()
    // Offline or the like: still valid here; renewed on a later page.
    return device
  }
}

/** How the device shows under Account → Devices: the app and the browser. */
function deviceLabel(): string {
  const app = typeof location === 'undefined' ? 'web' : location.hostname.split('.')[0]
  const agent = typeof navigator === 'undefined' ? '' : navigator.userAgent
  return `${app} · ${agent}`.slice(0, 100)
}

async function registered(): Promise<DeviceKeys> {
  const keypair = await generateDeviceKeypair()
  try {
    const { deviceId, issuedAtMs } = await registerDevice(encodePubKeyB64(keypair.publicKey), deviceLabel())
    const device = { id: deviceId, publicKey: keypair.publicKey, privateKey: keypair.privateKey, issuedAtMs }
    await persistDevice(device)
    return device
  } catch (error) {
    keypair.privateKey.fill(0)
    if (isTooManyDevices(error)) throw new TooManyDevicesError()
    throw error
  }
}

async function resolve(): Promise<CurrentDevice> {
  const session = getSession()
  if (!session) throw new Error('not signed in')
  let device = session.device
  if (device && checked !== device.id) {
    const trusted = await stillTrusted(device)
    if (trusted === false) {
      await persistDevice(null)
      device = null
    } else if (trusted) {
      checked = device.id
    }
  }
  if (device && Date.now() - device.issuedAtMs > RENEW_AFTER_MS) {
    device = await renewed(device)
    if (!device) await persistDevice(null)
  }
  if (!device) {
    device = await registered()
    checked = device.id
  }
  return asCurrent(device)
}

/**
 * This sign-in's device on this origin: the one kept (checked once per page,
 * renewed when due) or a newly registered one. Concurrent calls (two
 * editors, a StrictMode double mount) register once. Throws
 * [`TooManyDevicesError`] when the account has 20 devices in use.
 */
export function currentDevice(): Promise<CurrentDevice> {
  if (!pending) {
    pending = resolve().finally(() => {
      pending = null
    })
  }
  return pending
}

/**
 * The server refused this device mid-session (`403 deviceNotAuthorized`, or
 * a socket that keeps closing before it opens): forget it so the next
 * `currentDevice` registers again. At most once per page; false when that
 * was used already (the caller stops there).
 */
export async function deviceRefused(): Promise<boolean> {
  if (recheckUsed) return false
  recheckUsed = true
  checked = null
  await persistDevice(null)
  return true
}

/**
 * A server elsewhere no longer takes this device's statement (a shared
 * file's server, through the `renewDevice` socket message): renew it now if
 * it is this device.
 */
export async function renewRequested(deviceIds: readonly number[]): Promise<void> {
  const device = getSession()?.device
  if (!device || !deviceIds.includes(device.id)) return
  const next = await renewed(device)
  if (!next) await persistDevice(null)
}

/** Test seam: a fresh page. */
export function resetCurrentDeviceForTesting(): void {
  checked = null
  pending = null
  recheckUsed = false
}
