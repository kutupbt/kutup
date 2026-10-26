// This sign-in's device on this origin (docs/plans/one-device-list.md): an
// `editor` entry in the account's manifest, with the Ed25519 key its
// collaboration frames are signed with and the credential its calls carry.
// One device per sign-in, shared by the origin's tabs and sealed with the
// session's keys, so reloads and new tabs reuse it; it ends with the
// sign-in. One place for every editor (notes and lists, office documents,
// whiteboards) and for the Account app, which signs device removals as one.
//
// The device is checked once per page against the account's list and head
// manifest: one the account no longer lists (removed under Account →
// Devices, dropped as idle, or from before an account reset) is replaced,
// never a reason to sign out. Nothing is renewed: a device stays valid while
// the head lists it.

import { toBase64, toBase64Url } from '@kutup/crypto/base64'
import { listDeviceInManifest, type AccountManifest } from '@kutup/crypto/accountManifest'
import { randomBytes } from '@kutup/crypto/random'
import { generateSigningKey } from '@kutup/crypto/signing'
import {
  deviceHeader,
  fetchManifest,
  isDeviceCredentialRefused,
  isDeviceLimit,
  isDevicesMismatch,
  listAccountDevices,
  ownAccount,
  publishNextManifest,
  registerDevice,
} from './devices'
import type { DeviceKeys } from './keys'
import { persistDevice } from './persist'
import { getSession, type Session } from './store'

/** A device's Ed25519 keypair. */
export interface DeviceKeypair {
  /** 32 bytes. */
  publicKey: Uint8Array
  /** 64 bytes: seed ‖ public key (libsodium's form). */
  privateKey: Uint8Array
}

export interface CurrentDevice {
  /** 1..127, the account's id for it. */
  deviceId: number
  keypair: DeviceKeypair
  /** `X-Kutup-Device` for its calls: `<deviceId>.<credential>`. */
  header: string
  /** This account, `aci:<uuid>@<server>`: the sender its frames name. */
  account: string
  /** The account manifest's sequence it was last seen listed under: what its frames name. */
  manifestSequence: bigint
}

/**
 * The account has as many devices as the server allows (`409 deviceLimit`,
 * an admin setting): this browser gets none until the user removes one
 * under Account → Devices. Never chosen for them.
 */
export class TooManyDevicesError extends Error {
  constructor() {
    super('the account has as many devices as it may')
    this.name = 'TooManyDevicesError'
  }
}

/** The device checked on this page, and the head sequence it was found listed under. */
let checked: { id: number; sequence: bigint } | null = null
/** The device being worked out now: concurrent callers share it. */
let pending: Promise<CurrentDevice> | null = null
/** A refusal mid-session sends the page through registration again, once. */
let recheckUsed = false

function asCurrent(device: DeviceKeys, account: string, manifestSequence: bigint): CurrentDevice {
  return {
    deviceId: device.id,
    keypair: { publicKey: device.publicKey, privateKey: device.privateKey },
    header: deviceHeader(device),
    account,
    manifestSequence,
  }
}

type Standing =
  /** The head lists it with its key: its frames count. */
  | { state: 'listed'; sequence: bigint }
  /** Its row is live but the head doesn't list it yet (a listing cut short). */
  | { state: 'unlisted'; session: string }
  /** Removed, idle, of another sign-in, or its id now another device's. */
  | { state: 'gone' }

/** Where `device` stands with the account; null when that cannot be told now. */
async function standing(device: DeviceKeys, account: string): Promise<Standing | null> {
  let rows: Awaited<ReturnType<typeof listAccountDevices>>
  let head: AccountManifest | null
  try {
    ;[rows, head] = await Promise.all([listAccountDevices(), fetchManifest(account)])
  } catch {
    return null
  }
  const row = rows.find((r) => r.deviceId === device.id)
  if (!row || !row.thisSignIn || row.expired || row.kind !== 'editor') return { state: 'gone' }
  const entry = head?.devices.find((d) => d.deviceId === device.id)
  if (!head || !entry) return { state: 'unlisted', session: row.session }
  if (entry.frameKey !== toBase64(device.publicKey) || entry.session !== row.session) return { state: 'gone' }
  return { state: 'listed', sequence: BigInt(head.sequence) }
}

/**
 * Lists `device` in the account's next manifest, signed with the master
 * key's authority, and keeps the head's sequence with it. Null when the
 * server no longer backs it (its row went, or its credential): the caller
 * registers another.
 */
async function listed(session: Session, device: DeviceKeys, account: string, sessionHash: string): Promise<DeviceKeys | null> {
  const masterKey = toBase64(session.masterKey)
  const entry = { deviceId: device.id, kind: 'editor' as const, frameKey: toBase64(device.publicKey), session: sessionHash }
  let head: AccountManifest | null
  try {
    head = await publishNextManifest(account, deviceHeader(device), (current) =>
      listDeviceInManifest(current, entry, new Date().toISOString(), masterKey, account),
    )
  } catch (error) {
    if (isDeviceLimit(error)) throw new TooManyDevicesError()
    if (isDevicesMismatch(error) || isDeviceCredentialRefused(error)) return null
    throw error
  }
  if (!head) throw new Error('the device was not listed')
  const next = { ...device, manifestSequence: BigInt(head.sequence) }
  await persistDevice(next)
  return next
}

/** How the device shows under Account → Devices: the app and the browser. */
function deviceLabel(): string {
  const app = typeof location === 'undefined' ? 'web' : location.hostname.split('.')[0]
  const agent = typeof navigator === 'undefined' ? '' : navigator.userAgent
  return `${app} · ${agent}`.slice(0, 100)
}

/**
 * A new row for this origin, kept with the keys before it lists itself: a
 * listing cut short is finished on a later page instead of leaving the row
 * to idle out.
 */
async function registered(): Promise<{ device: DeviceKeys; sessionHash: string }> {
  const keypair = await generateSigningKey()
  const credential = randomBytes(32)
  try {
    const { deviceId, session } = await registerDevice({
      kind: 'editor',
      name: deviceLabel(),
      frameKey: toBase64(keypair.publicKey),
      credential: toBase64Url(credential),
    })
    const device: DeviceKeys = { id: deviceId, ...keypair, credential, manifestSequence: 0n }
    await persistDevice(device)
    return { device, sessionHash: session }
  } catch (error) {
    keypair.privateKey.fill(0)
    credential.fill(0)
    if (isDeviceLimit(error)) throw new TooManyDevicesError()
    throw error
  }
}

async function resolve(): Promise<CurrentDevice> {
  const session = getSession()
  if (!session) throw new Error('not signed in')
  const account = await ownAccount(session)
  let device = session.device
  if (device && checked?.id === device.id) return asCurrent(device, account, checked.sequence)
  if (device) {
    const found = await standing(device, account)
    if (found === null) {
      // The list cannot be read now: go on with the device; the socket
      // says if the server refuses it. One never listed can't go on.
      if (device.manifestSequence === 0n) throw new Error('the account’s devices cannot be read')
      return asCurrent(device, account, device.manifestSequence)
    }
    if (found.state === 'listed') {
      checked = { id: device.id, sequence: found.sequence }
      return asCurrent(device, account, found.sequence)
    }
    device = found.state === 'unlisted' ? await listed(session, device, account, found.session) : null
    if (!device) await persistDevice(null)
  }
  if (!device) {
    const fresh = await registered()
    device = await listed(session, fresh.device, account, fresh.sessionHash)
    if (!device) {
      await persistDevice(null)
      throw new Error('the new device could not be listed')
    }
  }
  checked = { id: device.id, sequence: device.manifestSequence }
  return asCurrent(device, account, device.manifestSequence)
}

/**
 * This sign-in's device on this origin: the one kept (checked once per
 * page, and listed if a listing was cut short) or a newly registered one
 * that lists itself. Concurrent calls (two editors, a StrictMode double
 * mount) register once. Throws [`TooManyDevicesError`] at the account's
 * device limit.
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
 * Whether the account still lists `device` with its key (its row live, of
 * this sign-in); null when that cannot be told now.
 */
export async function stillListed(device: CurrentDevice): Promise<boolean | null> {
  const kept = getSession()?.device
  if (!kept || kept.id !== device.deviceId) return false
  const found = await standing(kept, device.account)
  return found === null ? null : found.state === 'listed'
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
 * A refused `device` checked against the account: the next device when it
 * was replaced, or null when it still stands (or that can't be told now, or
 * this page already replaced one).
 */
export async function replaceRefusedDevice(device: CurrentDevice): Promise<CurrentDevice | null> {
  if ((await stillListed(device)) !== false) return null
  if (!(await deviceRefused())) return null
  return currentDevice()
}

/** This page's device was removed (by this page, from Account → Devices): forget it. */
export async function forgetCurrentDevice(): Promise<void> {
  checked = null
  await persistDevice(null)
}

/** Test seam: a fresh page. */
export function resetCurrentDeviceForTesting(): void {
  checked = null
  pending = null
  recheckUsed = false
}
