// The account's devices (docs/plans/one-device-list.md): one list per
// account, of every kind (Chat apps, editing apps, the CLI), each a row the
// server issues an id and credential for and an entry in the manifest the
// account authority signs. A device joins by registering its row and
// publishing the next manifest listing itself; it leaves, or is removed, by
// a manifest without it. These are the calls; ./currentDevice keeps this
// origin's own device.

import axios from 'axios'
import { accountKeyOf, accountOfKey } from '@kutup/crypto/accountRef'
import { checkOwnManifestHead, type AccountManifest, type DeviceKind } from '@kutup/crypto/accountManifest'
import { toBase64, toBase64Url } from '@kutup/crypto/base64'
import { loadServerSettings } from './apps'
import api from './client'
import type { DeviceKeys } from './keys'
import { keepManifestPin, manifestPin } from './manifestPins'
import { getSession, type Session } from './store'

/** The device credential beside the sign-in: `<deviceId>.<credential, base64url>`. */
export const DEVICE_HEADER = 'X-Kutup-Device'

/** One device of the account, as `GET /api/devices` lists it. */
export interface AccountDevice {
  deviceId: number
  kind: DeviceKind
  /** What it registered as ("office · Firefox …"); may be empty. */
  name: string
  /** The hash of its sign-in, as its manifest entry carries it. */
  session: string
  /** It belongs to the caller's sign-in. */
  thisSignIn: boolean
  /** The account's manifest lists it (one between registering and listing itself isn't yet). */
  listed: boolean
  /** Idle too long: the next manifest drops it. */
  expired: boolean
  createdAt: string
  lastSeenAt?: string
}

/** The header value a device's calls carry. */
export function deviceHeader(device: Pick<DeviceKeys, 'id' | 'credential'>): string {
  return `${device.id}.${toBase64Url(device.credential)}`
}

/** Axios config sending `header` as the device credential. */
function asDevice(header: string) {
  return { headers: { [DEVICE_HEADER]: header } }
}

/**
 * The signed-in account, `aci:<uuid>@<server>`: what its manifest names and
 * what its frames are signed under. The server's name comes from its public
 * settings (fetched once per page).
 */
export async function ownAccount(session: Pick<Session, 'userId'>): Promise<string> {
  const settings = await loadServerSettings<{ chat?: { serverName?: string } }>()
  const server = settings.chat?.serverName
  if (!server) throw new Error('the server did not publish its name')
  return accountKeyOf({ server, accountId: session.userId })
}

function errorCode(error: unknown, status: number): string | undefined {
  if (!axios.isAxiosError(error) || error.response?.status !== status) return undefined
  const code = (error.response.data as { code?: unknown } | undefined)?.code
  return typeof code === 'string' ? code : undefined
}

/** `409 deviceLimit`: the account has as many devices as the server allows. */
export function isDeviceLimit(error: unknown): boolean {
  return errorCode(error, 409) === 'deviceLimit'
}

/** `403 deviceNotAuthorized`: a collaboration call refused the device (not listed, or its sign-in ended). */
export function isDeviceNotAuthorized(error: unknown): boolean {
  return errorCode(error, 403) === 'deviceNotAuthorized'
}

/** `401 deviceCredential`: the credential matches no live device of the account. */
export function isDeviceCredentialRefused(error: unknown): boolean {
  return errorCode(error, 401) === 'deviceCredential'
}

/**
 * `409 devicesMismatch`: a manifest listed a device the server can't back
 * with a live row of that key and sign-in (the row went, or its id now
 * belongs to another device).
 */
export function isDevicesMismatch(error: unknown): boolean {
  return errorCode(error, 409) === 'devicesMismatch'
}

export async function listAccountDevices(): Promise<AccountDevice[]> {
  return (await api.get<{ devices: AccountDevice[] }>('/devices')).data.devices
}

/**
 * Registers an editing device of this sign-in: its row, under the lowest
 * free id. It then lists itself ({@link publishNextManifest}); until then
 * its frames are refused. `409 deviceLimit` at the cap.
 */
export async function registerDevice(request: {
  kind: Exclude<DeviceKind, 'chat'>
  name: string
  /** Canonical base64 of the 32-byte Ed25519 key. */
  frameKey: string
  /** Unpadded base64url of 32 random bytes. */
  credential: string
}): Promise<{ deviceId: number; session: string }> {
  return (await api.post<{ deviceId: number; session: string }>('/devices', request)).data
}

/** The account's head manifest; null when it has none yet (`404 noManifest`). */
export async function fetchManifest(account: string): Promise<AccountManifest | null> {
  const ref = accountOfKey(account)
  if (!ref) throw new Error('not an account reference')
  try {
    const { data } = await api.get<AccountManifest>(`/chat/accounts/${encodeURIComponent(ref.accountId)}/manifest`, {
      params: { server: ref.server },
    })
    return data
  } catch (error) {
    // Only the server's own answer: another 404 (a proxy) must not read as
    // an account without a manifest, which would start a new chain.
    if (errorCode(error, 404) === 'noManifest') return null
    throw error
  }
}

/** One page of `manifest-history` (`AccountManifestHistoryPageV3`). */
interface HistoryPage {
  manifests: AccountManifest[]
  nextSequence?: number | null
}

/** The most history pages one read takes (each holds up to 64 manifests). */
const MAX_HISTORY_PAGES = 16

/**
 * `account`'s manifests from sequence `from` through `to`, every page, as its
 * server (or, for an account on another server, this one on its behalf)
 * serves them (`manifest-history`). Whoever reads them verifies them.
 */
export async function fetchManifestHistory(account: string, from: number, to: number): Promise<AccountManifest[]> {
  const ref = accountOfKey(account)
  if (!ref) throw new Error('not an account reference')
  const out: AccountManifest[] = []
  let page: number | undefined = from
  for (let i = 0; i < MAX_HISTORY_PAGES && page !== undefined; i++) {
    const { data }: { data: HistoryPage } = await api.get<HistoryPage>(
      `/chat/accounts/${encodeURIComponent(ref.accountId)}/manifest-history`,
      { params: { server: ref.server, fromSequence: from, toSequence: to, pageFromSequence: page } },
    )
    out.push(...data.manifests)
    page = data.nextSequence ?? undefined
  }
  return out
}

/**
 * Checks `head`, the signed-in account's own head as its server gave it
 * (null: none), against this origin's pin and keeps the pin it gives: the
 * head must verify under the account's authority and be no older than the
 * newest one seen here, and none at all is refused once one was seen. So a
 * server can't have this origin sign a successor of a stale head (bringing
 * a removed device back, or dropping the Chat identity), or a new chain.
 */
async function keepPin(account: string, head: AccountManifest | null): Promise<void> {
  const session = getSession()
  if (!session) throw new Error('not signed in')
  const pin = await checkOwnManifestHead(await manifestPin(account), head, toBase64(session.masterKey), account)
  if (pin) await keepManifestPin(pin)
}

/** The signed-in account's own head, checked against this origin's pin ({@link keepPin}). */
export async function fetchOwnManifest(account: string): Promise<AccountManifest | null> {
  const head = await fetchManifest(account)
  await keepPin(account, head)
  return head
}

/**
 * Publishes the account's next manifest, `next(head)` (null: nothing to
 * publish), as the device `header` names; with no header, as the sign-in
 * alone, which the server takes only for a manifest that removes devices
 * and changes nothing else (the Account app). Another device publishing first
 * moves the head (`409`): the head is read again and `next` asked once more.
 * `next` only sees a head this origin's pin accepts ({@link keepPin}), and
 * the published manifest moves the pin. Resolves to the manifest now at the
 * head, or null when nothing was published.
 */
export async function publishNextManifest(
  account: string,
  header: string | null,
  next: (head: AccountManifest | null) => Promise<AccountManifest | null>,
): Promise<AccountManifest | null> {
  for (let attempt = 0; ; attempt++) {
    const manifest = await next(await fetchOwnManifest(account))
    if (!manifest) return null
    try {
      const { data } = await api.post<{ manifest?: AccountManifest }>(
        '/chat/manifest',
        manifest,
        header === null ? undefined : asDevice(header),
      )
      // The pin moves to what this client signed; an answer naming another
      // manifest is not the one published.
      if (data.manifest && data.manifest.signature !== manifest.signature) {
        throw new Error('the server answered another manifest than the one published')
      }
      await keepPin(account, manifest)
      return manifest
    } catch (error) {
      const moved = axios.isAxiosError(error) && error.response?.status === 409 && !isDeviceLimit(error) && !isDevicesMismatch(error)
      if (!moved || attempt > 0) throw error
    }
  }
}

/**
 * A single-use ticket for a socket of the device `header` names (a browser
 * can't set headers on a WebSocket): the Chat socket and the collab sockets.
 */
export async function deviceTicket(header: string): Promise<string> {
  return (await api.post<{ ticket: string }>('/device-ticket', null, asDevice(header))).data.ticket
}
