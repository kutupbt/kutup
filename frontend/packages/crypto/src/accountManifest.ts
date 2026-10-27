// The account's device list, signed (docs/plans/one-device-list.md): one
// manifest per account, one entry per device of every kind. A device that
// joins or leaves publishes the next one, signed with the account authority
// the master key derives. Rust (kutup-chat-proto) builds, signs and checks
// the chain; this is its typed browser face.

import { getCryptoWasm } from './rustWasm'

/** What kind of app instance a device is. */
export type DeviceKind = 'chat' | 'editor' | 'cli'

/** One device as the manifest lists it (`AccountManifestDeviceV3`). */
export interface ManifestDevice {
  /** 1..127, one id space per account. */
  deviceId: number
  kind: DeviceKind
  /** Present on a device that takes Chat messages. */
  chat?: { directChatSuite: number; registrationId: number }
  /** The device's Ed25519 frame key, canonical base64 of 32 bytes (editors and the CLI). */
  frameKey?: string
  /** The hash of the sign-in it belongs to, lowercase hex. */
  session: string
}

/**
 * A signed account manifest (`AccountManifestV3`), as the server hands it
 * out and takes it back. Only what the browser reads is typed; the rest
 * travels as it came.
 */
export interface AccountManifest {
  /** `aci:<uuid>@<server>`. */
  account: string
  sequence: number
  devices: ManifestDevice[]
  [field: string]: unknown
}

/**
 * The next manifest after `head` with `entry` listed (in place of any entry
 * of its id); `head` null makes the account's first, naming `account`. The
 * head must name the authority `masterKeyBase64` derives, and the result is
 * checked to follow it.
 */
export async function listDeviceInManifest(
  head: AccountManifest | null,
  entry: ManifestDevice,
  issuedAt: string,
  masterKeyBase64: string,
  account: string,
): Promise<AccountManifest> {
  return (await getCryptoWasm()).listDeviceInManifest(head, entry, issuedAt, masterKeyBase64, account) as AccountManifest
}

/**
 * The newest manifest of its own account a client saw (`AccountManifestPinV1`):
 * a server can't have it sign an older head, or start a new chain over one.
 */
export interface OwnManifestPin {
  account: string
  incarnationId: string
  sequence: number
  hash: string
}

/**
 * Checks `head` as the server gave it (null: none) against `pin` (null:
 * none seen) for `account` and the incarnation `masterKeyBase64` derives;
 * the pin to keep. Throws on a head that doesn't verify or is older than the
 * pin, and on no head once there is a pin.
 */
export async function checkOwnManifestHead(
  pin: OwnManifestPin | null,
  head: AccountManifest | null,
  masterKeyBase64: string,
  account: string,
): Promise<OwnManifestPin | null> {
  return (await getCryptoWasm()).checkOwnManifestHead(pin, head, masterKeyBase64, account) as OwnManifestPin | null
}

/** The next manifest after `head` without `deviceIds`. Throws when it would list no device. */
export async function removeDevicesFromManifest(
  head: AccountManifest,
  deviceIds: readonly number[],
  issuedAt: string,
  masterKeyBase64: string,
): Promise<AccountManifest> {
  return (await getCryptoWasm()).removeDevicesFromManifest(
    head,
    Uint32Array.from(deviceIds),
    issuedAt,
    masterKeyBase64,
  ) as AccountManifest
}
