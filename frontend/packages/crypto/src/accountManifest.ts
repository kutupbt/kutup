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
export interface AccountManifestPin {
  /** As Rust serializes an `AccountRef`. */
  account: import('./accountRef').AccountRef
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
  pin: AccountManifestPin | null,
  head: AccountManifest | null,
  masterKeyBase64: string,
  account: string,
): Promise<AccountManifestPin | null> {
  return (await getCryptoWasm()).checkOwnManifestHead(pin, head, masterKeyBase64, account) as AccountManifestPin | null
}

/** What a page does with a collab frame (`SenderVerdict`). */
export type SenderVerdict =
  | { kind: 'take' }
  | { kind: 'needHead' }
  | { kind: 'needManifest'; sequence: number }
  | { kind: 'refuse'; reason: string }

/**
 * One sender account's manifests, held in the crypto WASM
 * (`SenderManifests`, docs/plans/one-device-list.md §8, slice 3): its head,
 * the earlier manifests logged frames name, and the pin they follow.
 */
export interface CollabSenderHandle {
  /** Takes the head with the manifests after the pin up to it; throws on one that doesn't follow the pin. */
  takeHead(head: AccountManifest, history: AccountManifest[] | null, newIncarnation: boolean): void
  /** Takes an earlier manifest of the account, for logged frames. */
  takeEntry(manifest: AccountManifest): void
  /** What to do with a frame as the server delivers it (`live`: during editing; otherwise from the log). */
  check(delivered: Uint8Array, live: boolean): SenderVerdict
  /** The pin to keep for the account. */
  pin(): AccountManifestPin | null
  /** The head's authority public key (canonical base64), for the identity pins; null before a head. */
  headAuthority(): string | null
  free(): void
}

/** A record of `account` in the crypto WASM, from this page's pin of it. */
export async function collabSender(account: string, pin: AccountManifestPin | null): Promise<CollabSenderHandle> {
  return new (await getCryptoWasm()).CollabSender(account, pin)
}

/** The sender account a delivered frame names. */
export async function deliveredFrameSender(delivered: Uint8Array): Promise<string> {
  return (await getCryptoWasm()).deliveredFrameSender(delivered)
}

/** `pins` sealed under the key `masterKeyBase64` derives, for `profile` (`<client type>:<account>`). */
export async function sealManifestPins(pins: AccountManifestPin[], masterKeyBase64: string, profile: string): Promise<string> {
  return (await getCryptoWasm()).sealManifestPins(pins, masterKeyBase64, profile)
}

/** The pins {@link sealManifestPins} sealed; throws on another key, profile, or a changed envelope. */
export async function openManifestPins(envelope: string, masterKeyBase64: string, profile: string): Promise<AccountManifestPin[]> {
  return (await getCryptoWasm()).openManifestPins(envelope, masterKeyBase64, profile) as AccountManifestPin[]
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
