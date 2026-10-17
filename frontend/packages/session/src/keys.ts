// The key material an app origin needs, and its wire encoding inside the
// fork payload and the persisted WebSession blob (both local-state envelopes).

import { fromBase64, toBase64 } from '@kutup/crypto/base64'

export interface SessionKeys {
  userId: string
  /** The account master key (32 bytes). */
  masterKey: Uint8Array
  /** The Drive HPKE private key (32 bytes). */
  privateKey: Uint8Array
  /** The Drive HPKE public key, base64. */
  publicKey: string
  /**
   * The account's key binding as this device verified it
   * (docs/plans/account-identity.md, "Verified binding"): the one that opened
   * the master envelope, or the one drawn here at registration. Seals use it,
   * never the server's word.
   */
  keyBinding: string
  /**
   * This sign-in's collaboration device on this origin
   * (docs/plans/device-registration.md): one per sign-in, shared by its
   * tabs, kept sealed with the keys and gone with them. Never forked to
   * another origin: each registers its own.
   */
  device?: DeviceKeys
}

/** A registered collaboration device: its id and Ed25519 keypair. */
export interface DeviceKeys {
  id: number
  /** 32 bytes. */
  publicKey: Uint8Array
  /** 64 bytes (libsodium's expanded form: seed then public key). */
  privateKey: Uint8Array
  /** When the account's newest statement for it was made (renewed after 15 days). */
  issuedAtMs: number
}

interface EncodedDevice {
  id: number
  publicKey: string
  privateKey: string
  issuedAtMs: number
}

interface EncodedKeys {
  v: 2 | 3
  userId: string
  masterKey: string
  privateKey: string
  publicKey: string
  keyBinding: string
  /** v3 only, and optional there. */
  device?: EncodedDevice
}

/** A key binding's form: a UUID v4, lowercase. */
const KEY_BINDING = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

export function encodeKeys(keys: SessionKeys): Uint8Array {
  if (!KEY_BINDING.test(keys.keyBinding)) throw new Error('session keys have no valid key binding')
  const value: EncodedKeys = {
    v: 3,
    userId: keys.userId,
    masterKey: toBase64(keys.masterKey),
    privateKey: toBase64(keys.privateKey),
    publicKey: keys.publicKey,
    keyBinding: keys.keyBinding,
  }
  if (keys.device) {
    value.device = {
      id: keys.device.id,
      publicKey: toBase64(keys.device.publicKey),
      privateKey: toBase64(keys.device.privateKey),
      issuedAtMs: keys.device.issuedAtMs,
    }
  }
  return new TextEncoder().encode(JSON.stringify(value))
}

export function decodeKeys(bytes: Uint8Array): SessionKeys {
  const value = JSON.parse(new TextDecoder().decode(bytes)) as Partial<EncodedKeys>
  if (
    (value.v !== 2 && value.v !== 3) ||
    typeof value.userId !== 'string' ||
    typeof value.masterKey !== 'string' ||
    typeof value.privateKey !== 'string' ||
    typeof value.publicKey !== 'string' ||
    typeof value.keyBinding !== 'string' ||
    !KEY_BINDING.test(value.keyBinding)
  ) {
    throw new Error('session key payload is malformed')
  }
  const masterKey = fromBase64(value.masterKey)
  const privateKey = fromBase64(value.privateKey)
  if (masterKey.length !== 32 || privateKey.length !== 32) {
    throw new Error('session key payload has keys of the wrong length')
  }
  const keys: SessionKeys = {
    userId: value.userId,
    masterKey,
    privateKey,
    publicKey: value.publicKey,
    keyBinding: value.keyBinding,
  }
  if (value.v === 3 && value.device !== undefined) keys.device = decodeDevice(value.device)
  return keys
}

function decodeDevice(value: Partial<EncodedDevice>): DeviceKeys {
  if (
    typeof value.id !== 'number' ||
    !Number.isSafeInteger(value.id) ||
    value.id <= 0 ||
    typeof value.publicKey !== 'string' ||
    typeof value.privateKey !== 'string' ||
    typeof value.issuedAtMs !== 'number' ||
    !Number.isSafeInteger(value.issuedAtMs)
  ) {
    throw new Error('session key payload has a malformed device')
  }
  const publicKey = fromBase64(value.publicKey)
  const privateKey = fromBase64(value.privateKey)
  if (publicKey.length !== 32 || privateKey.length !== 64) {
    throw new Error('session key payload has a device key of the wrong length')
  }
  return { id: value.id, publicKey, privateKey, issuedAtMs: value.issuedAtMs }
}
