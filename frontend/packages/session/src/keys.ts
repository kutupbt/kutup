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
   * This sign-in's device on this origin (docs/plans/one-device-list.md):
   * one per sign-in, shared by its tabs, kept sealed with the keys and gone
   * with them. Never forked to another origin: each registers its own.
   */
  device?: DeviceKeys
}

/**
 * A device of the account (an `editor`-kind entry in its manifest): the
 * server's id for it, its Ed25519 frame key and its credential.
 */
export interface DeviceKeys {
  /** 1..127, the account's id for it. */
  id: number
  /** 32 bytes. */
  publicKey: Uint8Array
  /** 64 bytes (libsodium's expanded form: seed then public key). */
  privateKey: Uint8Array
  /** 32 random bytes: with the id, `X-Kutup-Device` beside the sign-in. */
  credential: Uint8Array
  /**
   * The account manifest's sequence when this device was last seen listed
   * (0: registered, not listed yet): what its frames name while the head
   * cannot be read.
   */
  manifestSequence: bigint
}

interface EncodedDevice {
  id: number
  publicKey: string
  privateKey: string
  credential: string
  /** Decimal. */
  manifestSequence: string
}

/**
 * v2: no device; v3: a device of the retired collaboration registry (read
 * as none: it registers again); v4: a device of the account's manifest.
 */
interface EncodedKeys {
  v: 2 | 3 | 4
  userId: string
  masterKey: string
  privateKey: string
  publicKey: string
  keyBinding: string
  /** Optional; read from v4 only. */
  device?: Partial<EncodedDevice>
}

/** A key binding's form: a UUID v4, lowercase. */
const KEY_BINDING = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

export function encodeKeys(keys: SessionKeys): Uint8Array {
  if (!KEY_BINDING.test(keys.keyBinding)) throw new Error('session keys have no valid key binding')
  const value: EncodedKeys = {
    v: 4,
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
      credential: toBase64(keys.device.credential),
      manifestSequence: keys.device.manifestSequence.toString(),
    }
  }
  return new TextEncoder().encode(JSON.stringify(value))
}

export function decodeKeys(bytes: Uint8Array): SessionKeys {
  const value = JSON.parse(new TextDecoder().decode(bytes)) as Partial<EncodedKeys>
  if (
    (value.v !== 2 && value.v !== 3 && value.v !== 4) ||
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
  if (value.v === 4 && value.device !== undefined) keys.device = decodeDevice(value.device)
  return keys
}

/** Bounds a manifest sequence (a u64) and a device id (1..127). */
const SEQUENCE = /^(0|[1-9][0-9]{0,19})$/
const MAX_SEQUENCE = (1n << 64n) - 1n
const MAX_DEVICE_ID = 127

function decodeDevice(value: Partial<EncodedDevice>): DeviceKeys {
  if (
    typeof value.id !== 'number' ||
    !Number.isSafeInteger(value.id) ||
    value.id < 1 ||
    value.id > MAX_DEVICE_ID ||
    typeof value.publicKey !== 'string' ||
    typeof value.privateKey !== 'string' ||
    typeof value.credential !== 'string' ||
    typeof value.manifestSequence !== 'string' ||
    !SEQUENCE.test(value.manifestSequence) ||
    BigInt(value.manifestSequence) > MAX_SEQUENCE
  ) {
    throw new Error('session key payload has a malformed device')
  }
  const publicKey = fromBase64(value.publicKey)
  const privateKey = fromBase64(value.privateKey)
  const credential = fromBase64(value.credential)
  if (publicKey.length !== 32 || privateKey.length !== 64 || credential.length !== 32) {
    throw new Error('session key payload has a device key of the wrong length')
  }
  return { id: value.id, publicKey, privateKey, credential, manifestSequence: BigInt(value.manifestSequence) }
}
