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
}

interface EncodedKeysV2 {
  v: 2
  userId: string
  masterKey: string
  privateKey: string
  publicKey: string
  keyBinding: string
}

/** A key binding's form: a UUID v4, lowercase. */
const KEY_BINDING = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

export function encodeKeys(keys: SessionKeys): Uint8Array {
  if (!KEY_BINDING.test(keys.keyBinding)) throw new Error('session keys have no valid key binding')
  const value: EncodedKeysV2 = {
    v: 2,
    userId: keys.userId,
    masterKey: toBase64(keys.masterKey),
    privateKey: toBase64(keys.privateKey),
    publicKey: keys.publicKey,
    keyBinding: keys.keyBinding,
  }
  return new TextEncoder().encode(JSON.stringify(value))
}

export function decodeKeys(bytes: Uint8Array): SessionKeys {
  const value = JSON.parse(new TextDecoder().decode(bytes)) as Partial<EncodedKeysV2>
  if (
    value.v !== 2 ||
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
  return {
    userId: value.userId,
    masterKey,
    privateKey,
    publicKey: value.publicKey,
    keyBinding: value.keyBinding,
  }
}
