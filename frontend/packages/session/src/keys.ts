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
}

interface EncodedKeysV1 {
  v: 1
  userId: string
  masterKey: string
  privateKey: string
  publicKey: string
}

export function encodeKeys(keys: SessionKeys): Uint8Array {
  const value: EncodedKeysV1 = {
    v: 1,
    userId: keys.userId,
    masterKey: toBase64(keys.masterKey),
    privateKey: toBase64(keys.privateKey),
    publicKey: keys.publicKey,
  }
  return new TextEncoder().encode(JSON.stringify(value))
}

export function decodeKeys(bytes: Uint8Array): SessionKeys {
  const value = JSON.parse(new TextDecoder().decode(bytes)) as Partial<EncodedKeysV1>
  if (
    value.v !== 1 ||
    typeof value.userId !== 'string' ||
    typeof value.masterKey !== 'string' ||
    typeof value.privateKey !== 'string' ||
    typeof value.publicKey !== 'string'
  ) {
    throw new Error('session key payload is malformed')
  }
  const masterKey = fromBase64(value.masterKey)
  const privateKey = fromBase64(value.privateKey)
  if (masterKey.length !== 32 || privateKey.length !== 32) {
    throw new Error('session key payload has keys of the wrong length')
  }
  return { userId: value.userId, masterKey, privateKey, publicKey: value.publicKey }
}
