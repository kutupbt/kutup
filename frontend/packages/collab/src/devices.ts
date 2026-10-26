// A collaboration device's Ed25519 keypair: it signs the frames sent over the
// relay. Made and kept by ./currentDevice (sealed with the sign-in's keys, one
// device per sign-in per origin).
import { generateSigningKey } from '@kutup/crypto/signing'

export interface DeviceKeypair {
  publicKey: Uint8Array  // 32 bytes
  privateKey: Uint8Array // 64 bytes: seed ‖ public key (libsodium's form)
}

export async function generateDeviceKeypair(): Promise<DeviceKeypair> {
  return generateSigningKey()
}

/** Standard base64 (matches Go's base64.StdEncoding decoder used by /api/devices register). */
export function encodePubKeyB64(pub: Uint8Array): string {
  let s = ''
  for (const b of pub) s += String.fromCharCode(b)
  return btoa(s)
}
