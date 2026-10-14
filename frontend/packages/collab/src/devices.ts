// A collaboration device's Ed25519 keypair: it signs the frames sent over the
// relay. Made and kept by ./currentDevice (sealed with the sign-in's keys, one
// device per sign-in per origin).
import { getSodium } from '@kutup/crypto/sodium'

export interface DeviceKeypair {
  publicKey: Uint8Array  // 32 bytes
  privateKey: Uint8Array // 64 bytes (libsodium expanded form)
}

export async function generateDeviceKeypair(): Promise<DeviceKeypair> {
  const sodium = await getSodium()
  const { publicKey, privateKey } = sodium.crypto_sign_keypair()
  return { publicKey, privateKey }
}

/** Standard base64 (matches Go's base64.StdEncoding decoder used by /api/devices register). */
export function encodePubKeyB64(pub: Uint8Array): string {
  let s = ''
  for (const b of pub) s += String.fromCharCode(b)
  return btoa(s)
}
