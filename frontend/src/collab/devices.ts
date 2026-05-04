// Per-session Ed25519 device keypair. Used to sign collab frames sent over the
// WebSocket relay. Public half registers with the backend on first use; private
// half lives only in sessionStorage (one device row per browser tab session,
// per spec §6).
import _sodium from 'libsodium-wrappers-sumo'

export interface DeviceKeypair {
  publicKey: Uint8Array  // 32 bytes
  privateKey: Uint8Array // 64 bytes (libsodium expanded form)
}

export async function generateDeviceKeypair(): Promise<DeviceKeypair> {
  await _sodium.ready
  const { publicKey, privateKey } = _sodium.crypto_sign_keypair()
  return { publicKey, privateKey }
}

/** Standard base64 (matches Go's base64.StdEncoding decoder used by /api/devices register). */
export function encodePubKeyB64(pub: Uint8Array): string {
  let s = ''
  for (const b of pub) s += String.fromCharCode(b)
  return btoa(s)
}

const STORAGE_KEY = 'kutup_device_keys_v1'

export function loadKeypair(): DeviceKeypair | null {
  const raw = sessionStorage.getItem(STORAGE_KEY)
  if (!raw) return null
  try {
    const obj = JSON.parse(raw)
    return {
      publicKey: new Uint8Array(obj.pub),
      privateKey: new Uint8Array(obj.priv),
    }
  } catch {
    return null
  }
}

export function saveKeypair(kp: DeviceKeypair) {
  sessionStorage.setItem(STORAGE_KEY, JSON.stringify({
    pub: Array.from(kp.publicKey),
    priv: Array.from(kp.privateKey),
  }))
}

export function clearKeypair() {
  sessionStorage.removeItem(STORAGE_KEY)
}
