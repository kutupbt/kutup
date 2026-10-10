// Ed25519 sign/verify helpers built on libsodium.
// Used by TextCollabEditor (F3) to sign each outbound frame, and by the
// server-side relay to verify (mirrored by backend/services/envelope/sign.go).
import { getSodium } from '@kutup/crypto/sodium'

export async function ed25519Sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
  const sodium = await getSodium()
  return sodium.crypto_sign_detached(message, privateKey)
}

export async function ed25519Verify(message: Uint8Array, sig: Uint8Array, pub: Uint8Array): Promise<boolean> {
  const sodium = await getSodium()
  try {
    return sodium.crypto_sign_verify_detached(sig, message, pub)
  } catch {
    return false
  }
}
