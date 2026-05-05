// Ed25519 sign/verify helpers built on libsodium.
// Used by TextCollabEditor (F3) to sign each outbound frame, and by the
// server-side relay to verify (mirrored by backend/services/envelope/sign.go).
import _sodium from 'libsodium-wrappers-sumo'

export async function ed25519Sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
  await _sodium.ready
  return _sodium.crypto_sign_detached(message, privateKey)
}

export async function ed25519Verify(message: Uint8Array, sig: Uint8Array, pub: Uint8Array): Promise<boolean> {
  await _sodium.ready
  try {
    return _sodium.crypto_sign_verify_detached(sig, message, pub)
  } catch {
    return false
  }
}
