// Ed25519 sign/verify for collaboration frames, through @kutup/crypto's
// signing (kutup-crypto in WASM, verified strictly as the server verifies).
// Used by TextCollabEditor to sign each outbound frame.
import { sign, verify } from '@kutup/crypto/signing'

export async function ed25519Sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
  return sign(message, privateKey)
}

export async function ed25519Verify(message: Uint8Array, sig: Uint8Array, pub: Uint8Array): Promise<boolean> {
  return verify(message, sig, pub)
}
