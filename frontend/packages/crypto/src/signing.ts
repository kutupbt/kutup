/**
 * The suite's signatures for the web apps (docs/plans/crypto-primitives.md,
 * step 5): Ed25519 under suite 1, made and checked in kutup-crypto (WASM),
 * verified strictly, as the server verifies. A private key is
 * `seed ‖ public key` (64 bytes, libsodium's form, as stored keys are).
 */
import { getCryptoWasm } from './rustWasm'

export interface SigningKeyPair {
  /** 32 bytes. */
  publicKey: Uint8Array
  /** 64 bytes: the seed, then the public key. */
  privateKey: Uint8Array
}

export async function generateSigningKey(): Promise<SigningKeyPair> {
  const privateKey = (await getCryptoWasm()).signingKeyGenerate()
  return { publicKey: privateKey.slice(32), privateKey }
}

export async function sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
  return (await getCryptoWasm()).signingKeySign(privateKey, message)
}

export async function verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
  return (await getCryptoWasm()).signingKeyVerify(publicKey, message, signature)
}
