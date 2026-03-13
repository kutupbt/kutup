// X25519 asymmetric operations for key sharing.
// Uses crypto_box_seal (anonymous sender) for sharing collection keys with recipients.
import { getSodium } from './sodium'

export interface Keypair {
  publicKey: Uint8Array
  privateKey: Uint8Array
}

export async function generateKeypair(): Promise<Keypair> {
  const sodium = await getSodium()
  return sodium.crypto_box_keypair()
}

// Wrap a key for a recipient using their public key (anonymous sender).
// Only the recipient's private key can unwrap.
export async function wrapKeyForRecipient(
  key: Uint8Array,
  recipientPublicKey: Uint8Array,
): Promise<Uint8Array> {
  const sodium = await getSodium()
  return sodium.crypto_box_seal(key, recipientPublicKey)
}

// Unwrap a key sealed with the recipient's public key.
export async function unwrapKeyFromSender(
  sealed: Uint8Array,
  recipientPublicKey: Uint8Array,
  recipientPrivateKey: Uint8Array,
): Promise<Uint8Array> {
  const sodium = await getSodium()
  const opened = sodium.crypto_box_seal_open(sealed, recipientPublicKey, recipientPrivateKey)
  if (!opened) throw new Error('Key unwrap failed — wrong keys or corrupted data')
  return opened
}
