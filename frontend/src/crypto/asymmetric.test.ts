import { describe, it, expect } from 'vitest'
import {
  generateKeypair,
  wrapKeyForRecipient,
  unwrapKeyFromSender,
} from './asymmetric'
import { generateKey } from './symmetric'

describe('asymmetric — X25519 sealed box', () => {
  it('generateKeypair returns 32-byte public + private', async () => {
    const kp = await generateKeypair()
    expect(kp.publicKey.length).toBe(32) // crypto_box_PUBLICKEYBYTES
    expect(kp.privateKey.length).toBe(32) // crypto_box_SECRETKEYBYTES
  })

  it('generates distinct keypairs', async () => {
    const a = await generateKeypair()
    const b = await generateKeypair()
    expect(Array.from(a.publicKey)).not.toEqual(Array.from(b.publicKey))
    expect(Array.from(a.privateKey)).not.toEqual(Array.from(b.privateKey))
  })

  it('round-trips a wrapped key for the right recipient', async () => {
    const kp = await generateKeypair()
    const symKey = await generateKey()
    const sealed = await wrapKeyForRecipient(symKey, kp.publicKey)
    // crypto_box_seal output = 32-byte ephemeral pk || ciphertext+tag
    expect(sealed.length).toBe(32 + symKey.length + 16)
    const out = await unwrapKeyFromSender(sealed, kp.publicKey, kp.privateKey)
    expect(Array.from(out)).toEqual(Array.from(symKey))
  })

  it('throws when unwrapping with the wrong recipient private key', async () => {
    const intended = await generateKeypair()
    const attacker = await generateKeypair()
    const symKey = await generateKey()
    const sealed = await wrapKeyForRecipient(symKey, intended.publicKey)
    await expect(
      unwrapKeyFromSender(sealed, intended.publicKey, attacker.privateKey),
    ).rejects.toThrow()
  })

  it('throws when unwrapping with the wrong recipient public key', async () => {
    const intended = await generateKeypair()
    const otherPub = (await generateKeypair()).publicKey
    const symKey = await generateKey()
    const sealed = await wrapKeyForRecipient(symKey, intended.publicKey)
    // Mismatched public-key argument: libsodium's seal_open uses pubkey
    // for the ECDH input and nonce derivation, so a wrong pk must fail.
    await expect(
      unwrapKeyFromSender(sealed, otherPub, intended.privateKey),
    ).rejects.toThrow()
  })

  it('produces a different sealed envelope for the same key on each call (ephemeral nonce)', async () => {
    const kp = await generateKeypair()
    const symKey = await generateKey()
    const a = await wrapKeyForRecipient(symKey, kp.publicKey)
    const b = await wrapKeyForRecipient(symKey, kp.publicKey)
    expect(Array.from(a)).not.toEqual(Array.from(b))
  })

  it('throws on tampered sealed envelope', async () => {
    const kp = await generateKeypair()
    const symKey = await generateKey()
    const sealed = await wrapKeyForRecipient(symKey, kp.publicKey)
    sealed[40] ^= 0xff // somewhere in the ciphertext region
    await expect(
      unwrapKeyFromSender(sealed, kp.publicKey, kp.privateKey),
    ).rejects.toThrow()
  })
})
