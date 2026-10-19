// @vitest-environment node
import { describe, expect, it, vi } from 'vitest'
vi.mock('./rustWasm', async () => {
  const [{ readFile }, module] = await Promise.all([
    import('node:fs/promises'),
    import('../../../wasm/crypto-wasm/kutup_crypto_wasm.js'),
  ])
  const wasm = await readFile(new URL('../../../wasm/crypto-wasm/kutup_crypto_wasm_bg.wasm', import.meta.url))
  await module.default({ module_or_path: wasm })
  return { getCryptoWasm: async () => module }
})

import vectors from '../../../../crates/kutup-crypto/tests/vectors/account-refs-v1.json'
import { parseAccountKey, type AccountRef } from './accountRef'
import { fromBase64 } from './base64'
import { deriveAccountIdentityKeys } from './identity'
import { signDriveKeyBinding, verifyDriveKeyBinding } from './identityPins'
import { openFileShareEnvelope, openNamedShareEnvelope, openProfileKeyEnvelope } from './namedShare'

// The formats that name a person by their account (docs/plans/account-ids.md),
// opened in the browser exactly as in Rust (kutup-crypto account_ref_vectors).
describe('account vectors', () => {
  const someoneElse = (person: AccountRef): AccountRef => ({ ...person, accountId: '00000000-0000-4000-8000-000000000000' })

  it('binds the Drive keys to the account', async () => {
    const sender = await parseAccountKey(vectors.sender)
    const keys = await deriveAccountIdentityKeys(vectors.senderMasterKey)
    expect(await signDriveKeyBinding(vectors.senderMasterKey, sender, 1)).toBe(vectors.binding)
    const verify = (person: AccountRef) =>
      verifyDriveKeyBinding(person, keys.authorityPublicKey, keys.driveHpkePublicKey, keys.driveSigningPublicKey, vectors.binding, 1)
    expect(await verify(sender)).toBe(true)
    expect(await verify(someoneElse(sender))).toBe(false)
    // The epoch is signed: the same binding claimed for another one fails.
    expect(
      await verifyDriveKeyBinding(sender, keys.authorityPublicKey, keys.driveHpkePublicKey, keys.driveSigningPublicKey, vectors.binding, 2),
    ).toBe(false)
  })

  it('opens shares only between their accounts', async () => {
    const [sender, recipient, from, to] = await Promise.all([
      parseAccountKey(vectors.sender),
      parseAccountKey(vectors.recipient),
      deriveAccountIdentityKeys(vectors.senderMasterKey),
      deriveAccountIdentityKeys(vectors.recipientMasterKey),
    ])
    const privateKey = fromBase64(to.driveHpkePrivateKey)
    const parties = (who: AccountRef, toWhom: AccountRef) => ({
      sender: who,
      senderIncarnationId: from.incarnationId,
      recipient: toWhom,
      recipientIncarnationId: to.incarnationId,
    })
    const named = (who: AccountRef, toWhom: AccountRef) =>
      openNamedShareEnvelope(vectors.namedShare, from.driveSigningPublicKey, privateKey, {
        collectionId: vectors.collectionId,
        epoch: vectors.epoch,
        ...parties(who, toWhom),
      })
    expect(await named(sender, recipient)).toEqual(fromBase64(vectors.collectionKey))
    await expect(named(sender, someoneElse(recipient))).rejects.toBeDefined()

    const file = (who: AccountRef, toWhom: AccountRef) =>
      openFileShareEnvelope(vectors.fileShare, from.driveSigningPublicKey, privateKey, {
        fileId: vectors.fileId,
        generation: vectors.generation,
        ...parties(who, toWhom),
      })
    expect(await file(sender, recipient)).toEqual(fromBase64(vectors.fileKey))
    await expect(file(someoneElse(sender), recipient)).rejects.toBeDefined()

    const profile = (who: AccountRef, toWhom: AccountRef) =>
      openProfileKeyEnvelope(vectors.profileKeyEnvelope, from.driveSigningPublicKey, privateKey, parties(who, toWhom))
    expect(await profile(sender, recipient)).toEqual(fromBase64(vectors.profileKey))
    await expect(profile(someoneElse(sender), recipient)).rejects.toBeDefined()
  })
})
