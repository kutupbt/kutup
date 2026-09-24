// @vitest-environment node
import { describe, expect, it, vi } from 'vitest'
import vectors from '../../../../crates/kutup-crypto/tests/vectors/crypto.json'
import { fromBase64 } from './base64'

vi.mock('./rustWasm', async () => {
  const [{ readFile }, module] = await Promise.all([
    import('node:fs/promises'),
    import('../../../wasm/crypto-wasm/kutup_crypto_wasm.js'),
  ])
  const wasm = await readFile(new URL('../../../wasm/crypto-wasm/kutup_crypto_wasm_bg.wasm', import.meta.url))
  await module.default({ module_or_path: wasm })
  return { getCryptoWasm: async () => module }
})

import { sealPreviousCollectionKey, unlockCollectionKeyring, type EpochLinkV1 } from './collectionKeyring'

const ring = vectors.collectionKeyring
const chain: EpochLinkV1[] = ring.chain.map((link) => ({
  epoch: link.epoch,
  epochStatement: link.statement,
  epochStatementHash: '',
  previousKeyEnvelope: link.previousKeyEnvelope ?? undefined,
}))
const keys = ring.keys.map((k) => fromBase64(k))

describe('folder keyring (docs/plans/drive-share-revocation.md)', () => {
  it('unlocks every older key from the current one, as the canonical vector says', async () => {
    const unlocked = await unlockCollectionKeyring(keys[2], ring.collectionId, ring.ownerUserId, ring.authorityPublicKey, chain)
    expect(unlocked).toEqual(keys)
  })

  it('refuses an older key: a removed member cannot read on', async () => {
    await expect(
      unlockCollectionKeyring(keys[1], ring.collectionId, ring.ownerUserId, ring.authorityPublicKey, chain),
    ).rejects.toThrow()
  })

  it('refuses a history with a gap or a substituted key', async () => {
    await expect(
      unlockCollectionKeyring(keys[2], ring.collectionId, ring.ownerUserId, ring.authorityPublicKey, [chain[0], chain[2]]),
    ).rejects.toThrow()
    const substitute = await sealPreviousCollectionKey(new Uint8Array(32).fill(9), keys[2], ring.collectionId, ring.ownerUserId, 3)
    await expect(
      unlockCollectionKeyring(keys[2], ring.collectionId, ring.ownerUserId, ring.authorityPublicKey, [
        chain[0],
        chain[1],
        { ...chain[2], previousKeyEnvelope: substitute },
      ]),
    ).rejects.toThrow()
  })
})
