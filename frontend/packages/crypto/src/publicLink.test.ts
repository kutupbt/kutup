// @vitest-environment node
import { describe, expect, it, vi } from 'vitest'

vi.mock('./rustWasm', async () => {
  const [{ readFile }, module] = await Promise.all([
    import('node:fs/promises'),
    import('../../../wasm/crypto-wasm/kutup_crypto_wasm.js'),
  ])
  const wasm = await readFile(new URL(
    '../../../wasm/crypto-wasm/kutup_crypto_wasm_bg.wasm',
    import.meta.url,
  ))
  await module.default({ module_or_path: wasm })
  return { getCryptoWasm: async () => module }
})

import vectors from '../../../../crates/kutup-crypto/tests/vectors/crypto.json'
import passwordVectors from '../../../../crates/kutup-crypto/tests/vectors/drive-link-password-v1.json'
import type { DriveRoot } from './accountRoots'
import { fromBase64 } from './base64'
import { openOwnerCollectionKey, sealOwnerCollectionKey } from './ownedCollection'
import {
  deriveLinkPasswordV1,
  openLinkPasswordKeyV1,
  openOwnerLinkSecretV1,
  protectLinkPasswordV1,
  sealOwnerLinkSecretV1,
  openOwnerLinkKeyV1,
  openPublicLinkCollectionKeyV1,
  sealOwnerLinkKeyV1,
  sealPublicLinkCollectionKeyV1,
} from './publicLink'

const context = {
  collectionId: '22222222-2222-4222-8222-222222222222',
  ownerAccountId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  epoch: 3,
}

describe('public-link collection-key envelope', () => {
  it('round-trips through the canonical Rust/WASM implementation', async () => {
    const collectionKey = new Uint8Array(32).fill(0x41)
    const linkKey = new Uint8Array(32).fill(0x52)
    const envelope = await sealPublicLinkCollectionKeyV1(collectionKey, linkKey, context)
    expect(await openPublicLinkCollectionKeyV1(envelope, linkKey, context))
      .toEqual(collectionKey)
  })

  it('rejects a wrong fragment key', async () => {
    const envelope = await sealPublicLinkCollectionKeyV1(
      new Uint8Array(32).fill(0x41),
      new Uint8Array(32).fill(0x52),
      context,
    )
    await expect(openPublicLinkCollectionKeyV1(
      envelope,
      new Uint8Array(32).fill(0x53),
      context,
    )).rejects.toThrow()
  })

  it('rejects collection, owner, and epoch relocation', async () => {
    const collectionKey = new Uint8Array(32).fill(0x41)
    const linkKey = new Uint8Array(32).fill(0x52)
    const envelope = await sealPublicLinkCollectionKeyV1(collectionKey, linkKey, context)
    await expect(openPublicLinkCollectionKeyV1(envelope, linkKey, {
      ...context,
      collectionId: '33333333-3333-4333-8333-333333333333',
    })).rejects.toThrow()
    await expect(openPublicLinkCollectionKeyV1(envelope, linkKey, {
      ...context,
      ownerAccountId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    })).rejects.toThrow()
    await expect(openPublicLinkCollectionKeyV1(envelope, linkKey, {
      ...context,
      epoch: context.epoch + 1,
    })).rejects.toThrow()
  })
})

describe('owner copies under the Drive root (vectors shared with Rust)', () => {
  const v = vectors.driveOwnerKeys
  const roots = { driveRoot: v.driveRoot as DriveRoot, driveGeneration: v.driveRootGeneration }
  const folder = { collectionId: v.collectionId, ownerAccountId: v.ownerAccountId, epoch: v.collectionEpoch }
  const link = { linkId: v.linkId, ownerAccountId: v.ownerAccountId }

  it('opens the checked-in owner copies and round-trips new ones', async () => {
    expect(await openOwnerCollectionKey(v.collectionKeyEnvelope, roots, folder)).toEqual(fromBase64(v.collectionKey))
    expect(await openOwnerLinkKeyV1(v.linkKeyEnvelope, roots, link)).toEqual(fromBase64(v.linkKey))
    const sealed = await sealOwnerCollectionKey(fromBase64(v.collectionKey), roots, folder)
    expect(await openOwnerCollectionKey(sealed, roots, folder)).toEqual(fromBase64(v.collectionKey))
    const sealedLink = await sealOwnerLinkKeyV1(fromBase64(v.linkKey), roots, link)
    expect(await openOwnerLinkKeyV1(sealedLink, roots, link)).toEqual(fromBase64(v.linkKey))
  })

  it('refuses another generation, epoch or kind', async () => {
    await expect(openOwnerCollectionKey(v.collectionKeyEnvelope, { ...roots, driveGeneration: 1 }, folder)).rejects.toThrow()
    await expect(openOwnerCollectionKey(v.collectionKeyEnvelope, roots, { ...folder, epoch: folder.epoch + 1 })).rejects.toThrow()
    await expect(openOwnerLinkKeyV1(v.collectionKeyEnvelope, roots, { ...link, linkId: v.collectionId })).rejects.toThrow()
  })
})

describe('link passwords (vectors shared with Rust)', () => {
  it('derives the checked-in proof and wrap key and opens the link key', async () => {
    for (const c of passwordVectors.cases) {
      const keys = await deriveLinkPasswordV1(fromBase64(c.secret), c.password, {
        linkId: c.linkId,
        salt: c.salt,
        operations: c.operations,
        memory: c.memory,
      })
      expect(keys.proof).toBe(c.proof)
      expect(keys.wrapKey).toEqual(fromBase64(c.wrapKey))
      const context = { linkId: c.linkId, ownerAccountId: c.ownerAccountId, keyRevision: c.keyRevision }
      expect(await openLinkPasswordKeyV1(c.linkKeyEnvelope, keys.wrapKey, context)).toEqual(fromBase64(c.linkKey))
      await expect(openLinkPasswordKeyV1(c.linkKeyEnvelope, keys.wrapKey, { ...context, keyRevision: c.keyRevision + 1 })).rejects.toThrow()
      const roots = { driveRoot: c.driveRoot as DriveRoot, driveGeneration: c.driveRootGeneration }
      const owner = { linkId: c.linkId, ownerAccountId: c.ownerAccountId }
      const opened = await openOwnerLinkSecretV1(c.ownerSecretEnvelope, roots, owner)
      expect(opened.secret).toEqual(fromBase64(c.secret))
      expect(opened.password).toBe(c.password.normalize('NFC'))
      const sealed = await sealOwnerLinkSecretV1(fromBase64(c.secret), c.password, roots, owner)
      expect((await openOwnerLinkSecretV1(sealed, roots, owner)).password).toBe(c.password.normalize('NFC'))
    }
  })

  it('protects a new link key that only the right password opens', async () => {
    const secret = new Uint8Array(32).fill(0x11)
    const linkKey = new Uint8Array(32).fill(0x22)
    const context = { linkId: '33333333-3333-4333-8333-333333333333', ownerAccountId: '22222222-2222-4222-8222-222222222222', keyRevision: 2 }
    const protection = await protectLinkPasswordV1(secret, 'hunter2', linkKey, context)
    const params = { linkId: context.linkId, salt: protection.salt, operations: protection.operations, memory: protection.memory }
    const right = await deriveLinkPasswordV1(secret, 'hunter2', params)
    expect(await openLinkPasswordKeyV1(protection.linkKeyEnvelope, right.wrapKey, context)).toEqual(linkKey)
    const wrong = await deriveLinkPasswordV1(secret, 'hunter3', params)
    await expect(openLinkPasswordKeyV1(protection.linkKeyEnvelope, wrong.wrapKey, context)).rejects.toThrow()
  }, 60_000)
})
