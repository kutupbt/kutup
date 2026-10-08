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

import vectors from '../../../../crates/kutup-crypto/tests/vectors/crypto.json'
import { fromBase64, toBase64 } from './base64'
import { hashBlob } from './contentHash'
import { canonicalName, contentHash, folderHashKey, nameHash, topLevelHashKey } from './driveNames'

describe('drive names (vectors shared with Rust)', () => {
  const v = vectors.driveNames

  it('derives the folder hash key, canonical names and name hashes', async () => {
    const key = await folderHashKey(fromBase64(v.firstFolderKey), v.collectionId)
    expect(toBase64(key)).toBe(v.hashKey)
    expect(toBase64(await topLevelHashKey(fromBase64(v.masterKey)))).toBe(v.topLevelHashKey)
    for (const c of v.names) {
      expect(await canonicalName(c.name)).toBe(c.canonical)
      expect(await nameHash(key, c.name)).toBe(c.hash)
    }
  })

  it('hashes content from the SHA-256 the uploads compute', async () => {
    const key = fromBase64(v.hashKey)
    const digest = await hashBlob(new Blob([fromBase64(v.content.plaintext) as Uint8Array<ArrayBuffer>]))
    expect(digest).toBe(v.content.sha256)
    expect(await contentHash(key, digest)).toBe(v.content.hash)
  })
})
