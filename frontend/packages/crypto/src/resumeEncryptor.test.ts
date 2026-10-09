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

import { generateKey } from './index'
import {
  newFileBlobStreamEncryptorV1,
  openFileBlobStreamV1,
  resumeFileBlobStreamEncryptorV1,
  DRIVE_FILE_BLOB_PREFIX_BYTES,
} from './fileBlob'
import { newStreamEncryptor, resumeStreamEncryptor } from './streamEncryptor'

function chunk(seed: number, size = 4096) {
  return Uint8Array.from({ length: size }, (_, i) => (i * 31 + seed) & 0xff)
}

describe('resuming an encryptor from its header', () => {
  it('reproduces a secretstream byte for byte', async () => {
    const key = await generateKey()
    const ad = chunk(9, 32)
    const first = await newStreamEncryptor(key, ad)
    const original = [first.push(chunk(1), false), first.push(chunk(2), false), first.push(chunk(3, 100), true)]
    const again = await resumeStreamEncryptor(key, first.header, ad)
    expect([again.push(chunk(1), false), again.push(chunk(2), false), again.push(chunk(3, 100), true)]).toEqual(original)
  })

  it('reproduces a Drive file blob, which still opens, and refuses another file', async () => {
    const fileKey = await generateKey()
    const context = { fileId: crypto.randomUUID(), generation: 1 }
    const first = await newFileBlobStreamEncryptorV1(fileKey, context)
    const original = [first.push(chunk(4), false), first.push(chunk(5, 10), true)]
    const again = await resumeFileBlobStreamEncryptorV1(fileKey, context, first.prefix)
    expect(again.prefix).toEqual(first.prefix)
    expect([again.push(chunk(4), false), again.push(chunk(5, 10), true)]).toEqual(original)

    const decryptor = await openFileBlobStreamV1(first.prefix, fileKey, context)
    expect(decryptor.pull(original[0]).plain).toEqual(chunk(4))

    await expect(resumeFileBlobStreamEncryptorV1(fileKey, { ...context, fileId: crypto.randomUUID() }, first.prefix)).rejects.toThrow()
    await expect(resumeFileBlobStreamEncryptorV1(fileKey, context, first.prefix.slice(0, DRIVE_FILE_BLOB_PREFIX_BYTES - 1))).rejects.toThrow()
  })
})
