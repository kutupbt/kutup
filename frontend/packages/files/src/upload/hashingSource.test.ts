// @vitest-environment node
import { describe, expect, it, vi } from 'vitest'
vi.mock('@kutup/crypto/rustWasm', async () => {
  const [{ readFile }, module] = await Promise.all([
    import('node:fs/promises'),
    import('../../../../wasm/crypto-wasm/kutup_crypto_wasm.js'),
  ])
  const wasm = await readFile(new URL('../../../../wasm/crypto-wasm/kutup_crypto_wasm_bg.wasm', import.meta.url))
  await module.default({ module_or_path: wasm })
  return { getCryptoWasm: () => Promise.resolve(module) }
})

import { createHash } from 'node:crypto'
import { hashingSource } from './streamUpload'
import { fileSource } from './encryptedSource'

const sha = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('base64')

describe('the content hash an upload computes', () => {
  const bytes = new Uint8Array(1000).map((_, i) => i % 251)

  it('is the SHA-256 of the file read in order, even when reading starts over', async () => {
    const hashed = await hashingSource(fileSource(new Blob([bytes])))
    await hashed.source.read(0, 400)
    // A pass that starts over reads from the start again: not hashed twice.
    await hashed.source.read(0, 400)
    await hashed.source.read(400, 1000)
    expect(hashed.digest()).toBe(sha(bytes))
    expect(hashed.digest()).toBe(sha(bytes))
  })

  it('is unknown when not every byte was read in order', async () => {
    const hashed = await hashingSource(fileSource(new Blob([bytes])))
    await hashed.source.read(400, 1000)
    expect(hashed.digest()).toBeNull()
  })

  it('is the empty file’s for an empty file', async () => {
    const hashed = await hashingSource(fileSource(new Blob([])))
    expect(hashed.digest()).toBe(sha(new Uint8Array(0)))
  })
})
