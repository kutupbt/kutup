// @vitest-environment node
import { describe, expect, it, vi } from 'vitest'
vi.mock('@kutup/crypto/rustWasm', async () => {
  const [{ readFile }, module] = await Promise.all([
    import('node:fs/promises'),
    import('../../../../wasm/crypto-wasm/kutup_crypto_wasm.js'),
  ])
  const wasm = await readFile(new URL('../../../../wasm/crypto-wasm/kutup_crypto_wasm_bg.wasm', import.meta.url))
  await module.default({ module_or_path: wasm })
  return { getCryptoWasm: async () => module }
})

import { generateKey } from '@kutup/crypto'
import {
  DRIVE_FILE_BLOB_CIPHER_CHUNK,
  fileBlobCipherSize,
  newFileBlobStreamEncryptorV1,
  resumeFileBlobStreamEncryptorV1,
} from '@kutup/crypto/fileBlob'
import { PLAIN_CHUNK } from '@kutup/crypto/streamEncryptor'
import { EncryptedFileSource, type PlaintextSource } from './encryptedSource'

function plaintext(size: number): PlaintextSource & { reads: number } {
  const bytes = Uint8Array.from({ length: size }, (_, i) => (i * 7 + 3) & 0xff)
  const source = {
    size,
    reads: 0,
    read: async (start: number, end: number) => {
      source.reads++
      return bytes.slice(start, end)
    },
  }
  return source
}

/** The whole ciphertext, as one upload with a fresh encryptor makes it. */
async function setup(size: number) {
  const fileKey = await generateKey()
  const context = { fileId: crypto.randomUUID(), generation: 1 }
  const first = await newFileBlobStreamEncryptorV1(fileKey, context)
  const plain = plaintext(size)
  const parts = [first.prefix]
  const messages = Math.max(1, Math.ceil(size / PLAIN_CHUNK))
  for (let i = 0; i < messages; i++) {
    const from = i * PLAIN_CHUNK
    parts.push(first.push(await plain.read(from, Math.min(from + PLAIN_CHUNK, size)), i === messages - 1))
  }
  const whole = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let at = 0
  for (const p of parts) {
    whole.set(p, at)
    at += p.length
  }
  const source = (input = plaintext(size)) => ({
    input,
    source: new EncryptedFileSource(input, () => resumeFileBlobStreamEncryptorV1(fileKey, context, first.prefix), first.prefix),
  })
  return { whole, source }
}

// Several 5 MiB chunks are built and encrypted here; that takes a few seconds.
vi.setConfig({ testTimeout: 60_000 })

describe('EncryptedFileSource', () => {
  for (const size of [0, 10, PLAIN_CHUNK, PLAIN_CHUNK + 1, 2 * PLAIN_CHUNK + 123]) {
    it(`gives tus the exact ciphertext of a ${size}-byte file`, async () => {
      const { whole, source } = await setup(size)
      const { source: s } = source()
      expect(s.size).toBe(fileBlobCipherSize(size))
      expect(whole.length).toBe(s.size)
      const read: Uint8Array[] = []
      for (let at = 0; at < s.size; at += DRIVE_FILE_BLOB_CIPHER_CHUNK) {
        const { bytes: value, done } = await s.bytes(at, at + DRIVE_FILE_BLOB_CIPHER_CHUNK)
        read.push(value)
        expect(done).toBe(at + DRIVE_FILE_BLOB_CIPHER_CHUNK >= s.size)
      }
      expect(Buffer.concat(read).equals(Buffer.from(whole))).toBe(true)
    })
  }

  it('resumes in the middle with the same bytes, and a retried range reads nothing again', async () => {
    const size = 3 * PLAIN_CHUNK + 5
    const { whole, source } = await setup(size)
    const { source: s, input } = source()
    const at = 2 * DRIVE_FILE_BLOB_CIPHER_CHUNK
    const first = await s.bytes(at, at + DRIVE_FILE_BLOB_CIPHER_CHUNK)
    expect(Buffer.from(first.bytes).equals(Buffer.from(whole.subarray(at, at + DRIVE_FILE_BLOB_CIPHER_CHUNK)))).toBe(true)
    const reads = input.reads
    const retried = await s.bytes(at, at + DRIVE_FILE_BLOB_CIPHER_CHUNK)
    expect(retried.bytes).toEqual(first.bytes)
    expect(input.reads).toBe(reads)
  })

  it('resumed in the middle of a whole number of chunks, reads to the very end', async () => {
    const size = 8 * PLAIN_CHUNK
    const { whole, source } = await setup(size)
    const { source: s } = source()
    const read: Uint8Array[] = []
    let done = false
    for (let at = 3 * DRIVE_FILE_BLOB_CIPHER_CHUNK; !done; at += DRIVE_FILE_BLOB_CIPHER_CHUNK) {
      const slice = await s.bytes(at, at + DRIVE_FILE_BLOB_CIPHER_CHUNK)
      read.push(slice.bytes)
      done = slice.done
    }
    const tail = Buffer.concat(read)
    expect(tail.length).toBe(whole.length - 3 * DRIVE_FILE_BLOB_CIPHER_CHUNK)
    expect(tail.equals(Buffer.from(whole.subarray(3 * DRIVE_FILE_BLOB_CIPHER_CHUNK)))).toBe(true)
  })

  it('starts the stream over for a range before the ones it kept', async () => {
    const size = 4 * PLAIN_CHUNK
    const { whole, source } = await setup(size)
    const { source: s } = source()
    await s.bytes(3 * DRIVE_FILE_BLOB_CIPHER_CHUNK, 4 * DRIVE_FILE_BLOB_CIPHER_CHUNK)
    const early = await s.bytes(0, DRIVE_FILE_BLOB_CIPHER_CHUNK)
    expect(Buffer.from(early.bytes).equals(Buffer.from(whole.subarray(0, DRIVE_FILE_BLOB_CIPHER_CHUNK)))).toBe(true)
  })

  it("gives tus a Blob, whose size tus reads, down to the last range", async () => {
    const { source } = await setup(PLAIN_CHUNK)
    const { source: s } = source()
    const last = await s.slice(DRIVE_FILE_BLOB_CIPHER_CHUNK, 2 * DRIVE_FILE_BLOB_CIPHER_CHUNK)
    expect(last.value).toBeInstanceOf(Blob)
    expect(last.value.size).toBe(s.size - DRIVE_FILE_BLOB_CIPHER_CHUNK)
    expect(last.done).toBe(true)
  })

  it('refuses a file that changed size while it was read', async () => {
    const { source } = await setup(PLAIN_CHUNK + 10)
    const shrunk = { ...plaintext(PLAIN_CHUNK + 10), read: async () => new Uint8Array(3) }
    const { source: s } = source(shrunk as unknown as ReturnType<typeof plaintext>)
    await expect(s.bytes(0, DRIVE_FILE_BLOB_CIPHER_CHUNK)).rejects.toThrow(/changed/)
  })
})
