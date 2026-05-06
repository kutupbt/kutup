// @vitest-environment node
// Microbenchmarks for symmetric crypto. Run with `pnpm vitest bench`.
//
// These set the perf budget for the AEAD path that wraps every kutup file
// chunk + every metadata blob. A 2× slowdown on either should be a flag.
import { bench, describe } from 'vitest'
import { encrypt, decrypt, encryptStream, decryptStream, generateKey } from './symmetric'

const KB = 1024
const MB = 1024 * KB

const key = await generateKey()
const small = new Uint8Array(1 * KB)
const medium = new Uint8Array(64 * KB)
const blobOneMB = new Uint8Array(1 * MB)
const blobFiveMB = new Uint8Array(5 * MB) // == CHUNK_SIZE in symmetric.ts
const enc1k = await encrypt(small, key)
const enc64k = await encrypt(medium, key)
const enc1MB = await encrypt(blobOneMB, key)
const stream1MB = await encryptStream(blobOneMB, key)
const stream5MB = await encryptStream(blobFiveMB, key)

describe('secretbox encrypt', () => {
  bench('1 KB', async () => { await encrypt(small, key) })
  bench('64 KB', async () => { await encrypt(medium, key) })
  bench('1 MB', async () => { await encrypt(blobOneMB, key) })
})

describe('secretbox decrypt', () => {
  bench('1 KB', async () => { await decrypt(enc1k.ciphertext, enc1k.nonce, key) })
  bench('64 KB', async () => { await decrypt(enc64k.ciphertext, enc64k.nonce, key) })
  bench('1 MB', async () => { await decrypt(enc1MB.ciphertext, enc1MB.nonce, key) })
})

describe('secretstream (file content)', () => {
  bench('encrypt 1 MB', async () => { await encryptStream(blobOneMB, key) })
  bench('encrypt 5 MB (single chunk)', async () => { await encryptStream(blobFiveMB, key) })
  bench('decrypt 1 MB', async () => { await decryptStream(stream1MB, key) })
  bench('decrypt 5 MB', async () => { await decryptStream(stream5MB, key) })
})
