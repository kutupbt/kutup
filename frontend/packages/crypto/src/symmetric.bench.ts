// @vitest-environment node
// Microbenchmarks for symmetric crypto. Run with `pnpm vitest bench`.
//
// These set the perf budget for Rust/WASM's typed file-blob path.
import { bench, describe } from 'vitest'
import { encryptStream, decryptStream, generateKey } from './symmetric'

const KB = 1024
const MB = 1024 * KB

const key = await generateKey()
const context = {
  fileId: '11111111-1111-4111-8111-111111111111',
  collectionId: '22222222-2222-4222-8222-222222222222',
  epoch: 1,
}
const blobOneMB = new Uint8Array(1 * MB)
const blobFiveMB = new Uint8Array(5 * MB) // == CHUNK_SIZE in symmetric.ts
const stream1MB = await encryptStream(blobOneMB, key, context)
const stream5MB = await encryptStream(blobFiveMB, key, context)

describe('typed file blob (secretstream content)', () => {
  bench('encrypt 1 MB', async () => { await encryptStream(blobOneMB, key, context) })
  bench('encrypt 5 MB (single chunk)', async () => { await encryptStream(blobFiveMB, key, context) })
  bench('decrypt 1 MB', async () => { await decryptStream(stream1MB, key, context) })
  bench('decrypt 5 MB', async () => { await decryptStream(stream5MB, key, context) })
})
