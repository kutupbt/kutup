// @vitest-environment node
// The block format's benchmark (docs/plans/drive-block-format.md §9): one
// 4 MiB block sealed and opened in kutup-crypto-wasm, against libsodium doing
// the same work (XChaCha20-Poly1305 and the two SHA-256s): the check the 10×
// rule in docs/cryptographic-dependencies.md asks for before a format leaves
// a libsodium primitive for the Rust core. Run with
// `pnpm -C frontend exec vitest bench --run packages/crypto/src/blocks.bench.ts`.
import { readFile } from 'node:fs/promises'
import { bench, describe } from 'vitest'
import { getSodium } from './sodium'

const module = await import('../../../wasm/crypto-wasm/kutup_crypto_wasm.js')
await module.default({
  module_or_path: await readFile(new URL('../../../wasm/crypto-wasm/kutup_crypto_wasm_bg.wasm', import.meta.url)),
})
const sodium = await getSodium()

const BLOCK = 4 * 1024 * 1024
const key = Buffer.alloc(32, 0x42).toString('base64')
const keyBytes = new Uint8Array(32).fill(0x42)
const fileId = '11111111-1111-4111-8111-111111111111'
const revisionId = '22222222-2222-4222-8222-222222222222'
const plaintext = Uint8Array.from({ length: BLOCK }, (_, i) => (i * 31) % 251)

const encryptor = module.driveBlockEncryptor(key, fileId, revisionId, 1, BLOCK)
const header = encryptor.header()
const block = encryptor.sealNext(plaintext)
const tail = encryptor.finishSigned(
  Buffer.alloc(32, 7).toString('base64'),
  '0b9f4c0e-6a51-4d2f-9a33-5e1f6c7d8e90',
  '05'.repeat(32),
)
const manifestSha256 = encryptor.manifestSha256
encryptor.free()
if (!manifestSha256) throw new Error('the encryptor gave no manifest digest')
const reader = module.driveBlockReader(key, fileId, 1, revisionId, manifestSha256, BLOCK, header, tail.subarray(0, tail.length - 12))

const nonce = new Uint8Array(24).fill(1)
const aad = new Uint8Array(53)
const sealedAead = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, null, nonce, keyBytes)

describe('seal one 4 MiB block', () => {
  bench('kutup-crypto-wasm block (hash, synthetic nonce, AEAD, block hash)', () => {
    const sealer = module.driveBlockEncryptor(key, fileId, revisionId, 1, BLOCK)
    sealer.sealNext(plaintext)
    sealer.free()
  })
  bench('libsodium, the same work (SHA-256, AEAD, SHA-256)', () => {
    sodium.crypto_hash_sha256(plaintext)
    const sealed = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, null, nonce, keyBytes)
    sodium.crypto_hash_sha256(sealed)
  })
})

describe('open one 4 MiB block', () => {
  bench('kutup-crypto-wasm block (block hash, AEAD)', () => {
    reader.openBlock(0, block)
  })
  bench('libsodium, the same work (SHA-256, AEAD)', () => {
    sodium.crypto_hash_sha256(sealedAead)
    sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, sealedAead, aad, nonce, keyBytes)
  })
})
