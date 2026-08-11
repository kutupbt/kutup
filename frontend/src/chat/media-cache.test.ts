// @vitest-environment node
import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@/crypto/rustWasm', async () => {
  const [{ readFile }, module] = await Promise.all([
    import('node:fs/promises'),
    import('../../public/crypto-wasm/kutup_crypto_wasm.js'),
  ])
  const wasm = await readFile(new URL(
    '../../public/crypto-wasm/kutup_crypto_wasm_bg.wasm',
    import.meta.url,
  ))
  await module.default({ module_or_path: wasm })
  return { getCryptoWasm: async () => module }
})

import { encryptChatMediaV1 } from '@/crypto/chatMedia'
import { toBase64 } from '@/crypto/base64'
import { getSodium } from '@/crypto/sodium'
import {
  PrivateCiphertextCacheV1,
  type CiphertextCacheBackendV1,
  type CiphertextCacheChunkV1,
  type CiphertextCacheEntryV1,
} from '@/mediaCache'
import type { ChatAttachmentDescriptorV1 } from './types'
import {
  chatMediaCacheBindingV1,
  decryptChatMediaCiphertextV1,
  downloadChatMediaToCacheV1,
  isChatMediaAvailableInKutupV1,
  openCachedChatMediaV1,
} from './media'

class MemoryBackend implements CiphertextCacheBackendV1 {
  readonly entries = new Map<string, CiphertextCacheEntryV1>()
  readonly chunks = new Map<string, CiphertextCacheChunkV1[]>()
  async getByBindingKey(key: string) {
    return [...this.entries.values()].find(entry => entry.bindingKey === key) ?? null
  }
  async putEntry(entry: CiphertextCacheEntryV1) { this.entries.set(entry.cacheId, structuredClone(entry)) }
  async putChunk(chunk: CiphertextCacheChunkV1) {
    const values = this.chunks.get(chunk.cacheId) ?? []
    values.push({ ...chunk, bytes: chunk.bytes.slice() })
    this.chunks.set(chunk.cacheId, values)
  }
  async listChunks(cacheId: string) { return this.chunks.get(cacheId) ?? [] }
  async listEntries(scope: string) {
    return [...this.entries.values()].filter(entry => entry.accountScope === scope)
  }
  async deleteEntry(cacheId: string) { this.entries.delete(cacheId); this.chunks.delete(cacheId) }
  async clearAccount(scope: string) {
    for (const entry of await this.listEntries(scope)) await this.deleteEntry(entry.cacheId)
  }
}

const attachmentId = '11111111-1111-4111-8111-111111111111'
const key = new Uint8Array(32).fill(0x42)

async function fixture(): Promise<{
  plaintext: Uint8Array
  ciphertext: Uint8Array
  descriptor: ChatAttachmentDescriptorV1
}> {
  const plaintext = new TextEncoder().encode('authenticated offline Chat attachment')
  const ciphertext = await encryptChatMediaV1(plaintext, key, attachmentId)
  const sodium = await getSodium()
  return {
    plaintext,
    ciphertext,
    descriptor: {
      version: 1,
      suite: 1,
      attachmentId,
      originDomain: 'a.test',
      retrievalToken: 'opaque-token',
      ciphertextBytes: ciphertext.length,
      ciphertextSha256: sodium.crypto_hash_sha256(ciphertext, 'hex'),
      attachmentKey: toBase64(key),
      plaintextBytes: plaintext.length,
      filename: 'note.txt',
      mimeType: 'text/plain',
      mediaClass: 'file',
    },
  }
}

async function* split(bytes: Uint8Array): AsyncGenerator<Uint8Array> {
  yield bytes.subarray(0, 7)
  yield bytes.subarray(7, 41)
  yield bytes.subarray(41)
}

describe('Chat private ciphertext cache integration', () => {
  beforeEach(() => vi.restoreAllMocks())

  it('authenticates arbitrary cached chunk boundaries before yielding plaintext', async () => {
    const { plaintext, ciphertext, descriptor } = await fixture()
    const restored: number[] = []
    for await (const { plain } of decryptChatMediaCiphertextV1(split(ciphertext), descriptor)) {
      restored.push(...plain)
    }
    expect(Uint8Array.from(restored)).toEqual(plaintext)

    const tampered = ciphertext.slice()
    tampered[tampered.length - 1] ^= 1
    await expect(async () => {
      for await (const _chunk of decryptChatMediaCiphertextV1(split(tampered), descriptor)) {
        // Drain to force FINAL and digest verification.
      }
    }).rejects.toThrow()
  })

  it('downloads verified ciphertext into Kutup without creating an OS save', async () => {
    const { ciphertext, descriptor } = await fixture()
    const backend = new MemoryBackend()
    const cache = new PrivateCiphertextCacheV1('alice@a.test', {
      backend,
      maxBytes: 500_000,
      chunkBytes: 64 * 1024,
    })
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(
      new ReadableStream({
        start(controller) {
          controller.enqueue(ciphertext.subarray(0, 13))
          controller.enqueue(ciphertext.subarray(13))
          controller.close()
        },
      }),
      { status: 200 },
    ))
    const progress = vi.fn()
    await downloadChatMediaToCacheV1(cache, descriptor, 'access-token', progress)
    expect(fetchMock).toHaveBeenCalledOnce()
    expect(progress).toHaveBeenLastCalledWith(ciphertext.length, ciphertext.length)
    expect(await isChatMediaAvailableInKutupV1(cache, descriptor)).toBe(true)
    expect([...backend.entries.values()][0]).toMatchObject({
      ...chatMediaCacheBindingV1(descriptor),
      state: 'verified',
    })
  })

  it('removes all persisted chunks when the downloaded object is tampered', async () => {
    const { ciphertext, descriptor } = await fixture()
    const backend = new MemoryBackend()
    const cache = new PrivateCiphertextCacheV1('alice@a.test', {
      backend,
      maxBytes: 500_000,
      chunkBytes: 64 * 1024,
    })
    const tampered = ciphertext.slice()
    tampered[tampered.length - 1] ^= 1
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(tampered, { status: 200 }))
    await expect(downloadChatMediaToCacheV1(cache, descriptor, 'access-token')).rejects.toThrow()
    expect(backend.entries.size).toBe(0)
    expect(backend.chunks.size).toBe(0)
  })

  it('opens only bounded, reclassified image/audio/video/PDF plaintext', async () => {
    const png = new Uint8Array(24)
    png.set(new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))
    png.set(new TextEncoder().encode('IHDR'), 12)
    new DataView(png.buffer).setUint32(16, 2, false)
    new DataView(png.buffer).setUint32(20, 3, false)
    const ciphertext = await encryptChatMediaV1(png, key, attachmentId)
    const sodium = await getSodium()
    const descriptor: ChatAttachmentDescriptorV1 = {
      version: 1,
      suite: 1,
      attachmentId,
      originDomain: 'a.test',
      retrievalToken: 'opaque-token',
      ciphertextBytes: ciphertext.length,
      ciphertextSha256: sodium.crypto_hash_sha256(ciphertext, 'hex'),
      attachmentKey: toBase64(key),
      plaintextBytes: png.length,
      filename: 'photo.png',
      mimeType: 'image/png',
      mediaClass: 'photo',
    }
    const backend = new MemoryBackend()
    const cache = new PrivateCiphertextCacheV1('alice@a.test', {
      backend,
      maxBytes: 500_000,
      chunkBytes: 64 * 1024,
    })
    await cache.putVerified(chatMediaCacheBindingV1(descriptor), split(ciphertext), async () => {})
    const opened = await openCachedChatMediaV1(cache, descriptor)
    expect(opened).toMatchObject({ kind: 'image', mimeType: 'image/png' })
    expect(new Uint8Array(await opened.blob.arrayBuffer())).toEqual(png)
    await expect(openCachedChatMediaV1(cache, {
      ...descriptor,
      filename: 'photo.jpg',
      mimeType: 'image/jpeg',
    })).rejects.toThrow(/not safe/)

    const pdfAttachmentId = '22222222-2222-4222-8222-222222222222'
    const pdf = new TextEncoder().encode('%PDF-1.7\n% bounded test')
    const pdfCiphertext = await encryptChatMediaV1(pdf, key, pdfAttachmentId)
    const pdfDescriptor: ChatAttachmentDescriptorV1 = {
      ...descriptor,
      attachmentId: pdfAttachmentId,
      ciphertextBytes: pdfCiphertext.length,
      ciphertextSha256: sodium.crypto_hash_sha256(pdfCiphertext, 'hex'),
      plaintextBytes: pdf.length,
      filename: 'report.pdf',
      mimeType: 'application/pdf',
      mediaClass: 'file',
    }
    await cache.putVerified(
      chatMediaCacheBindingV1(pdfDescriptor),
      split(pdfCiphertext),
      async () => {},
    )
    const openedPdf = await openCachedChatMediaV1(cache, pdfDescriptor)
    expect(openedPdf).toMatchObject({ kind: 'pdf', mimeType: 'application/pdf' })
    expect(new Uint8Array(await openedPdf.blob.arrayBuffer())).toEqual(pdf)
  })
})
