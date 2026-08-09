// @vitest-environment node
import { describe, expect, it, vi } from 'vitest'

vi.mock('./rustWasm', async () => {
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

import {
  CHAT_MEDIA_OBJECT_PREFIX_BYTES,
  chatAttachmentLedgerEnvelopeDigest,
  chatMediaCipherSize,
  decryptChatMediaV1,
  decodeChatAttachmentLedgerEntry,
  deriveChatAttachmentLedgerKey,
  encodeChatAttachmentLedgerEntry,
  encryptChatMediaV1,
  inspectChatAttachmentLedgerEnvelope,
  openChatAttachmentLedger,
  sealChatAttachmentLedger,
} from './chatMedia'

const attachmentId = '11111111-1111-4111-8111-111111111111'
const entityId = '22222222-2222-4222-8222-222222222222'
const incarnationId = '11'.repeat(32)

describe('Chat-media Rust/WASM framing', () => {
  it('round-trips empty and ordinary objects with mandatory FINAL framing', async () => {
    const key = new Uint8Array(32).fill(0x42)
    for (const plaintext of [new Uint8Array(), new TextEncoder().encode('photo bytes')]) {
      const object = await encryptChatMediaV1(plaintext, key, attachmentId)
      expect(object.length).toBe(chatMediaCipherSize(plaintext.length))
      expect(object.length).toBeGreaterThan(CHAT_MEDIA_OBJECT_PREFIX_BYTES)
      expect(await decryptChatMediaV1(object, key, attachmentId)).toEqual(plaintext)
    }
  })

  it('rejects key, attachment, tamper, truncation, and trailing data changes', async () => {
    const key = new Uint8Array(32).fill(0x42)
    const object = await encryptChatMediaV1(new TextEncoder().encode('opaque'), key, attachmentId)
    await expect(decryptChatMediaV1(
      object,
      new Uint8Array(32).fill(0x43),
      attachmentId,
    )).rejects.toThrow()
    await expect(decryptChatMediaV1(
      object,
      key,
      '33333333-3333-4333-8333-333333333333',
    )).rejects.toThrow()
    const tampered = object.slice()
    tampered[tampered.length - 1] ^= 1
    await expect(decryptChatMediaV1(tampered, key, attachmentId)).rejects.toThrow()
    await expect(decryptChatMediaV1(object.subarray(0, -1), key, attachmentId)).rejects.toThrow()
    const trailing = new Uint8Array(object.length + 1)
    trailing.set(object)
    await expect(decryptChatMediaV1(trailing, key, attachmentId)).rejects.toThrow()
  })
})

describe('Chat attachment ledger Rust/WASM envelope', () => {
  it('derives a stable purpose key and enforces account/entity/revision context', async () => {
    const key = await deriveChatAttachmentLedgerKey(new Uint8Array(32).fill(0x33))
    expect(Array.from(key)).toEqual(Array.from(await deriveChatAttachmentLedgerKey(
      new Uint8Array(32).fill(0x33),
    )))
    const plaintext = new TextEncoder().encode('canonical entry')
    const context = {
      accountIncarnationId: incarnationId,
      entityId,
      revision: 1n,
    }
    const envelope = await sealChatAttachmentLedger(plaintext, key, context)
    expect(await inspectChatAttachmentLedgerEnvelope(envelope)).toEqual({
      suite: 1,
      accountIncarnationId: incarnationId,
      entityId,
      revision: '1',
      previousEnvelopeDigest: '0'.repeat(64),
    })
    expect(await openChatAttachmentLedger(envelope, key, context)).toEqual(plaintext)
    expect(await chatAttachmentLedgerEnvelopeDigest(envelope)).toMatch(/^[0-9a-f]{64}$/)
    await expect(openChatAttachmentLedger(envelope, key, {
      ...context,
      entityId: '33333333-3333-4333-8333-333333333333',
    })).rejects.toThrow()
    await expect(openChatAttachmentLedger(envelope, key, {
      ...context,
      revision: 2n,
      previousEnvelopeDigest: '22'.repeat(32),
    })).rejects.toThrow()
  })

  it('uses the strict Rust canonical codec for private accounting entries', async () => {
    const entry = {
      version: 1,
      conversationKind: 'direct',
      conversationReference: 'bob@example.test',
      messageId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      attachmentId,
      storageReferenceId: '44444444-4444-4444-8444-444444444444',
      ciphertextBytes: 123,
      state: 'active',
      mediaClass: 'photo',
      displayName: 'cat.jpg',
      updatedAtMs: 1_800_000_000_000,
    }
    const canonical = await encodeChatAttachmentLedgerEntry(entry)
    expect(canonical.length).toBeGreaterThan(64)
    expect(await decodeChatAttachmentLedgerEntry(canonical)).toEqual(entry)
    await expect(encodeChatAttachmentLedgerEntry({
      ...entry,
      conversationReference: 'Bob@example.test',
    })).rejects.toThrow()
  })
})
