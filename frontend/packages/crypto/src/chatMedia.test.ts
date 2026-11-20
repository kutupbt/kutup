// @vitest-environment node
import { firstMasterKeys } from '@kutup/crypto/masterKeys'
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

import {
  chatMediaObjectLength,
  decodeChatAttachmentLedgerEntry,
  encodeChatAttachmentLedgerEntry,
  openChatAttachmentLedger,
  openChatMedia,
  sealChatAttachmentLedger,
  sealChatMedia,
} from './chatMedia'

const attachmentId = '11111111-1111-4111-8111-111111111111'
// A random record id of the chatAttachments scope: 32 bytes, base64url.
const entityId = 'IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI'
const otherEntityId = 'MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM'

describe('Chat-media block format (suite 2) through Rust/WASM', () => {
  it('round-trips empty, ordinary and multi-block attachments', async () => {
    const key = new Uint8Array(32).fill(0x42)
    for (const plaintext of [new Uint8Array(), new TextEncoder().encode('photo bytes'), new Uint8Array(4 * 1024 * 1024 + 5).fill(7)]) {
      const sealed = await sealChatMedia(plaintext, key, attachmentId)
      expect(sealed.bytes.length).toBe(await chatMediaObjectLength(plaintext.length))
      expect(new TextDecoder().decode(sealed.bytes.subarray(0, 8))).toBe('KUTPCM2\0')
      expect(sealed.manifestSha256).toMatch(/^[A-Za-z0-9+/]{43}=$/)
      expect(await openChatMedia(sealed.bytes, key, attachmentId, sealed.manifestSha256)).toEqual(plaintext)
    }
  })

  it('refuses another key, attachment, manifest digest, a tampered block, truncation and trailing data', async () => {
    const key = new Uint8Array(32).fill(0x42)
    const { bytes, manifestSha256 } = await sealChatMedia(new TextEncoder().encode('opaque'), key, attachmentId)
    await expect(openChatMedia(bytes, new Uint8Array(32).fill(0x43), attachmentId, manifestSha256)).rejects.toThrow()
    await expect(openChatMedia(bytes, key, '33333333-3333-4333-8333-333333333333', manifestSha256)).rejects.toThrow()
    // Another attachment sealed under the same id and key: not the one the descriptor names.
    const other = await sealChatMedia(new TextEncoder().encode('other'), key, attachmentId)
    await expect(openChatMedia(other.bytes, key, attachmentId, manifestSha256)).rejects.toThrow()
    const tampered = bytes.slice()
    tampered[40] ^= 1
    await expect(openChatMedia(tampered, key, attachmentId, manifestSha256)).rejects.toThrow()
    await expect(openChatMedia(bytes.subarray(0, -1), key, attachmentId, manifestSha256)).rejects.toThrow()
    const trailing = new Uint8Array(bytes.length + 1)
    trailing.set(bytes)
    await expect(openChatMedia(trailing, key, attachmentId, manifestSha256)).rejects.toThrow()
  })
})

describe('Chat attachment ledger Rust/WASM envelope', () => {
  it('is an account record of its account and entity, at its revision', async () => {
    const key = { masterKeys: firstMasterKeys(new Uint8Array(32).fill(0x33)), binding: '0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b' }
    const plaintext = new TextEncoder().encode('canonical entry')
    const envelope = await sealChatAttachmentLedger(plaintext, key, entityId, 2)
    expect(await openChatAttachmentLedger(envelope, key, entityId)).toEqual({ plaintext, revision: 2 })
    await expect(openChatAttachmentLedger(envelope, key, otherEntityId)).rejects.toThrow()
    // Not an id of the scope's form.
    await expect(sealChatAttachmentLedger(plaintext, key, '22222222-2222-4222-8222-222222222222', 1)).rejects.toThrow()
    // Another account's key binding, or another master key: refused.
    await expect(openChatAttachmentLedger(envelope, { ...key, binding: '7d3f1a2b-9c4e-4f6a-8b1d-2e5c7a9f0b3d' }, entityId)).rejects.toThrow()
    await expect(openChatAttachmentLedger(envelope, { ...key, masterKeys: firstMasterKeys(new Uint8Array(32).fill(0x34)) }, entityId)).rejects.toThrow()
  })

  it('uses the strict Rust canonical codec for private accounting entries', async () => {
    const entry = {
      version: 1,
      conversationKind: 'direct',
      conversationReference: 'aci:00000000-0000-4000-8000-000000000002@example.test',
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
    // A direct conversation is an account, never an address.
    for (const conversationReference of ['bob@example.test', 'aci:00000000-0000-4000-8000-000000000002@Example.test']) {
      await expect(encodeChatAttachmentLedgerEntry({ ...entry, conversationReference })).rejects.toThrow()
    }
  })
})
