// Browser adapter for Chat attachments in the block format
// (docs/chat-media.md, docs/plans/drive-block-format.md §2): Chat-media
// suite 2, `KUTPCM2`. Every block is sealed and opened in Rust
// (`kutup-crypto` chat_media_blocks.rs through `kutup-crypto-wasm`); the
// manifest is unsigned because the E2EE descriptor commits to its SHA-256.
// The ledger envelopes below are Rust-owned account records.

import type { MasterKeys } from './masterKeys'
import { fromBase64, toBase64 } from './base64'
import { getCryptoWasm, type WasmBlockEncryptor, type WasmBlockReader } from './rustWasm'

/** The Chat-media suite every new attachment is sealed under. */
export const CHAT_MEDIA_SUITE = 2
export const MAX_CHAT_MEDIA_PLAINTEXT_BYTES = 2 * 1024 * 1024 * 1024

function checkSize(plaintextBytes: number): void {
  if (!Number.isSafeInteger(plaintextBytes) || plaintextBytes < 0 || plaintextBytes > MAX_CHAT_MEDIA_PLAINTEXT_BYTES) {
    throw new Error('Chat-media plaintext length is outside the attachment limit')
  }
}

/** Where everything sits in a Chat attachment: the header, the 4 MiB blocks and the trailer. */
export async function chatMediaLayout(): Promise<{ headerBytes: number; blockSize: number; blockOverhead: number; trailerBytes: number }> {
  return (await getCryptoWasm()).blockLayout('chatMedia')
}

/**
 * A block encryptor for one attachment of `size` plaintext bytes: its
 * `header()` first, then `sealNext` for each block in order, then `finish()`
 * (the sealed manifest and trailer), after which `manifestSha256` is what
 * the descriptor carries. The caller frees it.
 */
export async function newChatMediaBlockEncryptor(attachmentKey: Uint8Array, attachmentId: string, size: number): Promise<WasmBlockEncryptor> {
  checkSize(size)
  return (await getCryptoWasm()).chatMediaBlockEncryptor(toBase64(attachmentKey), attachmentId, size)
}

/** The sealed object's length for `size` plaintext bytes. */
export async function chatMediaObjectLength(size: number): Promise<number> {
  const encryptor = await newChatMediaBlockEncryptor(new Uint8Array(32), '00000000-0000-4000-8000-000000000000', size)
  try {
    return encryptor.objectLength
  } finally {
    encryptor.free()
  }
}

/**
 * A reader of one attachment: the header must name it and the sealed
 * manifest must be the one the descriptor commits to (`manifestSha256`,
 * canonical base64). Blocks open by index, each checked against the
 * manifest's hash first. The caller frees it.
 */
export async function openChatMediaReader(
  attachmentKey: Uint8Array,
  attachmentId: string,
  manifestSha256: string,
  header: Uint8Array,
  sealedManifest: Uint8Array,
): Promise<WasmBlockReader> {
  return (await getCryptoWasm()).chatMediaBlockReader(toBase64(attachmentKey), attachmentId, manifestSha256, header, sealedManifest)
}

/** A whole attachment sealed at once, with the manifest digest its descriptor carries. */
export async function sealChatMedia(
  plaintext: Uint8Array,
  attachmentKey: Uint8Array,
  attachmentId: string,
): Promise<{ bytes: Uint8Array; manifestSha256: string }> {
  const encryptor = await newChatMediaBlockEncryptor(attachmentKey, attachmentId, plaintext.length)
  try {
    const parts: Uint8Array[] = [encryptor.header()]
    let at = 0
    for (let index = 0; index < encryptor.blockCount; index++) {
      const length = encryptor.blockLength(index)
      parts.push(encryptor.sealNext(plaintext.subarray(at, at + length)))
      at += length
    }
    parts.push(encryptor.finish())
    const bytes = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0))
    let offset = 0
    for (const part of parts) {
      bytes.set(part, offset)
      offset += part.length
    }
    return { bytes, manifestSha256: encryptor.manifestSha256! }
  } finally {
    encryptor.free()
  }
}

/** Opens a whole attachment whose sealed manifest has the descriptor's digest. */
export async function openChatMedia(
  object: Uint8Array,
  attachmentKey: Uint8Array,
  attachmentId: string,
  manifestSha256: string,
): Promise<Uint8Array> {
  const module = await getCryptoWasm()
  const layout = module.blockLayout('chatMedia')
  if (object.length < layout.headerBytes + layout.trailerBytes) throw new Error('Chat-media object is truncated')
  const manifestLength = module.blockTrailerManifestLength('chatMedia', object.subarray(object.length - layout.trailerBytes))
  const manifestStart = object.length - layout.trailerBytes - manifestLength
  if (manifestStart < layout.headerBytes) throw new Error('Chat-media manifest does not fit the object')
  const reader = await openChatMediaReader(
    attachmentKey,
    attachmentId,
    manifestSha256,
    object.subarray(0, layout.headerBytes),
    object.subarray(manifestStart, object.length - layout.trailerBytes),
  )
  try {
    if (reader.objectLength !== object.length) throw new Error('Chat-media object length is not its manifest\'s')
    const out = new Uint8Array(reader.size)
    let at = 0
    for (let index = 0; index < reader.blockCount; index++) {
      const start = reader.blockOffset(index)
      const plain = reader.openBlock(index, object.subarray(start, start + reader.sealedBlockLength(index)))
      out.set(plain, at)
      at += plain.length
    }
    return out
  } finally {
    reader.free()
  }
}

/**
 * Whose ledger: the account's master key and its key binding
 * (`session.envelopeBinding`); each record is an account record of that
 * account (docs/chat-media.md).
 */
export interface ChatAttachmentLedgerOwner {
  /** The account's master keys (`session.masterKeys`). */
  masterKeys: MasterKeys
  binding: string
}

/**
 * Seal one ledger entity's record (the account-records `chatAttachments`
 * scope; `entityId` is its random record id) as `revision`.
 */
export async function sealChatAttachmentLedger(
  plaintext: Uint8Array,
  owner: ChatAttachmentLedgerOwner,
  entityId: string,
  revision: number,
): Promise<string> {
  return (await getCryptoWasm()).sealChatAttachmentLedger(
    toBase64(plaintext),
    owner.masterKeys,
    owner.binding,
    entityId,
    revision,
  )
}

/** Open the record `entityId`: its plaintext and the revision it was sealed at. */
export async function openChatAttachmentLedger(
  envelope: string,
  owner: ChatAttachmentLedgerOwner,
  entityId: string,
): Promise<{ plaintext: Uint8Array; revision: number }> {
  const opened = (await getCryptoWasm()).openChatAttachmentLedger(
    envelope,
    owner.masterKeys,
    owner.binding,
    entityId,
  )
  return { plaintext: fromBase64(opened.plaintext), revision: opened.revision }
}

export async function encodeChatAttachmentLedgerEntry(entry: unknown): Promise<Uint8Array> {
  return fromBase64((await getCryptoWasm()).encodeChatAttachmentLedgerEntry(entry))
}

export async function decodeChatAttachmentLedgerEntry<T>(plaintext: Uint8Array): Promise<T> {
  return (await getCryptoWasm()).decodeChatAttachmentLedgerEntry(toBase64(plaintext)) as T
}
