// Browser adapter for the canonical Rust Chat-media headers, derivations, and
// ledger envelopes. The existing bounded libsodium secretstream adapter owns
// only incremental I/O; it does not select suites or construct persistent AAD.

import { fromBase64, toBase64 } from './base64'
import { getCryptoWasm } from './rustWasm'
import {
  ABYTES,
  HEADER_BYTES as SECRETSTREAM_HEADER_BYTES,
  PLAIN_CHUNK,
  newStreamEncryptor,
  type StreamEncryptor,
} from './streamEncryptor'
import { newStreamDecryptor, type StreamDecryptor } from './streamDecryptor'

export const CHAT_MEDIA_SUITE_V1 = 1
export const CHAT_MEDIA_OBJECT_HEADER_BYTES = 28
export const CHAT_MEDIA_OBJECT_PREFIX_BYTES =
  CHAT_MEDIA_OBJECT_HEADER_BYTES + SECRETSTREAM_HEADER_BYTES
export const CHAT_MEDIA_CIPHER_CHUNK_BYTES = PLAIN_CHUNK + ABYTES
export const MAX_CHAT_MEDIA_PLAINTEXT_BYTES = 2 * 1024 * 1024 * 1024

export interface ChatMediaStreamEncryptorV1 {
  readonly prefix: Uint8Array
  push(plain: Uint8Array, isLast: boolean): Uint8Array
}

export function chatMediaCipherSize(plaintextBytes: number): number {
  if (!Number.isSafeInteger(plaintextBytes) || plaintextBytes < 0 ||
      plaintextBytes > MAX_CHAT_MEDIA_PLAINTEXT_BYTES) {
    throw new Error('Chat-media plaintext length is outside V1')
  }
  const chunks = Math.max(1, Math.ceil(plaintextBytes / PLAIN_CHUNK))
  return CHAT_MEDIA_OBJECT_PREFIX_BYTES + plaintextBytes + ABYTES * chunks
}

async function prepare(
  attachmentKey: Uint8Array,
  attachmentId: string,
): Promise<{ objectHeader: Uint8Array; streamKey: Uint8Array }> {
  const module = await getCryptoWasm()
  const prepared = module.prepareChatMediaObject(toBase64(attachmentKey), attachmentId)
  const objectHeader = fromBase64(prepared.objectHeader)
  const streamKey = fromBase64(prepared.streamKey)
  if (objectHeader.length !== CHAT_MEDIA_OBJECT_HEADER_BYTES || streamKey.length !== 32) {
    throw new Error('Rust returned malformed Chat-media material')
  }
  return { objectHeader, streamKey }
}

export async function newChatMediaStreamEncryptorV1(
  attachmentKey: Uint8Array,
  attachmentId: string,
): Promise<ChatMediaStreamEncryptorV1> {
  const { objectHeader, streamKey } = await prepare(attachmentKey, attachmentId)
  const encryptor: StreamEncryptor = await newStreamEncryptor(streamKey, objectHeader)
  const prefix = new Uint8Array(CHAT_MEDIA_OBJECT_PREFIX_BYTES)
  prefix.set(objectHeader)
  prefix.set(encryptor.header, CHAT_MEDIA_OBJECT_HEADER_BYTES)
  return { prefix, push: encryptor.push }
}

export async function openChatMediaStreamV1(
  prefix: Uint8Array,
  attachmentKey: Uint8Array,
  expectedAttachmentId: string,
): Promise<StreamDecryptor> {
  if (prefix.length !== CHAT_MEDIA_OBJECT_PREFIX_BYTES) {
    throw new Error(`Chat-media prefix must be ${CHAT_MEDIA_OBJECT_PREFIX_BYTES} bytes`)
  }
  const objectHeader = prefix.subarray(0, CHAT_MEDIA_OBJECT_HEADER_BYTES)
  const streamHeader = prefix.subarray(CHAT_MEDIA_OBJECT_HEADER_BYTES)
  const module = await getCryptoWasm()
  const streamKey = fromBase64(module.openChatMediaObjectHeader(
    toBase64(objectHeader),
    toBase64(attachmentKey),
    expectedAttachmentId,
  ))
  return newStreamDecryptor(streamKey, streamHeader, objectHeader)
}

export async function encryptChatMediaV1(
  plaintext: Uint8Array,
  attachmentKey: Uint8Array,
  attachmentId: string,
): Promise<Uint8Array> {
  chatMediaCipherSize(plaintext.length)
  const encryptor = await newChatMediaStreamEncryptorV1(attachmentKey, attachmentId)
  const frames: Uint8Array[] = [encryptor.prefix]
  if (plaintext.length === 0) {
    frames.push(encryptor.push(new Uint8Array(), true))
  } else {
    for (let offset = 0; offset < plaintext.length; offset += PLAIN_CHUNK) {
      const end = Math.min(offset + PLAIN_CHUNK, plaintext.length)
      frames.push(encryptor.push(plaintext.subarray(offset, end), end === plaintext.length))
    }
  }
  const output = new Uint8Array(frames.reduce((sum, frame) => sum + frame.length, 0))
  let offset = 0
  for (const frame of frames) {
    output.set(frame, offset)
    offset += frame.length
  }
  return output
}

export async function decryptChatMediaV1(
  ciphertext: Uint8Array,
  attachmentKey: Uint8Array,
  expectedAttachmentId: string,
): Promise<Uint8Array> {
  if (ciphertext.length < CHAT_MEDIA_OBJECT_PREFIX_BYTES + ABYTES) {
    throw new Error('Chat-media object is truncated')
  }
  const decryptor = await openChatMediaStreamV1(
    ciphertext.subarray(0, CHAT_MEDIA_OBJECT_PREFIX_BYTES),
    attachmentKey,
    expectedAttachmentId,
  )
  const chunks: Uint8Array[] = []
  let offset = CHAT_MEDIA_OBJECT_PREFIX_BYTES
  let sawFinal = false
  while (offset < ciphertext.length) {
    const end = Math.min(offset + CHAT_MEDIA_CIPHER_CHUNK_BYTES, ciphertext.length)
    const result = decryptor.pull(ciphertext.subarray(offset, end))
    chunks.push(result.plain)
    offset = end
    if (result.isFinal) {
      sawFinal = true
      if (offset !== ciphertext.length) throw new Error('Chat-media has bytes after FINAL')
    } else if (offset === ciphertext.length) {
      throw new Error('Chat-media ended before FINAL')
    }
  }
  if (!sawFinal) throw new Error('Chat-media has no FINAL frame')
  const output = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.length, 0))
  let plainOffset = 0
  for (const chunk of chunks) {
    output.set(chunk, plainOffset)
    plainOffset += chunk.length
  }
  return output
}

export async function deriveChatAttachmentLedgerKey(masterKey: Uint8Array): Promise<Uint8Array> {
  return fromBase64((await getCryptoWasm()).deriveChatAttachmentLedgerKey(toBase64(masterKey)))
}

export interface ChatAttachmentLedgerContextV1 {
  accountIncarnationId: string
  entityId: string
  revision: bigint
  previousEnvelopeDigest?: string
}

export async function sealChatAttachmentLedger(
  plaintext: Uint8Array,
  ledgerKey: Uint8Array,
  context: ChatAttachmentLedgerContextV1,
): Promise<string> {
  return (await getCryptoWasm()).sealChatAttachmentLedger(
    toBase64(plaintext),
    toBase64(ledgerKey),
    context.accountIncarnationId,
    context.entityId,
    context.revision,
    context.previousEnvelopeDigest ?? '',
  )
}

export async function openChatAttachmentLedger(
  envelope: string,
  ledgerKey: Uint8Array,
  expected: ChatAttachmentLedgerContextV1,
): Promise<Uint8Array> {
  return fromBase64((await getCryptoWasm()).openChatAttachmentLedger(
    envelope,
    toBase64(ledgerKey),
    expected.accountIncarnationId,
    expected.entityId,
    expected.revision,
    expected.previousEnvelopeDigest ?? '',
  ))
}

export async function chatAttachmentLedgerEnvelopeDigest(envelope: string): Promise<string> {
  return (await getCryptoWasm()).chatAttachmentLedgerEnvelopeDigest(envelope)
}

export interface ChatAttachmentLedgerHeaderV1 {
  suite: number
  accountIncarnationId: string
  entityId: string
  revision: string
  previousEnvelopeDigest: string
}

export async function inspectChatAttachmentLedgerEnvelope(
  envelope: string,
): Promise<ChatAttachmentLedgerHeaderV1> {
  return (await getCryptoWasm()).inspectChatAttachmentLedgerEnvelope(envelope)
}

export async function encodeChatAttachmentLedgerEntry(entry: unknown): Promise<Uint8Array> {
  return fromBase64((await getCryptoWasm()).encodeChatAttachmentLedgerEntry(entry))
}

export async function decodeChatAttachmentLedgerEntry<T>(plaintext: Uint8Array): Promise<T> {
  return (await getCryptoWasm()).decodeChatAttachmentLedgerEntry(toBase64(plaintext)) as T
}
