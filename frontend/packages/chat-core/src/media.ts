// Browser orchestration for immutable E2EE Chat-media objects in the block
// format (docs/chat-media.md; docs/plans/drive-block-format.md §2): Chat-media
// suite 2, `KUTPCM2`. Headers, keys, blocks and the manifest are Rust-owned;
// this adapter only provides bounded browser File/ReadableStream I/O, tus
// mechanics and the block reader's ranged reads.

import * as tus from 'tus-js-client'
import {
  CHAT_MEDIA_SUITE,
  MAX_CHAT_MEDIA_PLAINTEXT_BYTES,
  chatMediaLayout,
  newChatMediaBlockEncryptor,
  openChatMediaReader,
} from '@kutup/crypto/chatMedia'
import { toBase64 } from '@kutup/crypto/base64'
import { exactBytes } from '@kutup/crypto/bytes'
import { createHasher, toHex } from '@kutup/crypto/hash'
import { randomBytes } from '@kutup/crypto/random'
import { resolveApiBase } from '@kutup/session/apiBase'
import { freshAccessToken } from '@kutup/session/client'
import { openBlockReader, type AccessToken } from '@kutup/files/blockReader/client'
import type { ChatMediaBlockSource } from '@kutup/files/blockReader/protocol'
import { openDownloadSink } from '@kutup/files/download/streamDownload'
import { driveStreamLimits } from '@kutup/files/stream/limits'
import { openPlayerStream } from '@kutup/files/stream/page'
import { openMediaPlayback, type Playback } from '@kutup/files/stream/playback'
import {
  CiphertextCacheRequestCoordinatorV1,
  type CiphertextCacheBindingV1,
  type CiphertextCacheLifecycleV1,
  type PrivateCiphertextCacheV1,
} from '@kutup/files/mediaCache'
import {
  CHAT_PREVIEW_GENERATION_LIMITS_V1,
  CHAT_PREVIEW_PROFILE_V1,
  classifyFileForKutup,
  generatePreviewPayloadV1,
  inspectRasterDimensions,
  type PreviewGenerationResultV1,
} from '@kutup/files/mediaPreview'
import api from '@kutup/session/client'
import { accountKey, type AccountRef } from './identity'
import type { ChatAttachmentDescriptorV1, ChatMediaClassV1 } from './types'
import { encodeChatMediaPreviewV1 } from './media-preview'
import { hash } from '@kutup/crypto/hash'

const SHA256_HEX_BYTES = 64
/** The block format's plaintext block and per-block overhead (`blocks.rs`). */
const CHAT_MEDIA_BLOCK_BYTES = 4 * 1024 * 1024
const CHAT_MEDIA_BLOCK_OVERHEAD = 40
const chatMediaCacheRequestsV1 = new CiphertextCacheRequestCoordinatorV1()

export interface UploadChatMediaOptions {
  file: File
  originDomain: string
  accessToken: string
  mediaClass?: ChatMediaClassV1
  caption?: string
  width?: number
  height?: number
  durationMs?: number
  /**
   * Leave the thumbnail out (view-once media: the picture must not stay
   * visible in the message).
   */
  withoutPreview?: boolean
  onProgress?: (plainSent: number, plainTotal: number) => void
  signal?: AbortSignal
}

export interface UploadedChatMediaV1 {
  descriptor: ChatAttachmentDescriptorV1
  storageReferenceId: string
}

export function chatMediaPresentationV1(
  options: Pick<UploadChatMediaOptions, 'file' | 'mediaClass' | 'caption' | 'width' | 'height' | 'durationMs'>,
  generatedPreview: PreviewGenerationResultV1 | null,
): Pick<
  ChatAttachmentDescriptorV1,
  'filename' | 'mimeType' | 'mediaClass' | 'caption' | 'width' | 'height' | 'durationMs' | 'preview'
> {
  const generatedWidth = generatedPreview?.mediaMetadata?.width
  const generatedHeight = generatedPreview?.mediaMetadata?.height
  const width = options.width ?? generatedWidth
  const height = options.height ?? generatedHeight
  const durationMs = options.durationMs ?? generatedPreview?.mediaMetadata?.durationMs
  return {
    filename: options.file.name,
    mimeType: options.file.type || 'application/octet-stream',
    mediaClass: options.mediaClass ?? inferMediaClass(options.file.type),
    ...(options.caption ? { caption: options.caption } : {}),
    ...(width && height ? { width, height } : {}),
    ...(durationMs ? { durationMs } : {}),
    ...(generatedPreview?.payload
      ? { preview: encodeChatMediaPreviewV1(generatedPreview.payload) }
      : {}),
  }
}

export type ChatMediaDeliveryStatusV1 =
  | 'stored'
  | 'already_stored'
  | 'queued'
  | 'storage_full'

export interface ChatMediaDeliveryResponseV1 {
  operationId: string
  status: ChatMediaDeliveryStatusV1
  storageReferenceId?: string
}

/**
 * Admit one already-accepted recipient through the sender's own homeserver.
 * Remote destinations are resolved only by the signed federation transport;
 * the browser never supplies or learns a remote URL.
 */
export async function deliverChatMediaV1(
  descriptor: ChatAttachmentDescriptorV1,
  recipient: AccountRef,
  deliveryCapability: string,
  operationId?: string,
): Promise<ChatMediaDeliveryResponseV1> {
  operationId ??= await chatMediaDeliveryOperationId(
    descriptor.attachmentId,
    accountKey(recipient),
  )
  const response = await api.post<ChatMediaDeliveryResponseV1>('/chat/media/deliveries', {
    version: 1,
    originDomain: descriptor.originDomain,
    destinationDomain: recipient.server,
    recipient,
    operationId,
    attachmentId: descriptor.attachmentId,
    suite: descriptor.suite,
    ciphertextBytes: descriptor.ciphertextBytes,
    ciphertextSha256: descriptor.ciphertextSha256,
    retrievalToken: descriptor.retrievalToken,
    deliveryCapability,
    expiresAt: Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60,
  })
  if (response.data.operationId !== operationId) {
    throw new Error('Chat-media delivery response changed its operation id')
  }
  return response.data
}

/**
 * Encrypt and upload one immutable attachment without materialising the file.
 * The descriptor is released only after the browser and homeserver SHA-256
 * values agree exactly.
 */
export async function uploadChatMediaV1(
  options: UploadChatMediaOptions,
): Promise<UploadedChatMediaV1> {
  if (!Number.isSafeInteger(options.file.size) || options.file.size < 0 ||
      options.file.size > MAX_CHAT_MEDIA_PLAINTEXT_BYTES) {
    throw new Error('Chat attachment exceeds the V1 2 GiB plaintext limit')
  }
  // Preview failure is deliberately non-fatal. The generator returns a
  // generic-card result for unsupported or hostile input and throws only for
  // caller cancellation or invalid programmer-supplied limits.
  const previewPromise = options.withoutPreview
    ? Promise.resolve(null)
    : generatePreviewPayloadV1(
        options.file,
        CHAT_PREVIEW_PROFILE_V1,
        CHAT_PREVIEW_GENERATION_LIMITS_V1,
        options.signal,
      ).catch(() => null)
  const attachmentId = crypto.randomUUID()
  const attachmentKey = randomBytes(32)
  const retrievalToken = randomBytes(32)
  // Sealed block by block in Rust; the manifest's digest is known once the
  // last block is, and goes into the descriptor.
  const encryptor = await newChatMediaBlockEncryptor(attachmentKey, attachmentId, options.file.size)
  const ciphertextBytes = encryptor.objectLength
  const headerBytes = encryptor.header().length
  const blockCount = encryptor.blockCount
  let manifestSha256 = ''
  let encryptorFreed = false
  const freeEncryptor = () => {
    if (encryptorFreed) return
    encryptorFreed = true
    encryptor.free()
  }
  const hasher = await createHasher()
  let hashFinalized = false
  let nextBlock = -1
  let position = 0

  const hashAndEnqueue = (
    controller: ReadableStreamDefaultController<Uint8Array>,
    bytes: Uint8Array,
  ) => {
    hasher.update(bytes)
    controller.enqueue(bytes)
  }
  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (nextBlock < 0) {
        nextBlock = 0
        hashAndEnqueue(controller, encryptor.header())
        return
      }
      if (nextBlock < blockCount) {
        const length = encryptor.blockLength(nextBlock)
        const plain = new Uint8Array(await options.file.slice(position, position + length).arrayBuffer())
        if (plain.length !== length) throw new Error('the file changed while it was read')
        hashAndEnqueue(controller, encryptor.sealNext(plain))
        position += length
        nextBlock++
        return
      }
      hashAndEnqueue(controller, encryptor.finish())
      manifestSha256 = encryptor.manifestSha256 ?? ''
      freeEncryptor()
      controller.close()
    },
    cancel() {
      freeEncryptor()
    },
  })

  const endpoint = `${await resolveApiBase()}/chat/media/uploads`
  return new Promise<UploadedChatMediaV1>((resolve, reject) => {
    let createdAttachmentId = ''
    let serverDigest = ''
    let storageReferenceId = ''
    let lastPlainSent = 0
    let settled = false
    const fail = (error: unknown) => {
      if (settled) return
      settled = true
      reject(error)
    }
    const upload = new tus.Upload(stream.getReader(), {
      endpoint,
      uploadSize: ciphertextBytes,
      // Two sealed blocks a PATCH: above the server's 5 MiB part minimum.
      chunkSize: 2 * (CHAT_MEDIA_BLOCK_BYTES + CHAT_MEDIA_BLOCK_OVERHEAD),
      retryDelays: [0, 1000, 3000, 5000, 10000],
      storeFingerprintForResuming: false,
      removeFingerprintOnSuccess: true,
      headers: { Authorization: `Bearer ${options.accessToken}` },
      metadata: {
        attachmentId,
        suite: String(CHAT_MEDIA_SUITE),
        retrievalToken: toBase64(retrievalToken),
      },
      onAfterResponse(request, response) {
        if (request.getMethod() === 'POST' && response.getStatus() === 201) {
          try {
            const body = JSON.parse(response.getBody()) as { attachmentId?: string }
            createdAttachmentId = body.attachmentId ?? ''
          } catch {
            // Reported as a protocol failure from onSuccess.
          }
        }
        if (request.getMethod() === 'PATCH' && response.getStatus() === 204) {
          serverDigest = response.getHeader('X-Kutup-Ciphertext-Sha256') ?? serverDigest
          storageReferenceId =
            response.getHeader('X-Kutup-Storage-Reference-Id') ?? storageReferenceId
        }
      },
      onChunkComplete(_chunkSize, bytesAccepted) {
        const blocks = Math.floor(Math.max(0, bytesAccepted - headerBytes) / (CHAT_MEDIA_BLOCK_BYTES + CHAT_MEDIA_BLOCK_OVERHEAD))
        const plain = Math.min(options.file.size, blocks * CHAT_MEDIA_BLOCK_BYTES)
        if (plain > lastPlainSent) {
          lastPlainSent = plain
          options.onProgress?.(plain, options.file.size)
        }
      },
      onError(error) {
        freeEncryptor()
        fail(error)
      },
      onSuccess() {
        void finalizeSuccess().catch(fail)
      },
    })

    async function finalizeSuccess() {
      if (settled) return
      if (createdAttachmentId !== attachmentId || !storageReferenceId ||
          serverDigest.length !== SHA256_HEX_BYTES || !manifestSha256) {
        fail(new Error('Chat-media server returned incomplete finalization evidence'))
        return
      }
      let localDigest: string
      try {
        if (hashFinalized) throw new Error('Chat-media hash was finalized twice')
        hashFinalized = true
        localDigest = toHex(hasher.digest())
      } catch (error) {
        fail(error)
        return
      }
      if (localDigest !== serverDigest) {
        // The object was finalized but no E2EE descriptor or delivery grant
        // exists yet, so the origin can safely release its only reference.
        void api.delete(`/chat/media/objects/${encodeURIComponent(attachmentId)}`)
          .catch(() => undefined)
          .finally(() => {
            fail(new Error('Chat-media ciphertext digest differs from the homeserver'))
          })
        return
      }
      const generatedPreview = await previewPromise
      if (settled) return
      options.onProgress?.(options.file.size, options.file.size)
      settled = true
      resolve({
        storageReferenceId,
        descriptor: {
            version: 1,
            suite: CHAT_MEDIA_SUITE,
            attachmentId,
            originDomain: options.originDomain,
            retrievalToken: toBase64(retrievalToken),
            ciphertextBytes,
            ciphertextSha256: localDigest,
            manifestSha256,
            attachmentKey: toBase64(attachmentKey),
            plaintextBytes: options.file.size,
            ...chatMediaPresentationV1(options, generatedPreview),
        },
      })
    }

    if (options.signal) {
      if (options.signal.aborted) {
        freeEncryptor()
        void upload.abort(true).catch(() => {})
        fail(new DOMException('Upload aborted', 'AbortError'))
        return
      }
      options.signal.addEventListener('abort', () => {
        freeEncryptor()
        void upload.abort(true).catch(() => {})
        fail(new DOMException('Upload aborted', 'AbortError'))
      }, { once: true })
    }
    upload.start()
  })
}

export interface ChatMediaPlainChunk {
  plain: Uint8Array
  isFinal: boolean
}

export function chatMediaCacheBindingV1(
  descriptor: ChatAttachmentDescriptorV1,
): CiphertextCacheBindingV1 {
  return {
    product: 'chat',
    suite: descriptor.suite,
    objectId: descriptor.attachmentId,
    ciphertextBytes: descriptor.ciphertextBytes,
    ciphertextSha256: descriptor.ciphertextSha256,
  }
}

async function chatMediaObjectUrl(attachmentId: string): Promise<string> {
  return `${await resolveApiBase()}/chat/media/objects/${encodeURIComponent(attachmentId)}`
}

/** The block reader's source for an attachment on the account's own server. */
export async function chatMediaBlockSourceV1(descriptor: ChatAttachmentDescriptorV1): Promise<ChatMediaBlockSource> {
  return {
    family: 'chatMedia',
    url: await chatMediaObjectUrl(descriptor.attachmentId),
    attachmentKey: fromBase6432(descriptor.attachmentKey),
    attachmentId: descriptor.attachmentId,
    manifestSha256: descriptor.manifestSha256,
    size: descriptor.plaintextBytes,
    objectLength: descriptor.ciphertextBytes,
  }
}

async function* fetchChatMediaCiphertextV1(
  descriptor: ChatAttachmentDescriptorV1,
  accessToken: string,
  signal?: AbortSignal,
  onProgress?: (receivedBytes: number, totalBytes: number) => void,
): AsyncGenerator<Uint8Array, void, void> {
  const response = await fetch(await chatMediaObjectUrl(descriptor.attachmentId), {
    headers: { Authorization: `Bearer ${accessToken}` },
    signal,
  })
  if (!response.ok) throw new Error(`Chat-media download HTTP ${response.status}`)
  if (!response.body) throw new Error('Chat-media download has no response body')
  const reader = response.body.getReader()
  let receivedBytes = 0
  try {
    for (;;) {
      const { value, done } = await reader.read()
      if (done) break
      if (!value?.length) continue
      receivedBytes += value.length
      if (receivedBytes > descriptor.ciphertextBytes) {
        throw new Error('Chat-media object exceeds its authenticated length')
      }
      onProgress?.(receivedBytes, descriptor.ciphertextBytes)
      yield value
    }
    if (receivedBytes !== descriptor.ciphertextBytes) {
      throw new Error('Chat-media object differs from its authenticated length')
    }
  } finally {
    reader.releaseLock()
  }
}

interface ChatMediaLayoutV1 {
  headerBytes: number
  blockCount: number
  /** Where the sealed manifest starts and ends (the trailer follows). */
  manifestStart: number
  manifestEnd: number
}

/** Where an attachment's parts sit, from its descriptor's lengths. */
async function layoutOf(descriptor: ChatAttachmentDescriptorV1): Promise<ChatMediaLayoutV1> {
  if (descriptor.suite !== CHAT_MEDIA_SUITE) throw new Error('unknown Chat-media suite')
  const layout = await chatMediaLayout()
  const size = descriptor.plaintextBytes
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX_CHAT_MEDIA_PLAINTEXT_BYTES) {
    throw new Error('Chat-media plaintext length is invalid')
  }
  const blockCount = Math.max(1, Math.ceil(size / layout.blockSize))
  const manifestStart = layout.headerBytes + size + blockCount * layout.blockOverhead
  const manifestEnd = descriptor.ciphertextBytes - layout.trailerBytes
  if (manifestEnd <= manifestStart) throw new Error('Chat-media lengths do not fit the block format')
  return { headerBytes: layout.headerBytes, blockCount, manifestStart, manifestEnd }
}

/**
 * Reads an attachment's ciphertext through once, as it arrives: its exact
 * length and whole-object digest against the descriptor, and its header
 * and sealed manifest, opened in Rust against the descriptor's manifest
 * digest. Nothing is decrypted. Returns the header and manifest.
 */
async function authenticateCiphertext(
  ciphertext: AsyncIterable<Uint8Array>,
  descriptor: ChatAttachmentDescriptorV1,
  signal?: AbortSignal,
): Promise<{ header: Uint8Array; manifest: Uint8Array }> {
  const layout = await layoutOf(descriptor)
  const digest = await createHasher()
  const header = new Uint8Array(layout.headerBytes)
  const manifest = new Uint8Array(layout.manifestEnd - layout.manifestStart)
  let read = 0
  for await (const chunk of ciphertext) {
    throwIfAborted(signal)
    if (!chunk.length) continue
    const start = read
    read += chunk.length
    if (read > descriptor.ciphertextBytes) throw new Error('Chat-media object exceeds its authenticated length')
    digest.update(chunk)
    copyOverlap(chunk, start, header, 0)
    copyOverlap(chunk, start, manifest, layout.manifestStart)
  }
  throwIfAborted(signal)
  if (read !== descriptor.ciphertextBytes || toHex(digest.digest()) !== descriptor.ciphertextSha256) {
    throw new Error('Chat-media object differs from its authenticated descriptor')
  }
  const reader = await openChatMediaReader(fromBase6432(descriptor.attachmentKey), descriptor.attachmentId, descriptor.manifestSha256, header, manifest)
  try {
    if (reader.size !== descriptor.plaintextBytes || reader.objectLength !== descriptor.ciphertextBytes) {
      throw new Error('Chat-media manifest differs from its authenticated descriptor')
    }
  } finally {
    reader.free()
  }
  return { header, manifest }
}

/** Copies the part of `chunk` (at `chunkStart` in the object) that falls in `target` (at `targetStart`). */
function copyOverlap(chunk: Uint8Array, chunkStart: number, target: Uint8Array, targetStart: number): void {
  const from = Math.max(chunkStart, targetStart)
  const to = Math.min(chunkStart + chunk.length, targetStart + target.length)
  if (from < to) target.set(chunk.subarray(from - chunkStart, to - chunkStart), from - targetStart)
}

/**
 * Authenticates an attachment's ciphertext without decrypting it: what the
 * private cache checks before it keeps a download (its length, its digest,
 * its header and the manifest the descriptor commits to).
 */
export async function verifyChatMediaCiphertextV1(
  ciphertext: AsyncIterable<Uint8Array>,
  descriptor: ChatAttachmentDescriptorV1,
  signal?: AbortSignal,
): Promise<void> {
  await authenticateCiphertext(ciphertext, descriptor, signal)
}

/**
 * Decrypts an attachment whose ciphertext can be read more than once
 * (`ciphertext()`, from the private cache): the first read authenticates it
 * and finds its manifest, which sits at the end; the second opens each
 * block in order, its hash checked against the manifest before its AEAD.
 * No plaintext leaves before the manifest is the descriptor's.
 */
export async function* decryptChatMediaCiphertextV1(
  ciphertext: () => AsyncIterable<Uint8Array>,
  descriptor: ChatAttachmentDescriptorV1,
  signal?: AbortSignal,
): AsyncGenerator<ChatMediaPlainChunk, void, void> {
  const layout = await layoutOf(descriptor)
  const { header, manifest } = await authenticateCiphertext(ciphertext(), descriptor, signal)
  const reader = await openChatMediaReader(fromBase6432(descriptor.attachmentKey), descriptor.attachmentId, descriptor.manifestSha256, header, manifest)
  try {
    let index = 0
    let read = 0
    let pending: Uint8Array<ArrayBufferLike> = new Uint8Array()
    let pendingStart = layout.headerBytes
    let plaintextRead = 0
    for await (const chunk of ciphertext()) {
      throwIfAborted(signal)
      const start = read
      read += chunk.length
      // The blocks: from the header's end to the manifest.
      const from = Math.max(start, layout.headerBytes)
      const to = Math.min(read, layout.manifestStart)
      if (from >= to) continue
      pending = appendBytes(pending, chunk.subarray(from - start, to - start))
      while (index < layout.blockCount) {
        const sealedLength = reader.sealedBlockLength(index)
        if (pendingStart + pending.length < reader.blockOffset(index) + sealedLength) break
        const plain = reader.openBlock(index, pending.subarray(0, sealedLength))
        pending = pending.subarray(sealedLength)
        pendingStart += sealedLength
        plaintextRead += plain.length
        index++
        yield { plain, isFinal: index === layout.blockCount }
      }
    }
    throwIfAborted(signal)
    if (index !== layout.blockCount || plaintextRead !== descriptor.plaintextBytes || read !== descriptor.ciphertextBytes) {
      throw new Error('Chat-media object differs from its authenticated descriptor')
    }
  } finally {
    reader.free()
  }
}

/**
 * Fetches from the user's own server by Range and opens it block by block:
 * the header and the manifest the descriptor commits to first, then each
 * block checked against it before it is released.
 */
export async function* fetchChatMediaV1(
  descriptor: ChatAttachmentDescriptorV1,
  accessToken: AccessToken,
  signal?: AbortSignal,
): AsyncGenerator<ChatMediaPlainChunk, void, void> {
  const reader = await openBlockReader({
    source: await chatMediaBlockSourceV1(descriptor),
    accessToken,
    settings: { cacheBlocks: 2, readaheadBlocks: 1, responseMaxBytes: 5 * 1024 * 1024 },
    signal,
  })
  try {
    const { blockCount } = reader.opened
    for (let index = 0; index < blockCount; index++) {
      throwIfAborted(signal)
      yield { plain: await reader.block(index), isFinal: index === blockCount - 1 }
    }
  } finally {
    reader.close()
  }
}

/**
 * Plays a video or song attachment (docs/plans/drive-block-format.md §4):
 * streamed from the account's own server through the service worker, so a
 * seek fetches one block; where no worker controls the page, opened whole
 * from the private cache (downloading it there first).
 */
export async function openChatMediaPlaybackV1(
  descriptor: ChatAttachmentDescriptorV1,
  cache: PrivateCiphertextCacheV1,
  signal?: AbortSignal,
): Promise<Playback> {
  const mimeType = descriptor.mimeType || 'application/octet-stream'
  return openMediaPlayback(
    {
      size: descriptor.plaintextBytes,
      mimeType,
      limits: () => driveStreamLimits(),
      stream: async (limits, streamSignal) =>
        openPlayerStream({
          source: await chatMediaBlockSourceV1(descriptor),
          accessToken: freshAccessToken,
          mimeType,
          limits,
          signal: streamSignal,
        }),
      readWhole: async (readSignal) => {
        if (!(await isChatMediaAvailableInKutupV1(cache, descriptor))) {
          await downloadChatMediaToCacheV1(cache, descriptor, await freshAccessToken(), undefined, readSignal)
        }
        return (await openCachedChatMediaV1(cache, descriptor, readSignal)).blob
      },
    },
    signal,
  )
}

export async function isChatMediaAvailableInKutupV1(
  cache: PrivateCiphertextCacheV1,
  descriptor: ChatAttachmentDescriptorV1,
): Promise<boolean> {
  return (await cache.getVerified(chatMediaCacheBindingV1(descriptor))) !== null
}

/** Download ciphertext into Kutup's account-private cache. This never opens an
 * OS save picker and does not persist plaintext. */
export async function downloadChatMediaToCacheV1(
  cache: PrivateCiphertextCacheV1,
  descriptor: ChatAttachmentDescriptorV1,
  accessToken: string,
  onProgress?: (receivedBytes: number, totalBytes: number) => void,
  signal?: AbortSignal,
  lifecycle: CiphertextCacheLifecycleV1 = {},
  backupCiphertext?: () => AsyncIterable<Uint8Array>,
): Promise<void> {
  const binding = chatMediaCacheBindingV1(descriptor)
  const bindingKey = await cache.bindingKey(binding)
  await chatMediaCacheRequestsV1.request(
    bindingKey,
    async (sharedSignal, report) => {
      await cache.putVerified(
        binding,
        fetchLiveOrBackupCiphertext(
          descriptor, accessToken, sharedSignal,
          (receivedBytes, totalBytes) => report({ receivedBytes, totalBytes }),
          backupCiphertext,
        ),
        async (chunks, _binding, verifySignal) => {
          await verifyChatMediaCiphertextV1(chunks, descriptor, verifySignal)
        },
        lifecycle,
        sharedSignal,
      )
    },
    { signal, onProgress: progress => onProgress?.(progress.receivedBytes, progress.totalBytes) },
  )
}

async function* fetchLiveOrBackupCiphertext(
  descriptor: ChatAttachmentDescriptorV1,
  accessToken: string,
  signal: AbortSignal,
  onProgress: (receivedBytes: number, totalBytes: number) => void,
  backupCiphertext?: () => AsyncIterable<Uint8Array>,
): AsyncGenerator<Uint8Array, void, void> {
  try {
    yield* fetchChatMediaCiphertextV1(descriptor, accessToken, signal, onProgress)
  } catch (error) {
    if (!backupCiphertext || !(error instanceof Error)
        || error.message !== 'Chat-media download HTTP 404') throw error
    let received = 0
    for await (const chunk of backupCiphertext()) {
      received += chunk.length
      onProgress(received, descriptor.ciphertextBytes)
      yield chunk
    }
  }
}

export async function clearCachedChatMediaV1(
  cache: PrivateCiphertextCacheV1,
  descriptor: ChatAttachmentDescriptorV1,
): Promise<void> {
  await cache.remove(chatMediaCacheBindingV1(descriptor))
}

/** Explicitly export already-verified cached media to the user's device. */
export async function saveCachedChatMediaToDeviceV1(
  cache: PrivateCiphertextCacheV1,
  descriptor: ChatAttachmentDescriptorV1,
  onProgress?: (plainBytes: number, plainTotal: number) => void,
  signal?: AbortSignal,
): Promise<void> {
  const sink = await openDownloadSink({ filename: descriptor.filename, mimeType: descriptor.mimeType })
  let written = 0
  try {
    for await (const { plain } of decryptChatMediaCiphertextV1(
      () => cache.readVerified(chatMediaCacheBindingV1(descriptor), signal),
      descriptor,
      signal,
    )) {
      await sink.write(plain)
      written += plain.length
      onProgress?.(written, descriptor.plaintextBytes)
    }
    await sink.finalize()
  } catch (error) {
    await sink.abort().catch(() => undefined)
    throw error
  }
}

export interface OpenedChatMediaV1 {
  blob: Blob
  mimeType: string
  kind: ChatMediaViewerKindV1
}

export type ChatMediaViewerKindV1 = 'image' | 'audio' | 'video' | 'pdf'

const CHAT_VIEWER_KIND_BY_EXTENSION: Readonly<Record<string, ChatMediaViewerKindV1>> = {
  aac: 'audio',
  avif: 'image',
  bmp: 'image',
  flac: 'audio',
  gif: 'image',
  jpeg: 'image',
  jpg: 'image',
  m4a: 'audio',
  mp3: 'audio',
  mp4: 'video',
  oga: 'audio',
  ogg: 'audio',
  ogv: 'video',
  pdf: 'pdf',
  png: 'image',
  wav: 'audio',
  webm: 'video',
  webp: 'image',
}

/** A presentation hint only. Full bytes are reclassified after authentication. */
export function chatMediaViewerKindV1(
  descriptor: Pick<ChatAttachmentDescriptorV1, 'filename' | 'mimeType'>,
): ChatMediaViewerKindV1 | null {
  const extension = descriptor.filename.split('.').pop()?.toLowerCase() ?? ''
  const hinted = CHAT_VIEWER_KIND_BY_EXTENSION[extension] ?? null
  if (!hinted) return null
  const mimeType = descriptor.mimeType.split(';', 1)[0].trim().toLowerCase()
  if (!mimeType || mimeType === 'application/octet-stream' || mimeType === 'binary/octet-stream') {
    return hinted
  }
  if (extension === 'webm' && mimeType.startsWith('audio/')) return 'audio'
  if (hinted === 'image') return mimeType.startsWith('image/') ? hinted : null
  if (hinted === 'audio') return mimeType.startsWith('audio/') ? hinted : null
  if (hinted === 'video') return mimeType.startsWith('video/') ? hinted : null
  return mimeType === 'application/pdf' ? hinted : null
}

const MAX_TRANSIENT_CHAT_MEDIA_BLOB_BYTES = 64 * 1024 * 1024

/** Fully authenticate a bounded cached object before exposing a transient Blob
 * to a browser decoder. Plaintext is never written back to persistent storage. */
export async function openCachedChatMediaV1(
  cache: PrivateCiphertextCacheV1,
  descriptor: ChatAttachmentDescriptorV1,
  signal?: AbortSignal,
): Promise<OpenedChatMediaV1> {
  if (descriptor.plaintextBytes > MAX_TRANSIENT_CHAT_MEDIA_BLOB_BYTES) {
    throw new Error('attachment is too large for the in-app viewer')
  }
  const plaintext = new Uint8Array(descriptor.plaintextBytes)
  let offset = 0
  for await (const { plain } of decryptChatMediaCiphertextV1(
    () => cache.readVerified(chatMediaCacheBindingV1(descriptor), signal),
    descriptor,
    signal,
  )) {
    if (offset + plain.length > plaintext.length) {
      throw new Error('Chat-media plaintext exceeds its authenticated length')
    }
    plaintext.set(plain, offset)
    offset += plain.length
  }
  if (offset !== plaintext.length) throw new Error('Chat-media plaintext length changed')
  const safety = classifyFileForKutup({
    filename: descriptor.filename,
    mimeType: descriptor.mimeType,
    bytes: plaintext.subarray(0, Math.min(plaintext.length, 4096)),
  })
  const mimeType = safety.detectedMimeType
  if (safety.classification !== 'previewable' || !mimeType) {
    throw new Error('attachment type is not safe for the in-app viewer')
  }
  const kind = mimeType.startsWith('image/')
    ? 'image'
    : mimeType.startsWith('audio/')
      ? 'audio'
      : mimeType.startsWith('video/')
        ? 'video'
        : mimeType === 'application/pdf'
          ? 'pdf'
          : null
  if (!kind) throw new Error('attachment type has no in-app viewer')
  if (kind === 'image') {
    const dimensions = inspectRasterDimensions(plaintext, mimeType)
    if (!dimensions || dimensions.width * dimensions.height > 16_000_000) {
      throw new Error('image dimensions exceed the in-app viewer budget')
    }
  }
  return {
    blob: new Blob([exactBytes(plaintext)], { type: mimeType }),
    mimeType,
    kind,
  }
}

export function cancelChatMediaCacheRequestsV1(): void {
  chatMediaCacheRequestsV1.cancelAll()
}

export async function downloadChatMediaV1(
  descriptor: ChatAttachmentDescriptorV1,
  accessToken: string,
  onProgress?: (plainBytes: number, plainTotal: number) => void,
  signal?: AbortSignal,
): Promise<void> {
  const sink = await openDownloadSink({
    filename: descriptor.filename,
    mimeType: descriptor.mimeType,
  })
  let written = 0
  try {
    for await (const { plain } of fetchChatMediaV1(descriptor, accessToken, signal)) {
      await sink.write(plain)
      written += plain.length
      onProgress?.(written, descriptor.plaintextBytes)
    }
    await sink.finalize()
  } catch (error) {
    await sink.abort().catch(() => {})
    throw error
  }
}

function appendBytes(
  left: Uint8Array<ArrayBufferLike>,
  right: Uint8Array<ArrayBufferLike>,
): Uint8Array<ArrayBufferLike> {
  if (left.length === 0) return right
  const joined = new Uint8Array(left.length + right.length)
  joined.set(left)
  joined.set(right, left.length)
  return joined
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new DOMException('Chat-media operation aborted', 'AbortError')
}

function fromBase6432(value: string): Uint8Array {
  const binary = atob(value)
  if (binary.length !== 32 || btoa(binary) !== value) {
    throw new Error('Chat-media attachment key is not canonical base64')
  }
  return Uint8Array.from(binary, character => character.charCodeAt(0))
}

function inferMediaClass(mimeType: string): ChatMediaClassV1 {
  if (mimeType.startsWith('image/')) return 'photo'
  if (mimeType.startsWith('video/')) return 'video'
  if (mimeType.startsWith('audio/')) return 'audio'
  return 'file'
}

/**
 * Whether a failed delivery request was refused for good: the recipient's
 * server refused the attachment (404, 422), or the request can never pass
 * (400, 409). Anything else (offline, a server error, a limit) may pass
 * when asked again.
 */
export function chatMediaDeliveryRefused(error: unknown): boolean {
  const status = (error as { response?: { status?: number } } | null)?.response?.status
  return status === 400 || status === 404 || status === 409 || status === 422
}

/** The delivery operation an attachment's first send to `recipient` asks under. */
export async function chatMediaDeliveryOperationId(
  attachmentId: string,
  recipient: string,
): Promise<string> {
  const input = new TextEncoder().encode(
    `kutup/chat-media/delivery-operation/v1\0${attachmentId}\0${recipient}`,
  )
  const digest = await hash(input)
  const uuid = digest.slice(0, 16)
  // RFC 9562 variant with the application-defined UUIDv8 version. The full
  // derivation is domain separated and deterministic for retry safety.
  uuid[6] = (uuid[6] & 0x0f) | 0x80
  uuid[8] = (uuid[8] & 0x3f) | 0x80
  const hex = Array.from(uuid, byte => byte.toString(16).padStart(2, '0')).join('')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}
