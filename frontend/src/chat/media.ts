// Browser orchestration for immutable E2EE Chat-media objects. Persistent
// headers, suite selection and key derivation remain Rust-owned; this adapter
// only provides bounded browser File/ReadableStream I/O and tus mechanics.

import * as tus from 'tus-js-client'
import {
  CHAT_MEDIA_CIPHER_CHUNK_BYTES,
  CHAT_MEDIA_OBJECT_PREFIX_BYTES,
  MAX_CHAT_MEDIA_PLAINTEXT_BYTES,
  chatMediaCipherSize,
  newChatMediaStreamEncryptorV1,
  openChatMediaStreamV1,
} from '@/crypto/chatMedia'
import { toBase64 } from '@/crypto/base64'
import { getSodium } from '@/crypto/sodium'
import { PLAIN_CHUNK } from '@/crypto/streamEncryptor'
import { resolveApiBase } from '@/lib/apiBase'
import { openDownloadSink } from '@/download/streamDownload'
import {
  CiphertextCacheRequestCoordinatorV1,
  type CiphertextCacheBindingV1,
  type CiphertextCacheLifecycleV1,
  type PrivateCiphertextCacheV1,
} from '@/mediaCache'
import {
  CHAT_PREVIEW_GENERATION_LIMITS_V1,
  CHAT_PREVIEW_PROFILE_V1,
  classifyFileForKutup,
  generatePreviewPayloadV1,
  inspectRasterDimensions,
  type PreviewGenerationResultV1,
} from '@/mediaPreview'
import api from '@/api/client'
import { canonicalAccountAddress } from './identity'
import type { AccountAddress } from './types'
import type { ChatAttachmentDescriptorV1, ChatMediaClassV1 } from './types'
import { encodeChatMediaPreviewV1 } from './media-preview'

const SHA256_HEX_BYTES = 64
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
  recipient: AccountAddress,
  deliveryCapability: string,
): Promise<ChatMediaDeliveryResponseV1> {
  if (!recipient.server) throw new Error('Chat-media recipient has no canonical server')
  const recipientText = canonicalAccountAddress(recipient)
  const operationId = await chatMediaDeliveryOperationId(
    descriptor.attachmentId,
    recipientText,
  )
  const response = await api.post<ChatMediaDeliveryResponseV1>('/chat/media/deliveries', {
    version: 1,
    originDomain: descriptor.originDomain,
    destinationDomain: recipient.server,
    recipient: recipientText,
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
  const previewPromise = generatePreviewPayloadV1(
    options.file,
    CHAT_PREVIEW_PROFILE_V1,
    CHAT_PREVIEW_GENERATION_LIMITS_V1,
    options.signal,
  ).catch(() => null)
  const sodium = await getSodium()
  const attachmentId = crypto.randomUUID()
  const attachmentKey = sodium.randombytes_buf(32)
  const retrievalToken = sodium.randombytes_buf(32)
  const encryptor = await newChatMediaStreamEncryptorV1(attachmentKey, attachmentId)
  const ciphertextBytes = chatMediaCipherSize(options.file.size)
  // DefinitelyTyped's sumo declaration currently returns `number` from init
  // but imports the newer branded StateAddress for update/final.
  const hashState = sodium.crypto_hash_sha256_init() as unknown as Parameters<
    typeof sodium.crypto_hash_sha256_update
  >[0]
  let hashFinalized = false
  let position = 0
  let prefixSent = false
  let emptyFinalSent = false

  const hashAndEnqueue = (
    controller: ReadableStreamDefaultController<Uint8Array>,
    bytes: Uint8Array,
  ) => {
    sodium.crypto_hash_sha256_update(hashState, bytes)
    controller.enqueue(bytes)
  }
  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (!prefixSent) {
        prefixSent = true
        hashAndEnqueue(controller, encryptor.prefix)
        return
      }
      if (options.file.size === 0 && !emptyFinalSent) {
        emptyFinalSent = true
        hashAndEnqueue(controller, encryptor.push(new Uint8Array(), true))
        controller.close()
        return
      }
      if (position >= options.file.size) {
        controller.close()
        return
      }
      const end = Math.min(position + PLAIN_CHUNK, options.file.size)
      const plain = new Uint8Array(await options.file.slice(position, end).arrayBuffer())
      const isLast = end === options.file.size
      hashAndEnqueue(controller, encryptor.push(plain, isLast))
      position = end
      if (isLast) controller.close()
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
      chunkSize: CHAT_MEDIA_CIPHER_CHUNK_BYTES,
      retryDelays: [0, 1000, 3000, 5000, 10000],
      storeFingerprintForResuming: false,
      removeFingerprintOnSuccess: true,
      headers: { Authorization: `Bearer ${options.accessToken}` },
      metadata: {
        attachmentId,
        suite: '1',
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
        if (bytesAccepted <= CHAT_MEDIA_OBJECT_PREFIX_BYTES) return
        const afterPrefix = bytesAccepted - CHAT_MEDIA_OBJECT_PREFIX_BYTES
        const chunks = Math.ceil(afterPrefix / CHAT_MEDIA_CIPHER_CHUNK_BYTES)
        const plain = Math.min(options.file.size, Math.max(0, afterPrefix - 17 * chunks))
        if (plain > lastPlainSent) {
          lastPlainSent = plain
          options.onProgress?.(plain, options.file.size)
        }
      },
      onError: fail,
      onSuccess() {
        void finalizeSuccess().catch(fail)
      },
    })

    async function finalizeSuccess() {
      if (settled) return
      if (createdAttachmentId !== attachmentId || !storageReferenceId ||
          serverDigest.length !== SHA256_HEX_BYTES) {
        fail(new Error('Chat-media server returned incomplete finalization evidence'))
        return
      }
      let localDigest: string
      try {
        if (hashFinalized) throw new Error('Chat-media hash was finalized twice')
        hashFinalized = true
        localDigest = sodium.crypto_hash_sha256_final(hashState, 'hex')
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
            suite: 1,
            attachmentId,
            originDomain: options.originDomain,
            retrievalToken: toBase64(retrievalToken),
            ciphertextBytes,
            ciphertextSha256: localDigest,
            attachmentKey: toBase64(attachmentKey),
            plaintextBytes: options.file.size,
            ...chatMediaPresentationV1(options, generatedPreview),
        },
      })
    }

    if (options.signal) {
      if (options.signal.aborted) {
        void upload.abort(true).catch(() => {})
        fail(new DOMException('Upload aborted', 'AbortError'))
        return
      }
      options.signal.addEventListener('abort', () => {
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

async function* fetchChatMediaCiphertextV1(
  descriptor: ChatAttachmentDescriptorV1,
  accessToken: string,
  signal?: AbortSignal,
  onProgress?: (receivedBytes: number, totalBytes: number) => void,
): AsyncGenerator<Uint8Array, void, void> {
  const response = await fetch(
    `${await resolveApiBase()}/chat/media/objects/${encodeURIComponent(descriptor.attachmentId)}`,
    { headers: { Authorization: `Bearer ${accessToken}` }, signal },
  )
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

/** Authenticate the digest, public binding, framing, final tag, AEAD and exact
 * plaintext length of an arbitrary ciphertext chunk stream. */
export async function* decryptChatMediaCiphertextV1(
  ciphertext: AsyncIterable<Uint8Array>,
  descriptor: ChatAttachmentDescriptorV1,
  signal?: AbortSignal,
): AsyncGenerator<ChatMediaPlainChunk, void, void> {
  const sodium = await getSodium()
  const digestState = sodium.crypto_hash_sha256_init() as unknown as Parameters<
    typeof sodium.crypto_hash_sha256_update
  >[0]
  let buffer: Uint8Array<ArrayBufferLike> = new Uint8Array()
  let decryptor: Awaited<ReturnType<typeof openChatMediaStreamV1>> | null = null
  let ciphertextRead = 0
  let plaintextRead = 0
  let sawFinal = false

  for await (const value of ciphertext) {
    throwIfAborted(signal)
    if (!value.length) continue
    if (sawFinal) throw new Error('Chat-media object has bytes after FINAL')
    ciphertextRead += value.length
    if (ciphertextRead > descriptor.ciphertextBytes) {
      throw new Error('Chat-media object exceeds its authenticated length')
    }
    sodium.crypto_hash_sha256_update(digestState, value)
    buffer = appendBytes(buffer, value)
    while (true) {
      if (!decryptor) {
        if (buffer.length < CHAT_MEDIA_OBJECT_PREFIX_BYTES) break
        decryptor = await openChatMediaStreamV1(
          buffer.subarray(0, CHAT_MEDIA_OBJECT_PREFIX_BYTES),
          fromBase6432(descriptor.attachmentKey),
          descriptor.attachmentId,
        )
        buffer = buffer.subarray(CHAT_MEDIA_OBJECT_PREFIX_BYTES)
      }
      if (buffer.length < CHAT_MEDIA_CIPHER_CHUNK_BYTES) break
      const result = decryptor.pull(buffer.subarray(0, CHAT_MEDIA_CIPHER_CHUNK_BYTES))
      buffer = buffer.subarray(CHAT_MEDIA_CIPHER_CHUNK_BYTES)
      plaintextRead += result.plain.length
      yield result
      if (result.isFinal) {
        sawFinal = true
        if (buffer.length) throw new Error('Chat-media object has bytes after FINAL')
        break
      }
    }
  }
  throwIfAborted(signal)
  if (!decryptor) throw new Error('Chat-media object ended before its prefix')
  if (!sawFinal && buffer.length) {
    const result = decryptor.pull(buffer)
    buffer = new Uint8Array()
    plaintextRead += result.plain.length
    yield result
    sawFinal = result.isFinal
  }
  if (!sawFinal) throw new Error('Chat-media object ended before FINAL')
  const digest = sodium.crypto_hash_sha256_final(digestState, 'hex')
  if (ciphertextRead !== descriptor.ciphertextBytes ||
      plaintextRead !== descriptor.plaintextBytes ||
      digest !== descriptor.ciphertextSha256) {
    throw new Error('Chat-media object differs from its authenticated descriptor')
  }
}

/** Fetch from the user's own server and verify digest, framing, ID and AEAD. */
export async function* fetchChatMediaV1(
  descriptor: ChatAttachmentDescriptorV1,
  accessToken: string,
  signal?: AbortSignal,
): AsyncGenerator<ChatMediaPlainChunk, void, void> {
  yield* decryptChatMediaCiphertextV1(
    fetchChatMediaCiphertextV1(descriptor, accessToken, signal),
    descriptor,
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
          for await (const _chunk of decryptChatMediaCiphertextV1(
            chunks,
            descriptor,
            verifySignal,
          )) {
            // Authentication is complete only after the generator reaches EOF.
          }
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
      cache.readVerified(chatMediaCacheBindingV1(descriptor), signal),
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
    cache.readVerified(chatMediaCacheBindingV1(descriptor), signal),
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
    blob: new Blob([plaintext.slice().buffer], { type: mimeType }),
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

async function chatMediaDeliveryOperationId(
  attachmentId: string,
  recipient: string,
): Promise<string> {
  const input = new TextEncoder().encode(
    `kutup/chat-media/delivery-operation/v1\0${attachmentId}\0${recipient}`,
  )
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', input))
  const uuid = digest.slice(0, 16)
  // RFC 9562 variant with the application-defined UUIDv8 version. The full
  // derivation is domain separated and deterministic for retry safety.
  uuid[6] = (uuid[6] & 0x0f) | 0x80
  uuid[8] = (uuid[8] & 0x3f) | 0x80
  const hex = Array.from(uuid, byte => byte.toString(16).padStart(2, '0')).join('')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}
