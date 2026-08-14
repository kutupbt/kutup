import { classifyFileForKutup, type FileSafetyResult } from './fileSafety'
import {
  PREVIEW_WAVEFORM_MIME,
  PREVIEW_WEBP_MIME,
  validatePreviewManifestV1,
  type PreviewManifestV1,
  type PreviewProfileV1,
  type PreviewSourceV1,
} from './manifest'
import { inspectOoxmlContainerV1 } from './ooxml'
import { normalizeAudioWaveform } from './waveform'
import type {
  RasterPreviewWorkerRequestV1,
  RasterPreviewWorkerResponseV1,
} from './workerProtocol'

export interface PreviewGenerationLimitsV1 {
  maxImageInputBytes: number
  maxImageInputPixels: number
  maxAudioInputBytes: number
  timeoutMs: number
}

export const CHAT_PREVIEW_GENERATION_LIMITS_V1: PreviewGenerationLimitsV1 = Object.freeze({
  maxImageInputBytes: 32 * 1024 * 1024,
  maxImageInputPixels: 16_000_000,
  maxAudioInputBytes: 16 * 1024 * 1024,
  timeoutMs: 10_000,
})

export const DRIVE_PREVIEW_GENERATION_LIMITS_V1: PreviewGenerationLimitsV1 = Object.freeze({
  maxImageInputBytes: 64 * 1024 * 1024,
  maxImageInputPixels: 16_000_000,
  maxAudioInputBytes: 64 * 1024 * 1024,
  timeoutMs: 15_000,
})

export type GeneratedPreviewPayloadV1 =
  | {
      kind: 'image'
      contentType: typeof PREVIEW_WEBP_MIME
      width: number
      height: number
      raster: Uint8Array
    }
  | {
      kind: 'audio-waveform'
      contentType: typeof PREVIEW_WAVEFORM_MIME
      durationMs: number
      waveform: Uint8Array
    }

export interface PreviewGenerationResultV1 {
  safety: FileSafetyResult
  payload: GeneratedPreviewPayloadV1 | null
  mediaMetadata?: { width?: number; height?: number; durationMs?: number }
  unavailableReason?: string
}

export interface RasterPreviewWorkerLike {
  onmessage: ((event: MessageEvent<RasterPreviewWorkerResponseV1>) => void) | null
  onerror: ((event: ErrorEvent) => void) | null
  postMessage(message: RasterPreviewWorkerRequestV1, transfer: Transferable[]): void
  terminate(): void
}

export type RasterWorkerFactory = () => RasterPreviewWorkerLike

export interface PreviewGenerationDependenciesV1 {
  rasterWorkerFactory?: RasterWorkerFactory
  decodeAudio?: (bytes: ArrayBuffer, signal?: AbortSignal) => Promise<DecodedAudioV1>
}

export interface DecodedAudioV1 {
  durationMs: number
  channels: Float32Array[]
  close?: () => Promise<void> | void
}

export async function generatePreviewPayloadV1(
  file: File,
  profile: PreviewProfileV1,
  limits: PreviewGenerationLimitsV1,
  signal?: AbortSignal,
  dependencies: PreviewGenerationDependenciesV1 = {},
): Promise<PreviewGenerationResultV1> {
  validateGenerationLimits(limits)
  throwIfAborted(signal)
  const header = new Uint8Array(await readBlob(file.slice(0, 4096)))
  throwIfAborted(signal)
  let safety = classifyFileForKutup({ filename: file.name, mimeType: file.type, bytes: header })
  if (safety.reason === 'container-verification-required') {
    try {
      const verifiedContainerType = await runWithDeadline(
        deadlineSignal => inspectOoxmlContainerV1(file, undefined, deadlineSignal),
        limits.timeoutMs,
        signal,
      )
      safety = classifyFileForKutup({
        filename: file.name,
        mimeType: file.type,
        bytes: header,
        ...(verifiedContainerType ? { verifiedContainerType } : {}),
      })
    } catch (error) {
      if (isAbortError(error)) throw error
      return {
        safety,
        payload: null,
        unavailableReason: error instanceof Error ? error.message : 'container-inspection-failed',
      }
    }
  }
  if (safety.classification !== 'previewable' || !safety.detectedMimeType) {
    return { safety, payload: null, unavailableReason: safety.reason }
  }
  const detectedMimeType = safety.detectedMimeType

  try {
    if (detectedMimeType.startsWith('image/')) {
      if (file.size > limits.maxImageInputBytes) {
        return { safety, payload: null, unavailableReason: 'image-input-byte-limit' }
      }
      const bytes = await readBlob(file)
      throwIfAborted(signal)
      const response = await runWithDeadline(
        deadlineSignal => runRasterWorker({
          type: 'raster-image-v1',
          filename: file.name,
          mimeType: detectedMimeType,
          bytes,
          maxInputPixels: limits.maxImageInputPixels,
          maxEdge: profile.maxEdge,
          maxOutputBytes: profile.maxRasterBytes,
        }, deadlineSignal, dependencies.rasterWorkerFactory),
        limits.timeoutMs,
        signal,
      )
      return {
        safety,
        mediaMetadata: { width: response.sourceWidth, height: response.sourceHeight },
        payload: {
          kind: 'image',
          contentType: PREVIEW_WEBP_MIME,
          width: response.width,
          height: response.height,
          raster: new Uint8Array(response.raster),
        },
      }
    }

    if (detectedMimeType.startsWith('audio/')) {
      if (file.size > limits.maxAudioInputBytes) {
        return { safety, payload: null, unavailableReason: 'audio-input-byte-limit' }
      }
      const encodedAudio = await readBlob(file)
      throwIfAborted(signal)
      const decoded = await runWithDeadline(
        deadlineSignal => (dependencies.decodeAudio ?? decodeAudioInBrowser)(
          encodedAudio,
          deadlineSignal,
        ),
        limits.timeoutMs,
        signal,
      )
      try {
        if (!Number.isSafeInteger(decoded.durationMs) || decoded.durationMs < 1 ||
            decoded.durationMs > profile.maxDurationMs || decoded.channels.length > 8) {
          return { safety, payload: null, unavailableReason: 'audio-decoder-budget' }
        }
        return {
          safety,
          mediaMetadata: { durationMs: decoded.durationMs },
          payload: {
            kind: 'audio-waveform',
            contentType: PREVIEW_WAVEFORM_MIME,
            durationMs: decoded.durationMs,
            waveform: normalizeAudioWaveform(decoded.channels, profile.waveformSamples),
          },
        }
      } finally {
        await decoded.close?.()
      }
    }

    return { safety, payload: null, unavailableReason: 'generator-not-implemented' }
  } catch (error) {
    if (isAbortError(error)) throw error
    return {
      safety,
      payload: null,
      unavailableReason: error instanceof Error ? error.message : 'preview-generation-failed',
    }
  }
}

export function bindPreviewPayloadV1(
  payload: GeneratedPreviewPayloadV1,
  source: PreviewSourceV1,
  profile: PreviewProfileV1,
): PreviewManifestV1 {
  return validatePreviewManifestV1({ version: 1, ...payload, source }, profile)
}

async function runRasterWorker(
  request: RasterPreviewWorkerRequestV1,
  signal?: AbortSignal,
  factory: RasterWorkerFactory = defaultRasterWorkerFactory,
): Promise<Extract<RasterPreviewWorkerResponseV1, { type: 'raster-image-result-v1' }>> {
  throwIfAborted(signal)
  return new Promise((resolve, reject) => {
    const worker = factory()
    let settled = false
    const finish = (action: () => void) => {
      if (settled) return
      settled = true
      signal?.removeEventListener('abort', abort)
      worker.terminate()
      action()
    }
    const abort = () => finish(() => reject(new DOMException('preview generation aborted', 'AbortError')))
    signal?.addEventListener('abort', abort, { once: true })
    worker.onmessage = event => {
      const response = event.data
      if (response.type === 'error') finish(() => reject(new Error(response.message)))
      else if (response.type === 'raster-image-result-v1') finish(() => resolve(response))
      else finish(() => reject(new Error('preview worker returned an unexpected response')))
    }
    worker.onerror = event => finish(() => reject(new Error(event.message || 'preview worker failed')))
    worker.postMessage(request, [request.bytes])
  })
}

function defaultRasterWorkerFactory(): RasterPreviewWorkerLike {
  return new Worker(new URL('../workers/mediaPreview.worker.ts', import.meta.url), {
    type: 'module',
  }) as unknown as RasterPreviewWorkerLike
}

async function decodeAudioInBrowser(bytes: ArrayBuffer, signal?: AbortSignal): Promise<DecodedAudioV1> {
  throwIfAborted(signal)
  const AudioContextConstructor = window.AudioContext ||
    (window as typeof window & { webkitAudioContext?: typeof AudioContext }).webkitAudioContext
  if (!AudioContextConstructor) throw new Error('audio decoder is unavailable')
  const context = new AudioContextConstructor()
  const abort = () => { void context.close().catch(() => undefined) }
  signal?.addEventListener('abort', abort, { once: true })
  try {
    const buffer = await context.decodeAudioData(bytes.slice(0))
    throwIfAborted(signal)
    if (buffer.numberOfChannels < 1 || buffer.numberOfChannels > 8 ||
        !Number.isFinite(buffer.duration) || buffer.duration <= 0) {
      throw new Error('decoded audio exceeds channel or duration budget')
    }
    const channels: Float32Array[] = []
    for (let index = 0; index < buffer.numberOfChannels; index += 1) {
      channels.push(buffer.getChannelData(index))
    }
    return {
      durationMs: Math.max(1, Math.round(buffer.duration * 1000)),
      channels,
      close: () => context.close(),
    }
  } catch (error) {
    await context.close().catch(() => undefined)
    throw error
  } finally {
    signal?.removeEventListener('abort', abort)
  }
}

async function runWithDeadline<T>(
  operation: (signal: AbortSignal) => Promise<T>,
  timeoutMs: number,
  outerSignal?: AbortSignal,
): Promise<T> {
  throwIfAborted(outerSignal)
  const controller = new AbortController()
  let timedOut = false
  const forwardAbort = () => controller.abort()
  outerSignal?.addEventListener('abort', forwardAbort, { once: true })
  const timer = setTimeout(() => {
    timedOut = true
    controller.abort()
  }, timeoutMs)
  try {
    const aborted = new Promise<T>((_resolve, reject) => {
      controller.signal.addEventListener('abort', () => {
        reject(new DOMException('preview generation aborted', 'AbortError'))
      }, { once: true })
    })
    return await Promise.race([operation(controller.signal), aborted])
  } catch (error) {
    if (timedOut) throw new Error('preview generation timed out')
    if (outerSignal?.aborted) {
      throw new DOMException('preview generation aborted', 'AbortError')
    }
    throw error
  } finally {
    clearTimeout(timer)
    outerSignal?.removeEventListener('abort', forwardAbort)
  }
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new DOMException('preview generation aborted', 'AbortError')
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === 'AbortError'
}

function validateGenerationLimits(limits: PreviewGenerationLimitsV1): void {
  for (const value of [
    limits.maxImageInputBytes,
    limits.maxImageInputPixels,
    limits.maxAudioInputBytes,
    limits.timeoutMs,
  ]) {
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new Error('invalid preview generation limits')
    }
  }
}

function readBlob(blob: Blob): Promise<ArrayBuffer> {
  if (typeof blob.arrayBuffer === 'function') return blob.arrayBuffer()
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onerror = () => reject(reader.error ?? new Error('file could not be read'))
    reader.onload = () => {
      if (!(reader.result instanceof ArrayBuffer)) reject(new Error('file reader returned invalid bytes'))
      else resolve(reader.result)
    }
    reader.readAsArrayBuffer(blob)
  })
}
