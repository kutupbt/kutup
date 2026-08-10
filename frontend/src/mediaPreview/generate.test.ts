import { describe, expect, it, vi } from 'vitest'
import {
  CHAT_PREVIEW_GENERATION_LIMITS_V1,
  bindPreviewPayloadV1,
  generatePreviewPayloadV1,
  type RasterPreviewWorkerLike,
} from './generate'
import { CHAT_PREVIEW_PROFILE_V1 } from './manifest'
import type { RasterPreviewWorkerResponseV1 } from './workerProtocol'

function pngFile(name = 'photo.png'): File {
  const bytes = new Uint8Array(24)
  bytes.set(new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))
  bytes.set(new TextEncoder().encode('IHDR'), 12)
  const view = new DataView(bytes.buffer)
  view.setUint32(16, 320, false)
  view.setUint32(20, 180, false)
  return new File([bytes], name, { type: 'image/png' })
}

function webp(): ArrayBuffer {
  const bytes = new Uint8Array(20)
  bytes.set(new TextEncoder().encode('RIFF'), 0)
  bytes.set(new TextEncoder().encode('WEBP'), 8)
  return bytes.buffer
}

function respondingWorker(response: RasterPreviewWorkerResponseV1) {
  const terminate = vi.fn()
  const worker: RasterPreviewWorkerLike = {
    onmessage: null,
    onerror: null,
    postMessage: vi.fn(() => queueMicrotask(() => {
      worker.onmessage?.({ data: response } as MessageEvent<RasterPreviewWorkerResponseV1>)
    })),
    terminate,
  }
  return { worker, terminate }
}

describe('preview generation orchestration', () => {
  it('runs allowlisted images through the bounded worker and validates source binding', async () => {
    const { worker, terminate } = respondingWorker({
      type: 'raster-image-result-v1',
      raster: webp(),
      width: 320,
      height: 180,
      sourceWidth: 1920,
      sourceHeight: 1080,
    })
    const result = await generatePreviewPayloadV1(
      pngFile(),
      CHAT_PREVIEW_PROFILE_V1,
      CHAT_PREVIEW_GENERATION_LIMITS_V1,
      undefined,
      { rasterWorkerFactory: () => worker },
    )
    expect(result.safety.classification).toBe('previewable')
    expect(result.payload).toMatchObject({ kind: 'image', width: 320, height: 180 })
    expect(result.mediaMetadata).toEqual({ width: 1920, height: 1080 })
    expect(terminate).toHaveBeenCalledOnce()
    expect(bindPreviewPayloadV1(result.payload!, {
      product: 'chat',
      objectId: '11111111-1111-4111-8111-111111111111',
      contentRevision: 1,
      ciphertextSha256: 'cd'.repeat(32),
    }, CHAT_PREVIEW_PROFILE_V1).kind).toBe('image')
  })

  it('creates bounded audio waveforms through an injected decoder', async () => {
    const close = vi.fn()
    const result = await generatePreviewPayloadV1(
      new File([new TextEncoder().encode('ID3audio')], 'voice.mp3', { type: 'audio/mpeg' }),
      CHAT_PREVIEW_PROFILE_V1,
      CHAT_PREVIEW_GENERATION_LIMITS_V1,
      undefined,
      {
        decodeAudio: vi.fn(async () => ({
          durationMs: 900,
          channels: [Float32Array.from([0, 0.25, 0.5, 1])],
          close,
        })),
      },
    )
    expect(result.payload?.kind).toBe('audio-waveform')
    if (result.payload?.kind === 'audio-waveform') {
      expect(result.payload.waveform).toHaveLength(CHAT_PREVIEW_PROFILE_V1.waveformSamples)
      expect(Math.max(...result.payload.waveform)).toBe(255)
    }
    expect(close).toHaveBeenCalledOnce()
  })

  it('routes audio/webm voice notes through the audio preview decoder', async () => {
    const decodeAudio = vi.fn(async () => ({
      durationMs: 1_200,
      channels: [Float32Array.from([0, 0.5, 1])],
    }))
    const result = await generatePreviewPayloadV1(
      new File(
        [new Uint8Array([0x1a, 0x45, 0xdf, 0xa3])],
        'voice-note.webm',
        { type: 'audio/webm; codecs=opus' },
      ),
      CHAT_PREVIEW_PROFILE_V1,
      CHAT_PREVIEW_GENERATION_LIMITS_V1,
      undefined,
      { decodeAudio },
    )
    expect(result.safety).toMatchObject({
      classification: 'previewable',
      detectedMimeType: 'audio/webm',
    })
    expect(result.payload?.kind).toBe('audio-waveform')
    expect(decodeAudio).toHaveBeenCalledOnce()
  })

  it('returns no preview for unsafe input without invoking a decoder', async () => {
    const rasterWorkerFactory = vi.fn()
    const result = await generatePreviewPayloadV1(
      new File([new Uint8Array([0x4d, 0x5a])], 'renamed.png', { type: 'image/png' }),
      CHAT_PREVIEW_PROFILE_V1,
      CHAT_PREVIEW_GENERATION_LIMITS_V1,
      undefined,
      { rasterWorkerFactory },
    )
    expect(result.safety.classification).toBe('dangerous-active')
    expect(result.payload).toBeNull()
    expect(rasterWorkerFactory).not.toHaveBeenCalled()
  })

  it('terminates the image worker when the caller aborts', async () => {
    const terminate = vi.fn()
    const postMessage = vi.fn()
    const worker: RasterPreviewWorkerLike = {
      onmessage: null,
      onerror: null,
      postMessage,
      terminate,
    }
    const controller = new AbortController()
    const pending = generatePreviewPayloadV1(
      pngFile(),
      CHAT_PREVIEW_PROFILE_V1,
      CHAT_PREVIEW_GENERATION_LIMITS_V1,
      controller.signal,
      { rasterWorkerFactory: () => worker },
    )
    await vi.waitFor(() => expect(postMessage).toHaveBeenCalledOnce())
    controller.abort()
    await expect(pending).rejects.toMatchObject({ name: 'AbortError' })
    expect(terminate).toHaveBeenCalledOnce()
  })

  it('times out a non-responsive worker and reports a non-fatal missing preview', async () => {
    const terminate = vi.fn()
    const worker: RasterPreviewWorkerLike = {
      onmessage: null,
      onerror: null,
      postMessage: vi.fn(),
      terminate,
    }
    const pending = generatePreviewPayloadV1(
      pngFile(),
      CHAT_PREVIEW_PROFILE_V1,
      { ...CHAT_PREVIEW_GENERATION_LIMITS_V1, timeoutMs: 10 },
      undefined,
      { rasterWorkerFactory: () => worker },
    )
    await expect(pending).resolves.toMatchObject({
      payload: null,
      unavailableReason: 'preview generation timed out',
    })
    expect(terminate).toHaveBeenCalledOnce()
  })
})
