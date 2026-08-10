import { describe, expect, it } from 'vitest'
import {
  CHAT_PREVIEW_PROFILE_V1,
  DRIVE_PREVIEW_PROFILE_V1,
  PREVIEW_WAVEFORM_MIME,
  PREVIEW_WEBP_MIME,
  decodeAudioWaveformV1,
  encodeAudioWaveformV1,
  validatePreviewManifestV1,
} from './manifest'

const source = {
  product: 'chat' as const,
  objectId: '11111111-1111-4111-8111-111111111111',
  contentRevision: 1,
  ciphertextSha256: 'ab'.repeat(32),
}

function webp(size = 20): Uint8Array {
  const bytes = new Uint8Array(size)
  bytes.set(new TextEncoder().encode('RIFF'), 0)
  bytes.set(new TextEncoder().encode('WEBP'), 8)
  return bytes
}

describe('PreviewManifestV1', () => {
  it('accepts a strictly bounded Chat raster preview', () => {
    const preview = validatePreviewManifestV1({
      version: 1,
      kind: 'image',
      contentType: PREVIEW_WEBP_MIME,
      width: 320,
      height: 180,
      raster: webp(),
      source,
    }, CHAT_PREVIEW_PROFILE_V1)
    expect(preview.kind).toBe('image')
  })

  it('rejects unknown fields, missing source binding, oversized payloads, and non-WebP bytes', () => {
    const base = {
      version: 1,
      kind: 'image',
      contentType: PREVIEW_WEBP_MIME,
      width: 320,
      height: 180,
      raster: webp(),
      source,
    }
    expect(() => validatePreviewManifestV1({ ...base, surprise: true }, CHAT_PREVIEW_PROFILE_V1))
      .toThrow(/unknown or missing fields/)
    expect(() => validatePreviewManifestV1({
      ...base,
      source: { product: 'chat', objectId: source.objectId, contentRevision: 1 },
    }, CHAT_PREVIEW_PROFILE_V1)).toThrow(/digest is required/)
    expect(() => validatePreviewManifestV1({
      ...base,
      raster: webp(CHAT_PREVIEW_PROFILE_V1.maxRasterBytes + 1),
    }, CHAT_PREVIEW_PROFILE_V1)).toThrow(/raster preview bytes/)
    expect(() => validatePreviewManifestV1({
      ...base,
      raster: new Uint8Array(20),
    }, CHAT_PREVIEW_PROFILE_V1)).toThrow(/raster preview bytes/)
  })

  it('does not allow Chat-sized dimensions to exceed pixel or edge budgets', () => {
    expect(() => validatePreviewManifestV1({
      version: 1,
      kind: 'image',
      contentType: PREVIEW_WEBP_MIME,
      width: 385,
      height: 1,
      raster: webp(),
      source,
    }, CHAT_PREVIEW_PROFILE_V1)).toThrow(/dimensions/)
  })

  it('requires the profile waveform length and positive bounded duration', () => {
    const waveform = new Uint8Array(CHAT_PREVIEW_PROFILE_V1.waveformSamples).fill(100)
    const preview = validatePreviewManifestV1({
      version: 1,
      kind: 'audio-waveform',
      contentType: PREVIEW_WAVEFORM_MIME,
      durationMs: 1234,
      waveform,
      source,
    }, CHAT_PREVIEW_PROFILE_V1)
    expect(preview.kind).toBe('audio-waveform')
    expect(() => validatePreviewManifestV1({
      version: 1,
      kind: 'audio-waveform',
      contentType: PREVIEW_WAVEFORM_MIME,
      durationMs: 0,
      waveform,
      source,
    }, CHAT_PREVIEW_PROFILE_V1)).toThrow(/duration/)
    expect(() => validatePreviewManifestV1({
      version: 1,
      kind: 'audio-waveform',
      contentType: PREVIEW_WAVEFORM_MIME,
      durationMs: 10,
      waveform: new Uint8Array(DRIVE_PREVIEW_PROFILE_V1.waveformSamples),
      source,
    }, CHAT_PREVIEW_PROFILE_V1)).toThrow(/samples/)
  })

  it('round-trips the canonical compact waveform wire payload', () => {
    const samples = Uint8Array.from({ length: 64 }, (_, index) => index * 4)
    const encoded = encodeAudioWaveformV1(samples)
    expect(encoded.length).toBe(8 + 2 + samples.length)
    expect(decodeAudioWaveformV1(encoded, 64)).toEqual(samples)
    expect(() => decodeAudioWaveformV1(encoded.subarray(0, encoded.length - 1), 64))
      .toThrow(/sample count/)
    expect(() => decodeAudioWaveformV1(encoded, 100)).toThrow(/sample count/)
  })
})
