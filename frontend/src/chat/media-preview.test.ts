import { describe, expect, it } from 'vitest'
import {
  decodeChatMediaPreviewV1,
  encodeChatMediaPreviewV1,
} from './media-preview'
import { CHAT_PREVIEW_PROFILE_V1, PREVIEW_WAVEFORM_MIME } from '@/mediaPreview'

function webp(): Uint8Array {
  const bytes = new Uint8Array(20)
  bytes.set(new TextEncoder().encode('RIFF'), 0)
  bytes.set(new TextEncoder().encode('WEBP'), 8)
  return bytes
}

describe('Chat preview V1 adapter', () => {
  it('round-trips raster bytes through the existing descriptor shape', () => {
    const encoded = encodeChatMediaPreviewV1({
      kind: 'image',
      contentType: 'image/webp',
      width: 100,
      height: 50,
      raster: webp(),
    })
    expect(encoded.mimeType).toBe('image/webp')
    expect(decodeChatMediaPreviewV1(encoded)).toEqual({
      kind: 'raster',
      mimeType: 'image/webp',
      bytes: webp(),
    })
  })

  it('round-trips the canonical 64-sample Chat waveform', () => {
    const samples = Uint8Array.from(
      { length: CHAT_PREVIEW_PROFILE_V1.waveformSamples },
      (_, index) => index * 4,
    )
    const encoded = encodeChatMediaPreviewV1({
      kind: 'audio-waveform',
      contentType: PREVIEW_WAVEFORM_MIME,
      durationMs: 1000,
      waveform: samples,
    })
    expect(decodeChatMediaPreviewV1(encoded)).toEqual({
      kind: 'waveform',
      mimeType: PREVIEW_WAVEFORM_MIME,
      samples,
    })
  })

  it('rejects noncanonical base64, unsupported MIME, oversized data, and fake WebP', () => {
    expect(() => decodeChatMediaPreviewV1({ mimeType: 'image/webp', data: 'abc' }))
      .toThrow(/base64/)
    expect(() => decodeChatMediaPreviewV1({ mimeType: 'image/png', data: 'AA==' }))
      .toThrow(/unsupported/)
    const oversized = new Uint8Array(CHAT_PREVIEW_PROFILE_V1.maxRasterBytes + 1)
    expect(() => decodeChatMediaPreviewV1({
      mimeType: 'image/webp',
      data: btoa(String.fromCharCode(...oversized)),
    })).toThrow(/byte length/)
    expect(() => decodeChatMediaPreviewV1({
      mimeType: 'image/webp',
      data: btoa('not-webp'),
    })).toThrow(/not WebP/)
  })
})
