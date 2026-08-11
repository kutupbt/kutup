import { describe, expect, it } from 'vitest'
import { PREVIEW_WAVEFORM_MIME, type PreviewGenerationResultV1 } from '@/mediaPreview'
import { chatMediaPresentationV1, chatMediaViewerKindV1 } from './media'

describe('Chat upload preview presentation', () => {
  it('adds generated image dimensions and the existing V1 preview descriptor', () => {
    const generated: PreviewGenerationResultV1 = {
      safety: {
        classification: 'previewable',
        normalizedFilename: 'photo.png',
        extension: 'png',
        claimedMimeType: 'image/png',
        detectedMimeType: 'image/png',
        reason: 'allowlisted-signature',
      },
      mediaMetadata: { width: 1920, height: 1080 },
      payload: {
        kind: 'image',
        contentType: 'image/webp',
        width: 320,
        height: 180,
        raster: webp(),
      },
    }
    const result = chatMediaPresentationV1({
      file: new File([new Uint8Array([1])], 'photo.png', { type: 'image/png' }),
    }, generated)
    expect(result).toMatchObject({
      filename: 'photo.png',
      mimeType: 'image/png',
      mediaClass: 'photo',
      width: 1920,
      height: 1080,
      preview: { mimeType: 'image/webp' },
    })
  })

  it('prefers authenticated caller metadata for a recorded voice note', () => {
    const samples = new Uint8Array(64).fill(100)
    const result = chatMediaPresentationV1({
      file: new File([new TextEncoder().encode('ID3')], 'voice.mp3', { type: 'audio/mpeg' }),
      durationMs: 1500,
    }, {
      safety: {
        classification: 'previewable',
        normalizedFilename: 'voice.mp3',
        extension: 'mp3',
        claimedMimeType: 'audio/mpeg',
        detectedMimeType: 'audio/mpeg',
        reason: 'allowlisted-signature',
      },
      mediaMetadata: { durationMs: 1490 },
      payload: {
        kind: 'audio-waveform',
        contentType: PREVIEW_WAVEFORM_MIME,
        durationMs: 1490,
        waveform: samples,
      },
    })
    expect(result.durationMs).toBe(1500)
    expect(result.preview?.mimeType).toBe(PREVIEW_WAVEFORM_MIME)
  })

  it('keeps unsupported files on the generic descriptor path', () => {
    expect(chatMediaPresentationV1({
      file: new File([new Uint8Array([1])], 'archive.zip', { type: 'application/zip' }),
    }, null)).toEqual({
      filename: 'archive.zip',
      mimeType: 'application/zip',
      mediaClass: 'file',
    })
  })

  it('offers in-app viewers only for matching safe presentation hints', () => {
    expect(chatMediaViewerKindV1({ filename: 'report.pdf', mimeType: 'application/pdf' })).toBe('pdf')
    expect(chatMediaViewerKindV1({ filename: 'photo.png', mimeType: 'image/png' })).toBe('image')
    expect(chatMediaViewerKindV1({ filename: 'clip.mp4', mimeType: 'video/mp4' })).toBe('video')
    expect(chatMediaViewerKindV1({ filename: 'renamed.pdf', mimeType: 'application/x-executable' })).toBeNull()
    expect(chatMediaViewerKindV1({ filename: 'program.exe', mimeType: 'application/octet-stream' })).toBeNull()
  })
})

function webp(): Uint8Array {
  const bytes = new Uint8Array(20)
  bytes.set(new TextEncoder().encode('RIFF'), 0)
  bytes.set(new TextEncoder().encode('WEBP'), 8)
  return bytes
}
