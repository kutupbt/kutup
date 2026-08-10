import { fromBase64, toBase64 } from '@/crypto/base64'
import {
  CHAT_PREVIEW_PROFILE_V1,
  PREVIEW_WAVEFORM_MIME,
  PREVIEW_WEBP_MIME,
  decodeAudioWaveformV1,
  encodeAudioWaveformV1,
  type GeneratedPreviewPayloadV1,
} from '@/mediaPreview'
import type { ChatMediaPreviewV1 } from './types'

export type DecodedChatMediaPreviewV1 =
  | { kind: 'raster'; mimeType: typeof PREVIEW_WEBP_MIME; bytes: Uint8Array }
  | { kind: 'waveform'; mimeType: typeof PREVIEW_WAVEFORM_MIME; samples: Uint8Array }

export function encodeChatMediaPreviewV1(
  payload: GeneratedPreviewPayloadV1,
): ChatMediaPreviewV1 {
  if (payload.kind === 'audio-waveform') {
    return {
      mimeType: PREVIEW_WAVEFORM_MIME,
      data: toBase64(encodeAudioWaveformV1(payload.waveform)),
    }
  }
  return { mimeType: PREVIEW_WEBP_MIME, data: toBase64(payload.raster) }
}

export function decodeChatMediaPreviewV1(
  preview: ChatMediaPreviewV1,
): DecodedChatMediaPreviewV1 {
  if (preview.mimeType !== PREVIEW_WEBP_MIME && preview.mimeType !== PREVIEW_WAVEFORM_MIME) {
    throw new Error('unsupported Chat preview MIME type')
  }
  const bytes = fromCanonicalBase64(preview.data)
  if (bytes.length === 0 || bytes.length > CHAT_PREVIEW_PROFILE_V1.maxRasterBytes) {
    throw new Error('invalid Chat preview byte length')
  }
  if (preview.mimeType === PREVIEW_WAVEFORM_MIME) {
    return {
      kind: 'waveform',
      mimeType: PREVIEW_WAVEFORM_MIME,
      samples: decodeAudioWaveformV1(bytes, CHAT_PREVIEW_PROFILE_V1.waveformSamples),
    }
  }
  if (!isWebP(bytes)) throw new Error('Chat raster preview is not WebP')
  return { kind: 'raster', mimeType: PREVIEW_WEBP_MIME, bytes }
}

function fromCanonicalBase64(value: string): Uint8Array {
  let bytes: Uint8Array
  try {
    bytes = fromBase64(value)
  } catch {
    throw new Error('invalid Chat preview base64')
  }
  if (toBase64(bytes) !== value) throw new Error('non-canonical Chat preview base64')
  return bytes
}

function isWebP(bytes: Uint8Array): boolean {
  return bytes.length >= 12 && asciiAt(bytes, 'RIFF', 0) && asciiAt(bytes, 'WEBP', 8)
}

function asciiAt(bytes: Uint8Array, value: string, offset: number): boolean {
  if (bytes.length < offset + value.length) return false
  for (let index = 0; index < value.length; index += 1) {
    if (bytes[offset + index] !== value.charCodeAt(index)) return false
  }
  return true
}
