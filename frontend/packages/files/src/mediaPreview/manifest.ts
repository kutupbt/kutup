export const PREVIEW_WEBP_MIME = 'image/webp' as const
export const PREVIEW_WAVEFORM_MIME = 'application/vnd.kutup.audio-waveform.v1' as const

export type PreviewProduct = 'chat' | 'drive'
export type RasterPreviewKind = 'image' | 'video-poster' | 'pdf-page' | 'office-page'

export interface PreviewSourceV1 {
  product: PreviewProduct
  objectId: string
  contentRevision: number
  ciphertextSha256?: string
}

interface PreviewBaseV1 {
  version: 1
  source: PreviewSourceV1
}

export interface RasterPreviewManifestV1 extends PreviewBaseV1 {
  kind: RasterPreviewKind
  contentType: typeof PREVIEW_WEBP_MIME
  width: number
  height: number
  raster: Uint8Array
  durationMs?: number
  blurHash?: string
}

export interface AudioWaveformPreviewManifestV1 extends PreviewBaseV1 {
  kind: 'audio-waveform'
  contentType: typeof PREVIEW_WAVEFORM_MIME
  durationMs: number
  waveform: Uint8Array
}

export type PreviewManifestV1 = RasterPreviewManifestV1 | AudioWaveformPreviewManifestV1

export interface PreviewProfileV1 {
  product: PreviewProduct
  maxRasterBytes: number
  maxEdge: number
  maxPixels: number
  waveformSamples: number
  maxDurationMs: number
}

export const CHAT_PREVIEW_PROFILE_V1: PreviewProfileV1 = Object.freeze({
  product: 'chat',
  maxRasterBytes: 32 * 1024,
  maxEdge: 384,
  maxPixels: 384 * 384,
  waveformSamples: 64,
  maxDurationMs: 24 * 60 * 60 * 1000,
})

export const DRIVE_PREVIEW_PROFILE_V1: PreviewProfileV1 = Object.freeze({
  product: 'drive',
  maxRasterBytes: 256 * 1024,
  maxEdge: 768,
  maxPixels: 768 * 768,
  waveformSamples: 100,
  maxDurationMs: 24 * 60 * 60 * 1000,
})

const WAVEFORM_MAGIC = new TextEncoder().encode('KUTPWF1\0')

export function validatePreviewManifestV1(
  value: unknown,
  profile: PreviewProfileV1,
): PreviewManifestV1 {
  const record = objectRecord(value, 'preview manifest')
  if (record.version !== 1 || typeof record.kind !== 'string') {
    throw new Error('unsupported preview manifest')
  }
  const source = validateSource(record.source, profile.product)
  if (record.kind === 'audio-waveform') {
    requireExactKeys(record, [
      'contentType', 'durationMs', 'kind', 'source', 'version', 'waveform',
    ])
    if (record.contentType !== PREVIEW_WAVEFORM_MIME) {
      throw new Error('invalid waveform preview content type')
    }
    requireDuration(record.durationMs, profile)
    if (!(record.waveform instanceof Uint8Array) ||
        record.waveform.length !== profile.waveformSamples) {
      throw new Error('invalid waveform preview samples')
    }
    return {
      version: 1,
      kind: 'audio-waveform',
      contentType: PREVIEW_WAVEFORM_MIME,
      durationMs: record.durationMs,
      waveform: record.waveform,
      source,
    }
  }

  if (!isRasterKind(record.kind)) throw new Error('unknown preview manifest kind')
  const optional = ['blurHash']
  if (record.kind === 'video-poster') optional.push('durationMs')
  requireExactKeys(record, [
    'contentType', 'height', 'kind', 'raster', 'source', 'version', 'width',
    ...optional.filter(key => record[key] !== undefined),
  ])
  if (record.contentType !== PREVIEW_WEBP_MIME) {
    throw new Error('invalid raster preview content type')
  }
  if (!isPositiveInteger(record.width) || !isPositiveInteger(record.height) ||
      record.width > profile.maxEdge || record.height > profile.maxEdge ||
      record.width * record.height > profile.maxPixels) {
    throw new Error('invalid raster preview dimensions')
  }
  if (!(record.raster instanceof Uint8Array) || record.raster.length === 0 ||
      record.raster.length > profile.maxRasterBytes || !isWebP(record.raster)) {
    throw new Error('invalid raster preview bytes')
  }
  let durationMs: number | undefined
  if (record.kind === 'video-poster') {
    requireDuration(record.durationMs, profile)
    durationMs = record.durationMs
  } else if (record.durationMs !== undefined) {
    throw new Error('duration is not valid for this preview kind')
  }
  if (record.blurHash !== undefined &&
      (typeof record.blurHash !== 'string' || record.blurHash.length < 6 ||
       record.blurHash.length > 128 || !/^[\x21-\x7e]+$/u.test(record.blurHash))) {
    throw new Error('invalid preview blur hash')
  }
  return {
    version: 1,
    kind: record.kind,
    contentType: PREVIEW_WEBP_MIME,
    width: record.width,
    height: record.height,
    raster: record.raster,
    source,
    ...(durationMs !== undefined ? { durationMs } : {}),
    ...(record.blurHash !== undefined ? { blurHash: record.blurHash } : {}),
  }
}

export function encodeAudioWaveformV1(samples: Uint8Array): Uint8Array {
  if (samples.length === 0 || samples.length > 0xffff) {
    throw new Error('invalid waveform sample count')
  }
  const output = new Uint8Array(WAVEFORM_MAGIC.length + 2 + samples.length)
  output.set(WAVEFORM_MAGIC)
  new DataView(output.buffer).setUint16(WAVEFORM_MAGIC.length, samples.length, false)
  output.set(samples, WAVEFORM_MAGIC.length + 2)
  return output
}

export function decodeAudioWaveformV1(bytes: Uint8Array, expectedSamples?: number): Uint8Array {
  if (bytes.length < WAVEFORM_MAGIC.length + 3 ||
      !WAVEFORM_MAGIC.every((byte, index) => bytes[index] === byte)) {
    throw new Error('invalid waveform encoding')
  }
  const count = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    .getUint16(WAVEFORM_MAGIC.length, false)
  if (count === 0 || bytes.length !== WAVEFORM_MAGIC.length + 2 + count ||
      (expectedSamples !== undefined && count !== expectedSamples)) {
    throw new Error('invalid waveform sample count')
  }
  return bytes.slice(WAVEFORM_MAGIC.length + 2)
}

function validateSource(value: unknown, product: PreviewProduct): PreviewSourceV1 {
  const source = objectRecord(value, 'preview source')
  requireExactKeys(source, [
    'contentRevision', 'objectId', 'product',
    ...(source.ciphertextSha256 !== undefined ? ['ciphertextSha256'] : []),
  ])
  if (source.product !== product || typeof source.objectId !== 'string' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u
        .test(source.objectId) || !isPositiveInteger(source.contentRevision)) {
    throw new Error('invalid preview source')
  }
  if (source.ciphertextSha256 !== undefined &&
      (typeof source.ciphertextSha256 !== 'string' ||
       !/^[0-9a-f]{64}$/u.test(source.ciphertextSha256))) {
    throw new Error('invalid preview source digest')
  }
  if (product === 'chat' && source.ciphertextSha256 === undefined) {
    throw new Error('Chat preview source digest is required')
  }
  return {
    product,
    objectId: source.objectId,
    contentRevision: source.contentRevision,
    ...(source.ciphertextSha256 !== undefined
      ? { ciphertextSha256: source.ciphertextSha256 }
      : {}),
  }
}

function requireDuration(value: unknown, profile: PreviewProfileV1): asserts value is number {
  if (!isPositiveInteger(value) || value > profile.maxDurationMs) {
    throw new Error('invalid preview duration')
  }
}

function requireExactKeys(record: Record<string, unknown>, expected: string[]): void {
  const actual = Object.keys(record).sort()
  const canonicalExpected = [...expected].sort()
  if (actual.length !== canonicalExpected.length ||
      actual.some((key, index) => key !== canonicalExpected[index])) {
    throw new Error('preview manifest has unknown or missing fields')
  }
}

function objectRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`invalid ${label}`)
  }
  return value as Record<string, unknown>
}

function isPositiveInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) > 0
}

function isRasterKind(value: string): value is RasterPreviewKind {
  return value === 'image' || value === 'video-poster' ||
    value === 'pdf-page' || value === 'office-page'
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
