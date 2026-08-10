export interface RasterDimensions {
  width: number
  height: number
}

export function inspectRasterDimensions(
  bytes: Uint8Array,
  mimeType: string,
): RasterDimensions | null {
  switch (mimeType) {
    case 'image/png':
      return pngDimensions(bytes)
    case 'image/gif':
      return gifDimensions(bytes)
    case 'image/jpeg':
      return jpegDimensions(bytes)
    case 'image/webp':
      return webpDimensions(bytes)
    case 'image/bmp':
      return bmpDimensions(bytes)
    default:
      // AVIF dimensions live in nested ISO-BMFF boxes. Rejecting it here is
      // safer than asking a browser decoder to allocate before we know bounds.
      return null
  }
}

function pngDimensions(bytes: Uint8Array): RasterDimensions | null {
  if (bytes.length < 24 || !asciiAt(bytes, 'IHDR', 12)) return null
  const view = dataView(bytes)
  return dimensions(view.getUint32(16, false), view.getUint32(20, false))
}

function gifDimensions(bytes: Uint8Array): RasterDimensions | null {
  if (bytes.length < 10) return null
  const view = dataView(bytes)
  return dimensions(view.getUint16(6, true), view.getUint16(8, true))
}

function bmpDimensions(bytes: Uint8Array): RasterDimensions | null {
  if (bytes.length < 26) return null
  const view = dataView(bytes)
  const dibSize = view.getUint32(14, true)
  if (dibSize === 12) {
    return dimensions(view.getUint16(18, true), view.getUint16(20, true))
  }
  if (bytes.length < 26 || dibSize < 40) return null
  const width = view.getInt32(18, true)
  const height = view.getInt32(22, true)
  return dimensions(Math.abs(width), Math.abs(height))
}

function jpegDimensions(bytes: Uint8Array): RasterDimensions | null {
  if (bytes.length < 4 || bytes[0] !== 0xff || bytes[1] !== 0xd8) return null
  let offset = 2
  while (offset + 3 < bytes.length) {
    while (offset < bytes.length && bytes[offset] === 0xff) offset += 1
    if (offset >= bytes.length) return null
    const marker = bytes[offset]
    offset += 1
    if (marker === 0xd8 || marker === 0xd9 || (marker >= 0xd0 && marker <= 0xd7)) continue
    if (offset + 2 > bytes.length) return null
    const length = (bytes[offset] << 8) | bytes[offset + 1]
    if (length < 2 || offset + length > bytes.length) return null
    if (isJpegStartOfFrame(marker)) {
      if (length < 7) return null
      const height = (bytes[offset + 3] << 8) | bytes[offset + 4]
      const width = (bytes[offset + 5] << 8) | bytes[offset + 6]
      return dimensions(width, height)
    }
    offset += length
  }
  return null
}

function webpDimensions(bytes: Uint8Array): RasterDimensions | null {
  if (bytes.length < 30 || !asciiAt(bytes, 'RIFF', 0) || !asciiAt(bytes, 'WEBP', 8)) return null
  const chunk = ascii(bytes.subarray(12, 16))
  if (chunk === 'VP8X') {
    return dimensions(readUint24LE(bytes, 24) + 1, readUint24LE(bytes, 27) + 1)
  }
  if (chunk === 'VP8L') {
    if (bytes.length < 25 || bytes[20] !== 0x2f) return null
    const b1 = bytes[21]
    const b2 = bytes[22]
    const b3 = bytes[23]
    const b4 = bytes[24]
    return dimensions(1 + (((b2 & 0x3f) << 8) | b1), 1 + (((b4 & 0x0f) << 10) | (b3 << 2) | (b2 >> 6)))
  }
  if (chunk === 'VP8 ') {
    if (bytes.length < 30 || bytes[23] !== 0x9d || bytes[24] !== 0x01 || bytes[25] !== 0x2a) return null
    return dimensions(
      (bytes[26] | (bytes[27] << 8)) & 0x3fff,
      (bytes[28] | (bytes[29] << 8)) & 0x3fff,
    )
  }
  return null
}

function dimensions(width: number, height: number): RasterDimensions | null {
  if (!Number.isSafeInteger(width) || !Number.isSafeInteger(height) || width < 1 || height < 1) {
    return null
  }
  return { width, height }
}

function isJpegStartOfFrame(marker: number): boolean {
  return (marker >= 0xc0 && marker <= 0xc3) ||
    (marker >= 0xc5 && marker <= 0xc7) ||
    (marker >= 0xc9 && marker <= 0xcb) ||
    (marker >= 0xcd && marker <= 0xcf)
}

function readUint24LE(bytes: Uint8Array, offset: number): number {
  return bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16)
}

function dataView(bytes: Uint8Array): DataView {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
}

function asciiAt(bytes: Uint8Array, value: string, offset: number): boolean {
  return ascii(bytes.subarray(offset, offset + value.length)) === value
}

function ascii(bytes: Uint8Array): string {
  return String.fromCharCode(...bytes)
}
