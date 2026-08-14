import { describe, expect, it } from 'vitest'
import { inspectRasterDimensions } from './imageDimensions'

describe('bounded raster dimension inspection', () => {
  it('reads PNG dimensions without decoding pixels', () => {
    const bytes = new Uint8Array(24)
    bytes.set(new TextEncoder().encode('IHDR'), 12)
    const view = new DataView(bytes.buffer)
    view.setUint32(16, 1200, false)
    view.setUint32(20, 800, false)
    expect(inspectRasterDimensions(bytes, 'image/png')).toEqual({ width: 1200, height: 800 })
  })

  it('reads GIF, BMP, lossless WebP, and JPEG dimensions', () => {
    const gif = new Uint8Array(10)
    new DataView(gif.buffer).setUint16(6, 320, true)
    new DataView(gif.buffer).setUint16(8, 200, true)
    expect(inspectRasterDimensions(gif, 'image/gif')).toEqual({ width: 320, height: 200 })

    const bmp = new Uint8Array(26)
    const bmpView = new DataView(bmp.buffer)
    bmpView.setUint32(14, 40, true)
    bmpView.setInt32(18, 640, true)
    bmpView.setInt32(22, -480, true)
    expect(inspectRasterDimensions(bmp, 'image/bmp')).toEqual({ width: 640, height: 480 })

    const webp = new Uint8Array(30)
    webp.set(new TextEncoder().encode('RIFF'), 0)
    webp.set(new TextEncoder().encode('WEBP'), 8)
    webp.set(new TextEncoder().encode('VP8X'), 12)
    webp[24] = 0xff
    webp[27] = 0x7f
    expect(inspectRasterDimensions(webp, 'image/webp')).toEqual({ width: 256, height: 128 })

    const jpeg = new Uint8Array([
      0xff, 0xd8,
      0xff, 0xc0, 0x00, 0x07, 0x08, 0x01, 0xe0, 0x02, 0x80,
    ])
    expect(inspectRasterDimensions(jpeg, 'image/jpeg')).toEqual({ width: 640, height: 480 })
  })

  it('fails closed for truncated, zero-sized, and unparsed AVIF headers', () => {
    expect(inspectRasterDimensions(new Uint8Array(10), 'image/png')).toBeNull()
    expect(inspectRasterDimensions(new Uint8Array(24), 'image/png')).toBeNull()
    expect(inspectRasterDimensions(new Uint8Array(32), 'image/avif')).toBeNull()
  })
})
