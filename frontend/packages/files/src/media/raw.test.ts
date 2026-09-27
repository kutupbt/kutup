// @vitest-environment node
import { readFile } from 'node:fs/promises'
import { describe, expect, it } from 'vitest'
import { extractRawPreview, isRawName } from './raw'

async function blob(name: string): Promise<Blob> {
  return new Blob([await readFile(new URL(`./fixtures/${name}`, import.meta.url))])
}

async function jpegSize(preview: Blob): Promise<[number, number]> {
  // SOF0: height at +5, width at +7.
  const bytes = new Uint8Array(await preview.arrayBuffer())
  for (let i = 2; i < bytes.length; ) {
    const marker = bytes[i + 1]!
    if (marker === 0xc0 || marker === 0xc2) return [(bytes[i + 7]! << 8) | bytes[i + 8]!, (bytes[i + 5]! << 8) | bytes[i + 6]!]
    i += 2 + ((bytes[i + 2]! << 8) | bytes[i + 3]!)
  }
  throw new Error('no SOF')
}

describe('RAW previews', () => {
  it("takes a TIFF-based RAW's largest decodable JPEG, with its orientation", async () => {
    const preview = await extractRawPreview(await blob('fake.dng'))
    expect(preview?.orientation).toBe(6)
    // The 640×480 strip in the SubIFD, not the 160×120 thumbnail nor the larger lossless strip.
    expect(await jpegSize(preview!.jpeg)).toEqual([640, 480])
  })

  it("follows a Fujifilm RAF's header", async () => {
    const preview = await extractRawPreview(await blob('fake.raf'))
    expect(await jpegSize(preview!.jpeg)).toEqual([640, 480])
  })

  it('finds nothing where there is nothing', async () => {
    expect(await extractRawPreview(new Blob([new Uint8Array(64)]))).toBeNull()
    expect(await extractRawPreview(await blob('clip.mp4'))).toBeNull()
  })

  it('knows RAW names', () => {
    expect(isRawName('IMG_1.CR3')).toBe(true)
    expect(isRawName('a.dng')).toBe(true)
    expect(isRawName('a.jpg')).toBe(false)
  })
})
