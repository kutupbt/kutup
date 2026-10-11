import { describe, expect, it } from 'vitest'
import { assetIdFromSrc, assetIdOf, imageMarkdown, imageTypeOf } from './noteImages'

describe('note images', () => {
  it('reads only the note’s own asset links', () => {
    expect(assetIdFromSrc('kutup:asset/img-abc123')).toBe('img-abc123')
    expect(assetIdFromSrc('kutup:asset/../etc')).toBeNull()
    expect(assetIdFromSrc('https://example.org/a.png')).toBeNull()
    expect(assetIdFromSrc(undefined)).toBeNull()
  })

  it('writes the file name as the alt text', () => {
    expect(imageMarkdown('Screenshot 2026-09-28.png', 'img-1')).toBe('![Screenshot 2026-09-28](kutup:asset/img-1)')
    expect(imageMarkdown('[x].png', 'img-1')).toBe('![x](kutup:asset/img-1)')
    expect(imageMarkdown('', 'img-1')).toBe('![image](kutup:asset/img-1)')
  })

  it('names an image by its content', async () => {
    const a = await assetIdOf(new Uint8Array([1, 2, 3]))
    expect(a).toMatch(/^img-[0-9a-f]{64}$/)
    expect(await assetIdOf(new Uint8Array([1, 2, 3]))).toBe(a)
    expect(await assetIdOf(new Uint8Array([1, 2, 4]))).not.toBe(a)
  })

  it('knows pictures by their signature, and nothing else', () => {
    expect(imageTypeOf(new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a]))).toBe('image/png')
    expect(imageTypeOf(new Uint8Array([0xff, 0xd8, 0xff, 0xe0]))).toBe('image/jpeg')
    expect(imageTypeOf(new TextEncoder().encode('GIF89a'))).toBe('image/gif')
    expect(imageTypeOf(new TextEncoder().encode('RIFF\0\0\0\0WEBPVP8 '))).toBe('image/webp')
    expect(imageTypeOf(new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg">'))).toBeNull()
  })
})
