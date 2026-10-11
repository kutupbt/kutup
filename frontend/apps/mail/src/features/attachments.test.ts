import { unzipSync } from 'fflate'
import { describe, expect, it } from 'vitest'
import { previewKind, zipAttachments } from './attachments'

describe('attachments', () => {
  it('preview images, PDFs, media and text, never HTML', () => {
    expect(previewKind({ mimeType: 'image/png', filename: 'a.png' })).toBe('image')
    expect(previewKind({ mimeType: 'application/x-pdf', filename: 'a.pdf' })).toBe('pdf')
    expect(previewKind({ mimeType: 'video/mp4', filename: 'a.mp4' })).toBe('video')
    expect(previewKind({ mimeType: 'text/plain', filename: 'a.txt' })).toBe('text')
    expect(previewKind({ mimeType: 'text/html', filename: 'a.html' })).toBeNull()
    expect(previewKind({ mimeType: 'application/zip', filename: 'a.zip' })).toBeNull()
  })

  it('zip every file once, names kept apart', () => {
    const bytes = (text: string) => new TextEncoder().encode(text)
    const zip = zipAttachments(
      [
        { filename: 'rapor.txt', content: bytes('1') },
        { filename: 'rapor.txt', content: bytes('2') },
        { filename: '../kaçak/yol.txt', content: bytes('3') },
        { filename: '', content: bytes('4') },
      ],
      'adsız',
    )
    const files = unzipSync(zip)
    expect(Object.keys(files).sort()).toEqual(['.._kaçak_yol.txt', 'adsız', 'rapor (1).txt', 'rapor.txt'])
    expect(new TextDecoder().decode(files['rapor (1).txt'])).toBe('2')
  })
})
