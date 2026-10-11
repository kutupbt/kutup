import { describe, expect, it } from 'vitest'
import { editorKindFor, extensionOf, opensInOffice } from './editorKind'

describe('editorKindFor', () => {
  it('sends notes and code to the text editor', () => {
    expect(editorKindFor('Notes.md')).toBe('text')
    expect(editorKindFor('main.RS')).toBe('text')
    expect(editorKindFor('Dockerfile')).toBe('text')
  })

  it('sends office documents and whiteboards to their editors', () => {
    expect(editorKindFor('Plan.docx')).toBe('office')
    expect(editorKindFor('Budget.xlsx')).toBe('office')
    expect(editorKindFor('Board.excalidraw')).toBe('whiteboard')
  })

  it('leaves pictures, including SVG, and unknown types to viewers or download', () => {
    expect(editorKindFor('logo.svg')).toBeNull()
    expect(editorKindFor('photo.jpg')).toBeNull()
    expect(editorKindFor('archive.tar.gz')).toBeNull()
    expect(editorKindFor('README')).toBeNull()
  })
})

describe('extensionOf', () => {
  it('takes the last extension, or the whole name when there is none', () => {
    expect(extensionOf('a.b.TXT')).toBe('txt')
    expect(extensionOf('Makefile')).toBe('makefile')
  })
})

describe('opensInOffice', () => {
  it('is true for what is edited, and PDFs', () => {
    for (const name of ['Notes.md', 'main.rs', 'Report.docx', 'Scan.PDF', 'Plan.excalidraw']) expect(opensInOffice(name), name).toBe(true)
  })

  it('is false for photos, media and other files', () => {
    for (const name of ['photo.jpg', 'clip.mp4', 'Report.doc', 'Trip.kutupmap']) expect(opensInOffice(name), name).toBe(false)
  })
})
