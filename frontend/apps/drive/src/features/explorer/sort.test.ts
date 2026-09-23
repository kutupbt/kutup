import { describe, expect, it } from 'vitest'
import { fileKind } from './kinds'
import { DEFAULT_SORT, filterItems, sortItems, type ExplorerItem } from './sort'

const item = (type: 'folder' | 'file', name: string, modifiedAt: string, size: number | null = null): ExplorerItem => ({
  type, id: name, name, kind: type === 'folder' ? 'folder' : fileKind(name), size, modifiedAt,
})

const items = [
  item('file', 'report 10.docx', '2026-09-20T10:00:00Z', 5000),
  item('folder', 'Photos', '2026-09-22T10:00:00Z'),
  item('file', 'report 2.docx', '2026-09-23T09:00:00Z', 900),
  item('file', 'notes.md', '2026-09-01T10:00:00Z', 20),
  item('folder', 'Archive', '2026-01-01T10:00:00Z'),
]
const names = (list: ExplorerItem[]) => list.map((i) => i.name)

describe('sortItems', () => {
  it('defaults to newest modified first with folders and files mixed', () => {
    expect(names(sortItems(items, DEFAULT_SORT, 'en'))).toEqual([
      'report 2.docx', 'Photos', 'report 10.docx', 'notes.md', 'Archive',
    ])
  })

  it('sorts names naturally and case-insensitively', () => {
    expect(names(sortItems(items, { ...DEFAULT_SORT, field: 'name', dir: 'asc' }, 'en'))).toEqual([
      'Archive', 'notes.md', 'Photos', 'report 2.docx', 'report 10.docx',
    ])
  })

  it('keeps folders first when asked, whatever the sort', () => {
    expect(names(sortItems(items, { ...DEFAULT_SORT, foldersFirst: true }, 'en'))).toEqual([
      'Photos', 'Archive', 'report 2.docx', 'report 10.docx', 'notes.md',
    ])
  })

  it('puts folders at the small end by size, and ties on name', () => {
    expect(names(sortItems(items, { ...DEFAULT_SORT, field: 'size', dir: 'asc' }, 'en'))).toEqual([
      'Archive', 'Photos', 'notes.md', 'report 2.docx', 'report 10.docx',
    ])
  })

  it('uses the locale for names (Turkish dotted/dotless i)', () => {
    const tr = [item('file', 'ılık.txt', '2026-01-01T00:00:00Z', 1), item('file', 'ilk.txt', '2026-01-01T00:00:00Z', 1)]
    expect(names(sortItems(tr, { ...DEFAULT_SORT, field: 'name', dir: 'asc' }, 'tr'))).toEqual(['ılık.txt', 'ilk.txt'])
  })
})

describe('filterItems / fileKind', () => {
  it('filters by kind, keeping everything when nothing is selected', () => {
    expect(filterItems(items, new Set())).toHaveLength(5)
    expect(names(filterItems(items, new Set(['folder'])))).toEqual(['Photos', 'Archive'])
    expect(names(filterItems(items, new Set(['document', 'note'])))).toEqual(['report 10.docx', 'report 2.docx', 'notes.md'])
  })

  it('prefers the extension and falls back to the MIME type', () => {
    expect(fileKind('board.excalidraw', 'application/json')).toBe('whiteboard')
    expect(fileKind('scan', 'application/pdf')).toBe('pdf')
    expect(fileKind('IMG_001', 'image/jpeg')).toBe('image')
    expect(fileKind('blob', 'application/octet-stream')).toBe('other')
  })
})
