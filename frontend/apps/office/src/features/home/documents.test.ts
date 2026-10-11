// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { documentKindOf, newDocument } from '@kutup/drive-core/documents'
import type { DriveFile, Folder } from '@kutup/drive-core/model'
import { filterDocuments, sortDocuments, type DocumentEntry } from './documents'

function entry(name: string, updatedAt: string): DocumentEntry {
  return {
    folder: { id: 'f', source: 'owned' } as Folder,
    file: { id: name, name, updatedAt } as DriveFile,
    kind: documentKindOf(name)!,
    owner: null,
    sharer: null,
    href: '',
  }
}

describe('documents', () => {
  it('tells the five kinds apart by extension and ignores everything else', () => {
    expect(['a.md', 'a.DOCX', 'a.xlsx', 'a.pptx', 'a.excalidraw', 'a.pdf', 'a', null].map(documentKindOf)).toEqual([
      'note', 'document', 'spreadsheet', 'presentation', 'whiteboard', null, null, null,
    ])
  })

  it('starts each kind as its editor expects', async () => {
    expect(await newDocument('note', 'Plans', []).text()).toBe('# Plans\n\n')
    expect(newDocument('document', 'Untitled', ['untitled.docx']).name).toBe('Untitled (1).docx')
    expect(newDocument('presentation', 'Untitled', []).size).toBe(1)
    expect(JSON.parse(await newDocument('whiteboard', 'Board', []).text())).toMatchObject({ type: 'excalidraw' })
  })

  it('lists the most recently changed first, or by name, within one kind and a search', () => {
    const all = [entry('Budget.xlsx', '2026-10-01T00:00:00Z'), entry('notes.md', '2026-10-03T00:00:00Z'), entry('Budget 2.xlsx', '2026-10-02T00:00:00Z')]
    expect(sortDocuments(all, 'recent', 'en').map((d) => d.file.name)).toEqual(['notes.md', 'Budget 2.xlsx', 'Budget.xlsx'])
    expect(sortDocuments(all, 'name', 'en').map((d) => d.file.name)).toEqual(['Budget 2.xlsx', 'Budget.xlsx', 'notes.md'])
    expect(filterDocuments(all, 'spreadsheet', '', 'en')).toHaveLength(2)
    expect(filterDocuments(all, null, 'BUDGET 2', 'en').map((d) => d.file.name)).toEqual(['Budget 2.xlsx'])
  })
})
