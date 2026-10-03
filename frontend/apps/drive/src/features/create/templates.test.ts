// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { newDocumentFile, uniqueName } from './templates'

describe('new documents', () => {
  it('pick the first free name, case-insensitively', () => {
    expect(uniqueName('Untitled', 'docx', [])).toBe('Untitled.docx')
    expect(uniqueName('Untitled', 'docx', ['untitled.DOCX', 'Untitled (1).docx'])).toBe('Untitled (2).docx')
  })

  it('start notes with their title and office files with a placeholder', async () => {
    const note = newDocumentFile('note', 'Plans', [])
    expect(note.name).toBe('Plans.md')
    expect(note.type).toBe('text/markdown')
    expect(await note.text()).toBe('# Plans\n\n')
    const doc = newDocumentFile('spreadsheet', 'Untitled', [])
    expect(doc.name).toBe('Untitled.xlsx')
    expect(doc.size).toBe(1)
    const board = newDocumentFile('whiteboard', 'Untitled', [])
    expect(JSON.parse(await board.text())).toMatchObject({ type: 'excalidraw', elements: [] })
  })
})
