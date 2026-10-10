import { CompletionContext } from '@codemirror/autocomplete'
import { EditorState } from '@codemirror/state'
import { describe, expect, it } from 'vitest'
import type { Folder } from '@kutup/drive-core/model'
import { linkPicker } from './linkPicker'
import type { KutupItem } from './useKutupItems'

const folder = { id: 'f' } as Folder
const item = (id: string, name: string, kind: KutupItem['kind'], type: KutupItem['type'] = 'file'): KutupItem =>
  ({ type, id, name, kind, folder, where: 'My files' })
const items = [
  item('1', 'Trips', 'folder', 'folder'),
  item('2', 'Trip plan.md', 'note'),
  item('3', 'İstanbul sunset.png', 'image'),
  item('4', 'Budget.xlsx', 'spreadsheet'),
]
const pick = linkPicker({ items: () => Promise.resolve(items) })

async function optionsAt(doc: string) {
  const state = EditorState.create({ doc })
  const result = await pick(new CompletionContext(state, doc.length, false))
  return result ? { from: result.from, labels: result.options.map((o) => o.label) } : null
}

describe('linkPicker', () => {
  it('starts on [[ and matches names in the browser', async () => {
    expect(await optionsAt('see [[trip')).toEqual({ from: 6, labels: ['Trips', 'Trip plan.md'] })
    // Accents and the Turkish İ fold.
    expect((await optionsAt('[[istanbul'))?.labels).toEqual(['İstanbul sunset.png'])
  })

  it('offers everything before a word is typed', async () => {
    expect((await optionsAt('[['))?.labels).toHaveLength(4)
  })

  it('embeds only pictures after ![[', async () => {
    expect(await optionsAt('![[')).toEqual({ from: 3, labels: ['İstanbul sunset.png'] })
  })

  it('stays out of the way elsewhere', async () => {
    expect(await optionsAt('a [link] here')).toBeNull()
    expect(await optionsAt('[single')).toBeNull()
  })
})
