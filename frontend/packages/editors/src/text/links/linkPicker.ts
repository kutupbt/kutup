// The `[[` picker: typing `[[` in a Markdown note searches your Drive (in the
// browser, over names only you can read) and writes the chosen item as a
// Kutup link; `![[` embeds it instead (a picture shows in the note), as in
// Obsidian. Ctrl/Cmd+K with nothing selected opens it too.

import { startCompletion, type Completion, type CompletionContext, type CompletionResult } from '@codemirror/autocomplete'
import type { EditorView } from '@codemirror/view'
import { matches, terms } from '../../search'
import { kutupLinkMarkdown } from './kutupLinks'
import type { KutupItem } from './useKutupItems'

const MAX_OPTIONS = 30

export interface LinkPickerSource {
  /** The items, once loaded: asks for them the first time (they load on demand). */
  items: () => Promise<KutupItem[]>
}

function option(item: KutupItem, from: number, embed: boolean): Completion {
  return {
    label: item.name,
    detail: item.where,
    type: item.type === 'folder' ? 'folder' : 'file',
    apply: (view: EditorView, _completion: Completion, _from: number, to: number) => {
      // closeBrackets may have put `]]` after the cursor: they go too.
      const after = view.state.sliceDoc(to, to + 2) === ']]' ? to + 2 : to
      const insert = kutupLinkMarkdown(item.name, { type: item.type, id: item.id }, embed)
      view.dispatch({ changes: { from, to: after, insert }, selection: { anchor: from + insert.length }, userEvent: 'input.complete' })
    },
  }
}

export function linkPicker(source: LinkPickerSource) {
  return async (context: CompletionContext): Promise<CompletionResult | null> => {
    const before = context.matchBefore(/!?\[\[[^\]\n]{0,80}$/)
    if (!before) return null
    const embed = before.text.startsWith('!')
    const query = before.text.slice(embed ? 3 : 2)
    const items = await source.items()
    if (context.aborted) return null
    const words = terms(query)
    // Embeds are for pictures; links take anything.
    const pool = embed ? items.filter((i) => i.kind === 'image') : items
    const found = (words.length ? pool.filter((i) => matches(i.name, words)) : pool).slice(0, MAX_OPTIONS)
    return {
      from: before.from + (embed ? 3 : 2),
      options: found.map((item) => option(item, before.from, embed)),
      // Matched here, over names; CodeMirror's own fuzzy filter would re-rank.
      filter: false,
    }
  }
}

/** Ctrl/Cmd+K with nothing selected: start a `[[` pick at the cursor. */
export function openLinkPicker(view: EditorView): boolean {
  const at = view.state.selection.main.head
  view.dispatch({ changes: { from: at, insert: '[[' }, selection: { anchor: at + 2 }, userEvent: 'input' })
  startCompletion(view)
  return true
}
