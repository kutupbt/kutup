// Formatting shortcuts for Markdown notes: bold, italic, inline code and
// links, each toggling (a second press on formatted text takes the marks
// off), for every selection at once.

import { EditorSelection, type StateCommand } from '@codemirror/state'
import type { EditorView, KeyBinding } from '@codemirror/view'
import { openLinkPicker } from './links/linkPicker'
import { insertNewlineContinueMarkup, deleteMarkupBackward } from '@codemirror/lang-markdown'

/** Wraps each selection in `marker`, or unwraps it when already wrapped. */
export function toggleWrap(marker: string): StateCommand {
  const m = marker.length
  return ({ state, dispatch }) => {
    const tr = state.changeByRange((range) => {
      const text = state.sliceDoc(range.from, range.to)
      // The marks just outside the selection (the usual case after a wrap).
      if (state.sliceDoc(range.from - m, range.from) === marker && state.sliceDoc(range.to, range.to + m) === marker) {
        return {
          changes: [
            { from: range.from - m, to: range.from },
            { from: range.to, to: range.to + m },
          ],
          range: EditorSelection.range(range.from - m, range.to - m),
        }
      }
      // The marks selected too.
      if (text.length >= m * 2 && text.startsWith(marker) && text.endsWith(marker)) {
        return {
          changes: { from: range.from, to: range.to, insert: text.slice(m, -m) },
          range: EditorSelection.range(range.from, range.to - m * 2),
        }
      }
      return {
        changes: [
          { from: range.from, insert: marker },
          { from: range.to, insert: marker },
        ],
        // Nothing selected: the cursor lands between the marks.
        range: EditorSelection.range(range.from + m, range.to + m),
      }
    })
    dispatch(state.update(tr, { scrollIntoView: true, userEvent: 'input' }))
    return true
  }
}

/** A link: the selection becomes its text and `url` is selected to type over. */
export const insertLink: StateCommand = ({ state, dispatch }) => {
  const tr = state.changeByRange((range) => {
    const text = state.sliceDoc(range.from, range.to)
    const insert = `[${text}](url)`
    // With text, select "url"; without, put the cursor inside the brackets.
    const range2 = text
      ? EditorSelection.range(range.from + text.length + 3, range.from + text.length + 6)
      : EditorSelection.cursor(range.from + 1)
    return { changes: { from: range.from, to: range.to, insert }, range: range2 }
  })
  dispatch(state.update(tr, { scrollIntoView: true, userEvent: 'input' }))
  return true
}

/** An item with nothing after its marker: `- `, `1. `, `- [ ] `, `> `. */
const EMPTY_ITEM = /^(\s*)(?:[-*+]|\d{1,9}[.)]|>)\s+(?:\[[ xX]\]\s*)?$|^(\s*)>\s*$/

/**
 * Enter in a list: continue it (CodeMirror's), but on an empty item end it
 * at once, as most editors do; a nested empty item moves up a level first.
 * (CodeMirror's own first makes the list loose, and ends it on a second Enter.)
 */
export const continueOrEndList: StateCommand = ({ state, dispatch }) => {
  const range = state.selection.main
  if (state.selection.ranges.length === 1 && range.empty) {
    const line = state.doc.lineAt(range.head)
    const empty = EMPTY_ITEM.exec(line.text)
    if (empty && range.head === line.to) {
      const indent = empty[1] ?? empty[2] ?? ''
      if (indent.length > 0) {
        // Up a level: two spaces (or a tab) less.
        const cut = indent.endsWith('\t') ? 1 : Math.min(2, indent.length)
        dispatch(state.update({ changes: { from: line.from, to: line.from + cut }, userEvent: 'delete' }))
      } else {
        dispatch(state.update({ changes: { from: line.from, to: line.to }, userEvent: 'delete' }))
      }
      return true
    }
  }
  return insertNewlineContinueMarkup({ state, dispatch })
}

/**
 * Notes' keys: the formatting shortcuts, and Enter / Backspace that continue
 * and end lists, task lists and quotes. Before the default keymap (which
 * uses Mod-i for selecting the parent syntax node).
 */
export const markdownNoteKeymap: KeyBinding[] = [
  { key: 'Mod-b', run: toggleWrap('**') },
  { key: 'Mod-i', run: toggleWrap('_') },
  { key: 'Mod-Shift-c', run: toggleWrap('`') },
  // A selection becomes a link's text; nothing selected picks a Kutup item.
  { key: 'Mod-k', run: (view: EditorView) => (view.state.selection.main.empty ? openLinkPicker(view) : insertLink(view)) },
  { key: 'Enter', run: continueOrEndList },
  { key: 'Backspace', run: deleteMarkupBackward },
]
