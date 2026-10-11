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

/** What a line can be: a heading, a list item, a task, a quote, or plain text. */
export type LineStyle = 'h1' | 'h2' | 'h3' | 'h4' | 'h5' | 'h6' | 'bullet' | 'number' | 'task' | 'quote' | 'body'

/** A line's leading marker (after its indentation), whatever it is. */
const LINE_MARK = /^(\s*)(#{1,6}\s+|[-*+]\s+\[[ xX]\]\s+|[-*+]\s+|\d{1,9}[.)]\s+|>\s?)?/

function styleOf(mark: string | undefined): LineStyle {
  if (!mark) return 'body'
  const heading = /^(#{1,6})\s/.exec(mark)
  if (heading) return `h${heading[1].length}` as LineStyle
  if (/^[-*+]\s+\[/.test(mark)) return 'task'
  if (/^[-*+]/.test(mark)) return 'bullet'
  if (/^\d/.test(mark)) return 'number'
  return 'quote'
}

function markFor(style: LineStyle, n: number): string {
  if (style === 'body') return ''
  if (style === 'bullet') return '- '
  if (style === 'number') return `${n}. `
  if (style === 'task') return '- [ ] '
  if (style === 'quote') return '> '
  return '#'.repeat(Number(style.slice(1))) + ' '
}

/**
 * Makes every selected line `style` (a heading level, a list, a quote), in
 * place of whatever marker it had; when they all already are, back to
 * plain text. Numbered lists count up.
 */
export function setLineStyle(style: LineStyle): StateCommand {
  return ({ state, dispatch }) => {
    const lines = new Set<number>()
    for (const r of state.selection.ranges) {
      for (let n = state.doc.lineAt(r.from).number; n <= state.doc.lineAt(r.to).number; n++) lines.add(n)
    }
    const numbers = [...lines].sort((a, b) => a - b)
    const all = numbers.every((n) => styleOf(LINE_MARK.exec(state.doc.line(n).text)?.[2]) === style)
    const target: LineStyle = all ? 'body' : style
    const changes = numbers.map((n, i) => {
      const line = state.doc.line(n)
      const m = LINE_MARK.exec(line.text)!
      const indent = m[1] ?? ''
      return { from: line.from + indent.length, to: line.from + m[0].length, insert: markFor(target, i + 1) }
    })
    dispatch(state.update({ changes, scrollIntoView: true, userEvent: 'input' }))
    return true
  }
}

/**
 * Puts `block` on lines of its own at the cursor (after the current line
 * when it has text), with the cursor `cursorAt` characters into it.
 */
export function insertBlock(block: string, cursorAt: number = block.length): StateCommand {
  return ({ state, dispatch }) => {
    const head = state.selection.main.head
    const line = state.doc.lineAt(head)
    const empty = line.text.trim() === ''
    // An empty line takes the block; otherwise it goes on the next line.
    const from = empty ? line.from : line.to
    const lead = empty ? '' : '\n'
    dispatch(state.update({
      changes: { from, to: line.to, insert: lead + block },
      selection: { anchor: from + lead.length + cursorAt },
      scrollIntoView: true,
      userEvent: 'input',
    }))
    return true
  }
}

export const INSERTS = {
  table: { block: '| Column 1 | Column 2 |\n| --- | --- |\n|  |  |', cursorAt: 2 },
  codeBlock: { block: '```\n\n```', cursorAt: 3 },
  rule: { block: '---\n', cursorAt: 4 },
  // The cursor lands on the callout's body line.
  callout: { block: '> [!note]\n> ', cursorAt: 12 },
  mathBlock: { block: '$$\n\n$$', cursorAt: 3 },
} as const

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
