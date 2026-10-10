// Live styling for Markdown notes in Edit mode (as Obsidian's live preview):
// the text stays editable Markdown, but reads like the note — headings sized,
// bold and italic shown, links in the accent colour, the marks (#, **, `)
// dimmed, inline code shaded, fenced code on a shaded monospace band. Colours
// come from Kutup's tokens, so it follows the theme; the code colours inside
// fences stay the editor theme's.

import { syntaxTree } from '@codemirror/language'
import { HighlightStyle, syntaxHighlighting } from '@codemirror/language'
import { Prec, RangeSetBuilder, type Extension } from '@codemirror/state'
import { Decoration, EditorView, ViewPlugin, type DecorationSet, type ViewUpdate } from '@codemirror/view'
import { tags } from '@lezer/highlight'

const MUTED = 'var(--color-muted-foreground)'
const TEXT = 'var(--color-foreground)'
const MONO = 'var(--font-mono, ui-monospace, monospace)'

const markdownStyle = HighlightStyle.define([
  // Headings in the text colour, not underlined (the base styles colour or
  // underline them as code tokens).
  { tag: tags.heading1, fontSize: '1.6em', fontWeight: '700', color: TEXT, textDecoration: 'none' },
  { tag: tags.heading2, fontSize: '1.35em', fontWeight: '700', color: TEXT, textDecoration: 'none' },
  { tag: tags.heading3, fontSize: '1.15em', fontWeight: '650', color: TEXT, textDecoration: 'none' },
  { tag: [tags.heading4, tags.heading5, tags.heading6], fontWeight: '650', color: TEXT, textDecoration: 'none' },
  { tag: tags.strong, fontWeight: '700' },
  { tag: tags.emphasis, fontStyle: 'italic' },
  { tag: tags.strikethrough, textDecoration: 'line-through' },
  { tag: tags.link, color: 'var(--color-primary)' },
  { tag: tags.url, color: MUTED },
  { tag: tags.quote, color: MUTED, fontStyle: 'italic' },
  { tag: tags.processingInstruction, color: MUTED, fontWeight: '400', fontStyle: 'normal' },
  { tag: tags.labelName, color: MUTED },
  { tag: tags.monospace, fontFamily: MONO },
  { tag: tags.contentSeparator, color: MUTED },
])

const codeLine = Decoration.line({ class: 'cm-md-codeblock' })
const inlineCode = Decoration.mark({ class: 'cm-md-inline-code' })

/** Shaded bands behind fenced (and indented) code, and inline code, in view. */
function codeDecorations(view: EditorView): DecorationSet {
  const builder = new RangeSetBuilder<Decoration>()
  const tree = syntaxTree(view.state)
  const lines = new Set<number>()
  const marks: [number, number][] = []
  for (const { from, to } of view.visibleRanges) {
    tree.iterate({
      from,
      to,
      enter: (node) => {
        if (node.name === 'FencedCode' || node.name === 'CodeBlock') {
          const first = view.state.doc.lineAt(node.from).number
          const last = view.state.doc.lineAt(node.to).number
          for (let n = first; n <= last; n++) lines.add(n)
          return false
        }
        if (node.name === 'InlineCode') marks.push([node.from, node.to])
      },
    })
  }
  // RangeSetBuilder wants ranges in order: lines and marks merged by position.
  const ranges: { from: number; to: number; deco: Decoration }[] = [
    ...[...lines].map((n) => {
      const at = view.state.doc.line(n).from
      return { from: at, to: at, deco: codeLine }
    }),
    ...marks.map(([from, to]) => ({ from, to, deco: inlineCode })),
  ].sort((a, b) => a.from - b.from || a.to - b.to)
  for (const r of ranges) builder.add(r.from, r.to, r.deco)
  return builder.finish()
}

const codePlugin = ViewPlugin.fromClass(
  class {
    decorations: DecorationSet
    constructor(view: EditorView) {
      this.decorations = codeDecorations(view)
    }
    update(update: ViewUpdate) {
      if (update.docChanged || update.viewportChanged || syntaxTree(update.startState) !== syntaxTree(update.state)) {
        this.decorations = codeDecorations(update.view)
      }
    }
  },
  { decorations: (plugin) => plugin.decorations },
)

const layout = EditorView.theme({
  '.cm-content': { fontFamily: 'var(--font-sans, system-ui, sans-serif)', lineHeight: '1.6' },
  '.cm-md-codeblock': { fontFamily: MONO, fontSize: '0.92em', backgroundColor: 'var(--color-muted)' },
  '.cm-md-inline-code': { backgroundColor: 'var(--color-muted)', borderRadius: '3px', padding: '0 2px' },
})

/** Markdown notes' Edit mode: the note's look, still as editable Markdown. */
export function liveMarkdown(): Extension {
  // Above the theme's own highlight style, so the dimmed marks win.
  return [Prec.high(syntaxHighlighting(markdownStyle)), codePlugin, layout]
}
