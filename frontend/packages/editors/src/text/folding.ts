// Folding for Markdown notes, as in Obsidian: an arrow just left of every
// line that folds (a heading's section, a list item, a code block, a quote,
// a table), shown on hover and kept while folded; a folded range shows as a
// small "…" pill that unfolds on click. Ctrl/Cmd+Shift+[ and ] fold and
// unfold at the cursor, Ctrl/Cmd+Alt+[ and ] everything.

import { codeFolding, foldable, foldedRanges, foldEffect, foldKeymap, unfoldEffect } from '@codemirror/language'
import { RangeSetBuilder, type EditorState, type Extension } from '@codemirror/state'
import { Decoration, EditorView, keymap, ViewPlugin, WidgetType, type DecorationSet, type ViewUpdate } from '@codemirror/view'

/** The folded range starting at the end of `line`, if any. */
function foldedAt(state: EditorState, lineTo: number): { from: number; to: number } | null {
  let found: { from: number; to: number } | null = null
  foldedRanges(state).between(lineTo, lineTo, (from, to) => {
    if (from === lineTo) found = { from, to }
  })
  return found
}

class FoldArrow extends WidgetType {
  constructor(readonly folded: boolean, readonly lineFrom: number) {
    super()
  }
  eq(other: FoldArrow) {
    return other.folded === this.folded && other.lineFrom === this.lineFrom
  }
  toDOM(view: EditorView) {
    const arrow = document.createElement('span')
    arrow.className = 'cm-fold-arrow' + (this.folded ? ' cm-fold-arrow-folded' : '')
    arrow.setAttribute('aria-hidden', 'true')
    arrow.addEventListener('mousedown', (event) => {
      event.preventDefault()
      const line = view.state.doc.lineAt(this.lineFrom)
      const folded = foldedAt(view.state, line.to)
      if (folded) {
        view.dispatch({ effects: unfoldEffect.of(folded) })
      } else {
        const range = foldable(view.state, line.from, line.to)
        if (range) view.dispatch({ effects: foldEffect.of(range) })
      }
    })
    return arrow
  }
  ignoreEvent() {
    return true
  }
}

function arrows(view: EditorView): DecorationSet {
  const builder = new RangeSetBuilder<Decoration>()
  for (const { from, to } of view.visibleRanges) {
    for (let pos = from; pos <= to; ) {
      const line = view.state.doc.lineAt(pos)
      const folded = foldedAt(view.state, line.to) !== null
      if (folded || (line.length > 0 && foldable(view.state, line.from, line.to))) {
        builder.add(line.from, line.from, Decoration.widget({ widget: new FoldArrow(folded, line.from), side: -1 }))
      }
      pos = line.to + 1
    }
  }
  return builder.finish()
}

const arrowPlugin = ViewPlugin.fromClass(
  class {
    decorations: DecorationSet
    constructor(view: EditorView) {
      this.decorations = arrows(view)
    }
    update(u: ViewUpdate) {
      // Folding and unfolding arrive as effects.
      if (u.docChanged || u.viewportChanged || u.transactions.some((tr) => tr.effects.length > 0)) {
        this.decorations = arrows(u.view)
      }
    }
  },
  { decorations: (p) => p.decorations },
)

const theme = EditorView.theme({
  '.cm-line': { position: 'relative' },
  '.cm-fold-arrow': {
    position: 'absolute',
    left: '-1.35em',
    top: '0.35em',
    width: '0.9em',
    height: '0.9em',
    cursor: 'pointer',
    opacity: '0',
    transition: 'opacity 120ms, transform 120ms',
    backgroundColor: 'var(--color-muted-foreground)',
    // A chevron, drawn with a mask so it takes the text colour.
    mask: "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2.5' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E\") center / contain no-repeat",
    WebkitMask: "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2.5' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E\") center / contain no-repeat",
  },
  '.cm-line:hover .cm-fold-arrow': { opacity: '0.7' },
  '.cm-fold-arrow:hover': { opacity: '1 !important', backgroundColor: 'var(--color-foreground)' },
  '.cm-fold-arrow-folded': { opacity: '0.7', transform: 'rotate(-90deg)' },
  '.cm-foldPlaceholder': {
    margin: '0 0.3em',
    padding: '0 0.45em',
    border: '1px solid var(--color-border)',
    borderRadius: '999px',
    backgroundColor: 'var(--color-muted)',
    color: 'var(--color-muted-foreground)',
    fontSize: '0.85em',
    cursor: 'pointer',
  },
  '.cm-foldPlaceholder:hover': { color: 'var(--color-foreground)', borderColor: 'var(--color-primary)' },
})

/** Folding for Markdown notes; `unfoldLabel` titles the "…" pill. */
export function noteFolding(unfoldLabel: string): Extension {
  return [
    codeFolding({
      placeholderDOM: (_view, onclick) => {
        const pill = document.createElement('span')
        pill.className = 'cm-foldPlaceholder'
        pill.textContent = '…'
        pill.title = unfoldLabel
        pill.setAttribute('aria-label', unfoldLabel)
        pill.onclick = onclick
        return pill
      },
    }),
    arrowPlugin,
    keymap.of(foldKeymap),
    theme,
  ]
}
