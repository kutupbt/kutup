// Live preview for Markdown notes, as Obsidian's: the note stays editable
// Markdown, but away from the cursor it reads as the note. On every line the
// selection does not touch, the marks hide (# ** _ ~~ == ` and a link's
// (target)), bullets become dots, tasks real checkboxes (clickable), quotes
// a bar, rules a line, pictures show, and links to Kutup items become chips.
// The line being edited shows its Markdown, so nothing is out of reach.

import { syntaxTree } from '@codemirror/language'
import { StateEffect, type EditorState, type Extension, type Range } from '@codemirror/state'
import { Decoration, EditorView, ViewPlugin, WidgetType, type DecorationSet, type ViewUpdate } from '@codemirror/view'

export interface LivePreviewConfig {
  /** A picture's blob: URL (a note's own `kutup:asset/…`, a Drive `kutup:file/…`, or a web URL as is). */
  resolveImage: (src: string) => Promise<string | null>
  /** What a Kutup link points to, as this reader sees it; undefined when not (yet) known. */
  describeLink: (href: string) => { name: string; folder: boolean } | undefined
  /** Opens a link: a Kutup item where it opens, a web link in a new tab. */
  openLink: (href: string) => void
  readOnly: boolean
  /** Labels for the widgets (accessibility). */
  labels: { noAccess: string; task: string }
}

/** Redraw (the link lookup finished loading, say). */
export const refreshLivePreview = StateEffect.define<null>()

const KUTUP_LINK = /^kutup:(file|folder)\/[0-9a-fA-F-]{36}$/

class BulletWidget extends WidgetType {
  eq() {
    return true
  }
  toDOM() {
    const el = document.createElement('span')
    el.className = 'cm-lp-bullet'
    el.textContent = '•'
    return el
  }
}

class CheckboxWidget extends WidgetType {
  constructor(readonly checked: boolean, readonly at: number, readonly readOnly: boolean, readonly label: string) {
    super()
  }
  eq(other: CheckboxWidget) {
    return other.checked === this.checked && other.at === this.at && other.readOnly === this.readOnly
  }
  toDOM(view: EditorView) {
    const box = document.createElement('input')
    box.type = 'checkbox'
    box.className = 'cm-lp-task'
    box.checked = this.checked
    box.disabled = this.readOnly
    box.setAttribute('aria-label', this.label)
    box.addEventListener('mousedown', (e) => e.preventDefault())
    box.addEventListener('click', (e) => {
      e.preventDefault()
      if (this.readOnly) return
      // `[ ]` ↔ `[x]`: the character between the brackets.
      view.dispatch({ changes: { from: this.at + 1, to: this.at + 2, insert: this.checked ? ' ' : 'x' }, userEvent: 'input' })
    })
    return box
  }
  ignoreEvent() {
    return true
  }
}

class RuleWidget extends WidgetType {
  eq() {
    return true
  }
  toDOM() {
    const el = document.createElement('span')
    el.className = 'cm-lp-rule'
    return el
  }
}

class ImageWidget extends WidgetType {
  constructor(readonly src: string, readonly alt: string, readonly resolve: (src: string) => Promise<string | null>) {
    super()
  }
  eq(other: ImageWidget) {
    return other.src === this.src && other.alt === this.alt
  }
  toDOM() {
    const wrap = document.createElement('span')
    wrap.className = 'cm-lp-image cm-lp-image-pending'
    const img = document.createElement('img')
    img.alt = this.alt
    void this.resolve(this.src).then((url) => {
      if (url) {
        img.src = url
        wrap.classList.remove('cm-lp-image-pending')
      } else {
        wrap.classList.remove('cm-lp-image-pending')
        wrap.classList.add('cm-lp-image-missing')
        wrap.textContent = this.alt || '🖼'
      }
    })
    wrap.appendChild(img)
    return wrap
  }
  ignoreEvent() {
    return false
  }
}

class LinkChipWidget extends WidgetType {
  constructor(
    readonly href: string,
    readonly text: string,
    readonly info: { name: string; folder: boolean } | undefined,
    readonly open: (href: string) => void,
    readonly noAccess: string,
  ) {
    super()
  }
  eq(other: LinkChipWidget) {
    return other.href === this.href && other.text === this.text && other.info?.name === this.info?.name
  }
  toDOM() {
    const chip = document.createElement('span')
    chip.className = 'cm-lp-chip' + (this.info ? (this.info.folder ? ' cm-lp-chip-folder' : ' cm-lp-chip-file') : ' cm-lp-chip-missing')
    chip.textContent = this.info?.name ?? this.text
    if (!this.info) chip.title = this.noAccess
    chip.addEventListener('mousedown', (e) => {
      // A click opens it; the cursor stays where it was.
      e.preventDefault()
      if (this.info) this.open(this.href)
    })
    return chip
  }
  ignoreEvent() {
    return true
  }
}

/** Line numbers any selection range touches: they show their Markdown. */
function activeLines(state: EditorState): Set<number> {
  const lines = new Set<number>()
  for (const r of state.selection.ranges) {
    const first = state.doc.lineAt(r.from).number
    const last = state.doc.lineAt(r.to).number
    for (let n = first; n <= last; n++) lines.add(n)
  }
  return lines
}

const hide = Decoration.replace({})
const quoteLine = Decoration.line({ class: 'cm-lp-quote' })
const highlightMark = Decoration.mark({ class: 'cm-lp-highlight' })
const HIGHLIGHT = /==(?=\S)([^=\n]+?)(?<=\S)==/g

function build(view: EditorView, config: LivePreviewConfig): DecorationSet {
  const { state } = view
  const active = activeLines(state)
  const on = (pos: number) => active.has(state.doc.lineAt(pos).number)
  const decos: Range<Decoration>[] = []
  const quoteLines = new Set<number>()
  const codeRanges: [number, number][] = []

  const hideMark = (from: number, to: number) => {
    if (to > from) decos.push(hide.range(from, to))
  }

  for (const { from, to } of view.visibleRanges) {
    syntaxTree(state).iterate({
      from,
      to,
      enter: (node) => {
        const name = node.name
        if (name === 'FencedCode' || name === 'CodeBlock') {
          codeRanges.push([node.from, node.to])
          return false
        }
        if (name === 'InlineCode') codeRanges.push([node.from, node.to])
        if (name === 'Blockquote') {
          const first = state.doc.lineAt(node.from).number
          const last = state.doc.lineAt(node.to).number
          for (let n = first; n <= last; n++) quoteLines.add(n)
        }
        if (on(node.from)) return
        switch (name) {
          case 'HeaderMark': {
            // The #s and the space after them.
            const after = state.sliceDoc(node.to, node.to + 1) === ' ' ? 1 : 0
            hideMark(node.from, node.to + after)
            return
          }
          case 'EmphasisMark':
          case 'StrikethroughMark':
            hideMark(node.from, node.to)
            return
          case 'CodeMark':
            // Inline code's backticks only; fences stay (they are code's frame).
            if (node.node.parent?.name === 'InlineCode') hideMark(node.from, node.to)
            return
          case 'QuoteMark': {
            const after = state.sliceDoc(node.to, node.to + 1) === ' ' ? 1 : 0
            hideMark(node.from, node.to + after)
            return
          }
          case 'HorizontalRule':
            decos.push(Decoration.replace({ widget: new RuleWidget() }).range(node.from, node.to))
            return
          case 'ListMark': {
            const item = node.node.parent
            const task = item?.getChild('Task')
            const after = state.sliceDoc(node.to, node.to + 1) === ' ' ? 1 : 0
            if (task) {
              // A task's checkbox is its bullet.
              hideMark(node.from, node.to + after)
            } else if (item?.parent?.name === 'BulletList') {
              decos.push(Decoration.replace({ widget: new BulletWidget() }).range(node.from, node.to))
            }
            return
          }
          case 'Image': {
            const url = node.node.getChild('URL')
            if (!url) return
            const src = state.sliceDoc(url.from, url.to)
            const raw = state.sliceDoc(node.from, node.to)
            const alt = raw.slice(2, Math.max(2, raw.indexOf('](')))
            decos.push(Decoration.replace({ widget: new ImageWidget(src, alt, config.resolveImage) }).range(node.from, node.to))
            return false
          }
          case 'Link': {
            const url = node.node.getChild('URL')
            const marks = node.node.getChildren('LinkMark')
            if (!url || marks.length < 2) return
            const href = state.sliceDoc(url.from, url.to)
            if (KUTUP_LINK.test(href)) {
              const text = state.sliceDoc(marks[0].to, marks[1].from)
              decos.push(
                Decoration.replace({
                  widget: new LinkChipWidget(href, text, config.describeLink(href), config.openLink, config.labels.noAccess),
                }).range(node.from, node.to),
              )
              return false
            }
            // A web link: its text, in the link colour; the target hides.
            hideMark(marks[0].from, marks[0].to)
            hideMark(marks[1].from, node.to)
            decos.push(Decoration.mark({ class: 'cm-lp-link', attributes: { 'data-href': href } }).range(marks[0].to, marks[1].from))
            return false
          }
        }
      },
    })
  }

  // Tasks: a checkbox in place of `[ ]` (hidden only while the cursor is in it).
  for (const { from, to } of view.visibleRanges) {
    syntaxTree(state).iterate({
      from,
      to,
      enter: (node) => {
        if (node.name !== 'TaskMarker') return
        const inside = state.selection.ranges.some((r) => r.from <= node.to && r.to >= node.from)
        if (inside) return
        const checked = /x/i.test(state.sliceDoc(node.from, node.to))
        decos.push(
          Decoration.replace({ widget: new CheckboxWidget(checked, node.from, config.readOnly, config.labels.task) }).range(node.from, node.to),
        )
      },
    })
  }

  // Quotes: a bar beside every line of one.
  for (const n of quoteLines) {
    const line = state.doc.line(n)
    if (line.from >= view.viewport.from && line.from <= view.viewport.to) decos.push(quoteLine.range(line.from))
  }

  // ==highlights== (not a Markdown node): outside code, marks hidden off the cursor's line.
  const inCode = (pos: number) => codeRanges.some(([a, b]) => pos >= a && pos < b)
  for (const { from, to } of view.visibleRanges) {
    const text = state.sliceDoc(from, to)
    for (const m of text.matchAll(HIGHLIGHT)) {
      const start = from + m.index
      const end = start + m[0].length
      if (inCode(start)) continue
      if (!on(start)) {
        hideMark(start, start + 2)
        hideMark(end - 2, end)
      }
      decos.push(highlightMark.range(start + 2, end - 2))
    }
  }

  return Decoration.set(decos, true)
}

const theme = EditorView.theme({
  '.cm-lp-bullet': { display: 'inline-block', width: '1em', color: 'var(--color-muted-foreground)', textAlign: 'center', fontWeight: '700' },
  '.cm-lp-task': {
    width: '0.95em', height: '0.95em', margin: '0 0.4em 0 0.05em', verticalAlign: '-0.1em',
    accentColor: 'var(--color-primary)', cursor: 'pointer',
  },
  '.cm-lp-task:disabled': { cursor: 'default' },
  '.cm-line.cm-lp-quote': { borderLeft: '3px solid var(--color-border)', paddingLeft: '0.9em', color: 'var(--color-muted-foreground)' },
  '.cm-lp-rule': { display: 'inline-block', width: '100%', height: '0', verticalAlign: 'middle', borderTop: '1px solid var(--color-border)' },
  '.cm-lp-image': { display: 'block', margin: '0.35em 0' },
  '.cm-lp-image img': { display: 'block', maxWidth: '100%', maxHeight: '480px', borderRadius: '0.375rem' },
  '.cm-lp-image-pending': {
    width: '100%', maxWidth: '24rem', aspectRatio: '4 / 3', borderRadius: '0.375rem', backgroundColor: 'var(--color-muted)',
  },
  '.cm-lp-image-missing': {
    display: 'inline-block', padding: '0.1em 0.5em', border: '1px dashed var(--color-border)', borderRadius: '0.375rem',
    color: 'var(--color-muted-foreground)', fontSize: '0.9em',
  },
  '.cm-lp-chip': {
    display: 'inline-flex', alignItems: 'center', gap: '0.3em', padding: '0 0.45em',
    border: '1px solid var(--color-border)', borderRadius: '0.375rem', backgroundColor: 'var(--color-muted)', cursor: 'pointer',
  },
  '.cm-lp-chip::before': {
    content: '""', width: '0.85em', height: '0.85em', flexShrink: '0', backgroundColor: 'var(--color-primary)',
    mask: "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z'/%3E%3Cpath d='M14 2v4a2 2 0 0 0 2 2h4'/%3E%3C/svg%3E\") center / contain no-repeat",
    WebkitMask: "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z'/%3E%3Cpath d='M14 2v4a2 2 0 0 0 2 2h4'/%3E%3C/svg%3E\") center / contain no-repeat",
  },
  '.cm-lp-chip-folder::before': {
    mask: "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z'/%3E%3C/svg%3E\") center / contain no-repeat",
    WebkitMask: "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z'/%3E%3C/svg%3E\") center / contain no-repeat",
  },
  '.cm-lp-chip:hover': { borderColor: 'var(--color-primary)' },
  '.cm-lp-chip-missing': { borderStyle: 'dashed', backgroundColor: 'transparent', color: 'var(--color-muted-foreground)', cursor: 'default' },
  '.cm-lp-chip-missing::before': { backgroundColor: 'var(--color-muted-foreground)' },
  '.cm-lp-link': { color: 'var(--color-primary)', textDecoration: 'underline', textUnderlineOffset: '2px', cursor: 'text' },
  '.cm-lp-highlight': { backgroundColor: 'color-mix(in oklab, #facc15 45%, transparent)', borderRadius: '0.2em' },
})

/** Live preview for a Markdown note (Obsidian's default editing mode). */
export function livePreview(config: LivePreviewConfig): Extension {
  const plugin = ViewPlugin.fromClass(
    class {
      decorations: DecorationSet
      constructor(view: EditorView) {
        this.decorations = build(view, config)
      }
      update(u: ViewUpdate) {
        if (
          u.docChanged || u.viewportChanged || u.selectionSet ||
          syntaxTree(u.startState) !== syntaxTree(u.state) ||
          u.transactions.some((tr) => tr.effects.some((e) => e.is(refreshLivePreview)))
        ) {
          this.decorations = build(u.view, config)
        }
      }
    },
    {
      decorations: (p) => p.decorations,
      eventHandlers: {
        // Ctrl/Cmd+click on a web link's text opens it.
        mousedown(event) {
          const target = event.target as HTMLElement | null
          const link = target?.closest?.('.cm-lp-link') as HTMLElement | null
          if (!link || !(event.metaKey || event.ctrlKey)) return false
          const href = link.getAttribute('data-href')
          if (!href) return false
          event.preventDefault()
          config.openLink(href)
          return true
        },
      },
    },
  )
  return [plugin, theme]
}
