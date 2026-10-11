// Live preview for fenced code in a Markdown note: away from the cursor, a
// fenced block reads as it does in Read mode (highlighted by the same
// highlight.js grammars, with its title bar, numbered and marked lines and a
// copy button) instead of as fences around monospace text. Clicking it, or
// moving the cursor into it, shows its Markdown again.
//
// The block's lines are replaced by one widget, which CodeMirror only allows
// from a state field (a view plugin cannot hide line breaks).

import { syntaxTree } from '@codemirror/language'
import { EditorSelection, Prec, StateField, type EditorState, type Extension, type Range } from '@codemirror/state'
import { Decoration, EditorView, keymap, WidgetType, type DecorationSet } from '@codemirror/view'
import type { Element, ElementContent, Root } from 'hast'
import { common, createLowlight } from 'lowlight'
import { parseCodeMeta, rehypeCodeLines } from './markdown/codeBlocks'

// The grammars rehype-highlight uses for Read mode.
const lowlight = createLowlight(common)

export interface CodeBlockLabels {
  copy: string
  copied: string
}

/** hast property names as DOM attributes: `className` → `class`, `dataTitle` → `data-title`. */
function attributeName(name: string): string {
  if (name === 'className') return 'class'
  if (name.startsWith('data')) return name.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)
  return name
}

function toDom(node: ElementContent): Node {
  if (node.type === 'text') return document.createTextNode(node.value)
  if (node.type !== 'element') return document.createTextNode('')
  const el = document.createElement(node.tagName)
  for (const [name, value] of Object.entries(node.properties ?? {})) {
    if (value === undefined || value === null || value === false) continue
    el.setAttribute(attributeName(name), Array.isArray(value) ? value.join(' ') : String(value))
  }
  for (const child of node.children) el.append(toDom(child))
  return el
}

/** The block's <pre>, highlighted and lined as Read mode draws it. */
function renderPre(code: string, language: string | null, meta: string): { pre: Node; title: string | null } {
  const options = parseCodeMeta(meta)
  const known = language !== null && lowlight.registered(language)
  const highlighted = known ? lowlight.highlight(language, code).children : [{ type: 'text' as const, value: code }]
  const properties: Element['properties'] = {
    className: known ? ['hljs', `language-${language}`] : language ? [`language-${language}`] : [],
  }
  if (options.lineNumbers) properties.dataLineNumbers = 'true'
  if (options.highlight.size > 0) properties.dataHighlight = [...options.highlight].join(',')
  const codeEl: Element = { type: 'element', tagName: 'code', properties, children: highlighted as ElementContent[] }
  const preEl: Element = { type: 'element', tagName: 'pre', properties: options.title ? { className: ['has-title'] } : {}, children: [codeEl] }
  const tree: Root = { type: 'root', children: [preEl] }
  rehypeCodeLines()(tree)
  return { pre: toDom(preEl), title: options.title }
}

const COPY_ICON =
  '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect width="14" height="14" x="8" y="8" rx="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>'

class CodeBlockWidget extends WidgetType {
  constructor(
    readonly code: string,
    readonly language: string | null,
    readonly meta: string,
    readonly labels: CodeBlockLabels,
  ) {
    super()
  }

  // Not the position: typing above a block moves it, and redrawing every
  // block below on each keystroke would highlight them all again.
  eq(other: CodeBlockWidget) {
    return other.code === this.code && other.language === this.language && other.meta === this.meta
  }

  toDOM(view: EditorView) {
    const { pre, title } = renderPre(this.code, this.language, this.meta)
    const outer = document.createElement('div')
    outer.className = 'cm-lp-codeblock prose prose-sm max-w-none'
    const block = document.createElement('div')
    block.className = 'code-block'
    if (title) {
      const bar = document.createElement('div')
      bar.className = 'code-block-title'
      bar.textContent = title
      block.append(bar)
    }
    const body = document.createElement('div')
    body.className = 'code-block-body'
    body.append(pre)
    const copy = document.createElement('button')
    copy.type = 'button'
    copy.className = 'code-block-copy'
    copy.title = this.labels.copy
    copy.setAttribute('aria-label', this.labels.copy)
    copy.innerHTML = COPY_ICON
    copy.addEventListener('mousedown', (e) => e.preventDefault())
    copy.addEventListener('click', (e) => {
      e.preventDefault()
      e.stopPropagation()
      navigator.clipboard?.writeText(this.code).then(
        () => {
          copy.title = this.labels.copied
          copy.setAttribute('aria-label', this.labels.copied)
        },
        // No clipboard access: the code can still be selected in Read mode.
        () => undefined,
      )
    })
    body.append(copy)
    block.append(body)
    outer.append(block)
    // A click edits the block: its Markdown comes back with the cursor in it.
    outer.addEventListener('mousedown', (e) => {
      if ((e.target as HTMLElement).closest('.code-block-copy')) return
      e.preventDefault()
      // The block starts at its opening fence; the cursor goes to its first
      // line of code.
      const fence = view.state.doc.lineAt(view.posAtDOM(outer))
      const editAt = Math.min(fence.to + 1, view.state.doc.length)
      view.dispatch({ selection: { anchor: editAt }, scrollIntoView: true })
      view.focus()
    })
    return outer
  }

  ignoreEvent() {
    return true
  }
}

function build(state: EditorState, labels: CodeBlockLabels): DecorationSet {
  const decos: Range<Decoration>[] = []
  syntaxTree(state).iterate({
    enter: (node) => {
      if (node.name === 'Document') return
      // Only top-level fences are drawn; nothing inside a paragraph, list
      // or quote needs visiting.
      if (node.name !== 'FencedCode') return false
      const touched = state.selection.ranges.some((r) => r.from <= node.to && r.to >= node.from)
      if (touched) return false
      const open = state.doc.lineAt(node.from)
      const close = state.doc.lineAt(node.to)
      // Only a closed block that starts its own line (not one in a list or a
      // quote, whose prefixes belong to other lines' Markdown).
      const marks = node.node.getChildren('CodeMark')
      if (open.from !== node.from || close.number === open.number || marks.length < 2) return false
      // The info string is the language, then the options (codeBlocks.ts);
      // the parser hands over all of it as one node.
      const fence = node.node.getChild('CodeMark')
      const infoText = fence ? state.sliceDoc(fence.to, open.to).trim() : ''
      const space = infoText.search(/\s/)
      const language = (space < 0 ? infoText : infoText.slice(0, space)).toLowerCase() || null
      const meta = space < 0 ? '' : infoText.slice(space + 1)
      const text = node.node.getChild('CodeText')
      const code = text ? state.sliceDoc(text.from, text.to) : ''
      decos.push(
        Decoration.replace({ widget: new CodeBlockWidget(code, language, meta, labels), block: true }).range(open.from, close.to),
      )
      return false
    },
  })
  return Decoration.set(decos, true)
}

const theme = EditorView.theme({
  '.cm-lp-codeblock': { padding: '0.25em 0', cursor: 'text', fontFamily: 'var(--font-sans, system-ui, sans-serif)' },
  '.cm-lp-codeblock pre': { margin: '0' },
  '.cm-lp-codeblock .code-block-title': { marginTop: '0' },
})

/**
 * The drawn block next to the cursor's line, above it (`up`) or below it:
 * vertical motion would otherwise step over it as over one tall line.
 */
function adjacentBlock(blocks: DecorationSet, state: EditorState, up: boolean): { from: number; to: number } | null {
  const line = state.doc.lineAt(state.selection.main.head)
  let found: { from: number; to: number } | null = null
  blocks.between(Math.max(0, line.from - 1), Math.min(state.doc.length, line.to + 1), (from, to) => {
    if (up ? to === line.from - 1 : from === line.to + 1) found = { from, to }
  })
  return found
}

/** Fenced code away from the cursor, drawn as Read mode draws it. */
export function codeBlockPreview(labels: CodeBlockLabels): Extension {
  const field = StateField.define<DecorationSet>({
    create: (state) => build(state, labels),
    update(value, tr) {
      if (tr.docChanged || tr.selection || syntaxTree(tr.startState) !== syntaxTree(tr.state)) return build(tr.state, labels)
      return value
    },
    provide: (f) => EditorView.decorations.from(f),
  })
  // Arrowing onto a block opens it, on its nearest fence, as moving onto any
  // other line would.
  const enter = (up: boolean) => (view: EditorView) => {
    const { state } = view
    if (!state.selection.main.empty || state.selection.ranges.length > 1) return false
    const block = adjacentBlock(state.field(field), state, up)
    if (!block) return false
    // A wrapped line has several rows: only from the row next to the block
    // (the line's first row going up, its last going down) does the arrow
    // leave the line. Without layout (no coordinates) a line is one row.
    const head = state.selection.main.head
    const line = state.doc.lineAt(head)
    const here = view.coordsAtPos(head)
    const edge = view.coordsAtPos(up ? line.from : line.to)
    if (here && edge && Math.abs(here.top - edge.top) > 2) return false
    const at = up ? state.doc.lineAt(block.to).from : block.from
    view.dispatch({ selection: EditorSelection.cursor(at), scrollIntoView: true, userEvent: 'select' })
    return true
  }
  return [field, theme, Prec.high(keymap.of([{ key: 'ArrowUp', run: enter(true) }, { key: 'ArrowDown', run: enter(false) }]))]
}
