// Pasting into Markdown notes, as Obsidian does:
//
// - a URL pasted over selected text makes that text a link to it;
// - rich text (from a web page, Google Docs, Word…) arrives as Markdown:
//   headings, lists, tasks, tables, links, emphasis, quotes and code keep
//   their shape instead of flattening into plain text.
//
// Plain text still pastes as plain text: into code blocks, with
// Ctrl/Cmd+Shift+V, and when the "rich" text is only styled spans (what code
// editors put on the clipboard).

import { syntaxTree } from '@codemirror/language'
import { EditorSelection, type EditorState } from '@codemirror/state'
import type { EditorView } from '@codemirror/view'
import { gfm } from '@joplin/turndown-plugin-gfm'
import TurndownService from 'turndown'

/** One link and nothing else: a web or mail address, or a Kutup item. */
export function isLinkTarget(text: string): boolean {
  const t = text.trim()
  if (!t || /\s/.test(t) || t.length > 2048) return false
  if (/^kutup:(file|folder)\/[0-9a-fA-F-]{36}$/.test(t)) return true
  try {
    const url = new URL(t)
    return url.protocol === 'http:' || url.protocol === 'https:' || url.protocol === 'mailto:'
  } catch {
    return false
  }
}

/** A link's Markdown: the selected text (brackets escaped) to `target`. */
export function linkMarkdown(text: string, target: string): string {
  return `[${text.replace(/([\\[\]])/g, '\\$1')}](${target.trim()})`
}

/** Rich text worth converting: it has structure, not just styled spans. */
export function hasStructure(html: string): boolean {
  return /<(h[1-6]|ul|ol|li|table|blockquote|pre|a\s|strong|b[\s>]|em|i[\s>]|s[\s>]|del|code|img|hr|p[\s>])/i.test(html)
}

let service: TurndownService | null = null

function turndown(): TurndownService {
  if (service) return service
  const td = new TurndownService({
    headingStyle: 'atx',
    codeBlockStyle: 'fenced',
    bulletListMarker: '-',
    emDelimiter: '_',
    strongDelimiter: '**',
    hr: '---',
  })
  td.use(gfm)
  td.remove(['script', 'style', 'noscript', 'iframe', 'object', 'embed', 'button', 'input', 'select', 'textarea', 'form', 'meta', 'link', 'title'])
  // List items as people write them (`- item`, `1. item`), not turndown's
  // `-   item`; what follows the first line is indented under the text.
  td.addRule('listItem', {
    filter: 'li',
    replacement: (content, node) => {
      const parent = node.parentNode as HTMLElement | null
      let prefix = '- '
      if (parent?.nodeName === 'OL') {
        const start = Number(parent.getAttribute('start') ?? '1') || 1
        prefix = `${start + Array.prototype.indexOf.call(parent.children, node)}. `
      }
      const body = content
        .replace(/^\n+/, '')
        .replace(/\n+$/, '\n')
        // A task's box then one space (the box and the text may each bring one).
        .replace(/^(\[[ xX]\]) +/, '$1 ')
        .replace(/\n/gm, '\n' + ' '.repeat(prefix.length))
      return prefix + body + (node.nextSibling && !body.endsWith('\n') ? '\n' : '')
    },
  })
  // Links: only web, mail and Kutup targets; anything else keeps its text.
  td.addRule('safeLinks', {
    filter: (node) => node.nodeName === 'A',
    replacement: (content, node) => {
      const href = (node as HTMLAnchorElement).getAttribute('href') ?? ''
      const text = content.trim()
      if (!text) return ''
      return /^(https?:|mailto:|kutup:)/i.test(href) ? linkMarkdown(text, href) : text
    },
  })
  // Pictures: web ones as Markdown images; embedded data: ones are dropped
  // (they would put megabytes into the note), leaving their description.
  td.addRule('images', {
    filter: 'img',
    replacement: (_content, node) => {
      const img = node as HTMLImageElement
      const src = img.getAttribute('src') ?? ''
      const alt = (img.getAttribute('alt') ?? '').replace(/[[\]]/g, '')
      return /^https?:/i.test(src) ? `![${alt}](${src})` : alt
    },
  })
  service = td
  return td
}

/**
 * Pasted HTML as Markdown. Parsed inert (DOMParser runs no scripts and loads
 * nothing); Google Docs' quirks are straightened first.
 */
export function htmlToMarkdown(html: string): string {
  const doc = new DOMParser().parseFromString(html, 'text/html')
  // Google Docs wraps everything in a <b style="font-weight:normal">, and
  // writes bold and italic as styled spans.
  for (const wrapper of doc.querySelectorAll('b[id^="docs-internal-guid"]')) wrapper.replaceWith(...wrapper.childNodes)
  for (const span of doc.querySelectorAll<HTMLElement>('span[style]')) {
    const weight = span.style.fontWeight
    const bold = weight === 'bold' || Number(weight) >= 600
    const italic = span.style.fontStyle === 'italic'
    if (!bold && !italic) continue
    let inner: Node = doc.createElement('span')
    ;(inner as HTMLElement).append(...span.childNodes)
    if (italic) {
      const em = doc.createElement('em')
      em.append(inner)
      inner = em
    }
    if (bold) {
      const strong = doc.createElement('strong')
      strong.append(inner)
      inner = strong
    }
    span.replaceWith(inner)
  }
  return turndown()
    .turndown(doc.body)
    .replace(/\n{3,}/g, '\n\n')
    .trim()
}

/** Whether `pos` is inside fenced or indented code (pastes stay as they are there). */
function inCode(state: EditorState, pos: number): boolean {
  const start = syntaxTree(state).resolveInner(pos, -1)
  for (let node: typeof start | null = start; node; node = node.parent) {
    if (node.name === 'FencedCode' || node.name === 'CodeBlock' || node.name === 'InlineCode') return true
  }
  return false
}

/** Blocks pasted after text start on a line of their own, after a blank one (Markdown needs it). */
function separated(state: EditorState, markdown: string): string {
  const at = state.selection.main.from
  const line = state.doc.lineAt(at)
  if (at > line.from && state.sliceDoc(line.from, at).trim()) return '\n\n' + markdown
  if (line.number > 1 && state.doc.line(line.number - 1).text.trim()) return '\n' + markdown
  return markdown
}

/**
 * A paste into a Markdown note, from its text and HTML flavours; true when
 * handled here (otherwise it pastes as plain text, as usual).
 */
export function pasteMarkdown(view: EditorView, text: string, html: string, plain: boolean): boolean {
  const { state } = view
  if (inCode(state, state.selection.main.head)) return false
  // A URL over selected text: that text becomes a link.
  if (isLinkTarget(text) && state.selection.ranges.some((r) => !r.empty)) {
    const tr = state.changeByRange((range) => {
      if (range.empty) return { range }
      const insert = linkMarkdown(state.sliceDoc(range.from, range.to), text)
      return { changes: { from: range.from, to: range.to, insert }, range: EditorSelection.cursor(range.from + insert.length) }
    })
    view.dispatch(state.update(tr, { userEvent: 'input.paste', scrollIntoView: true }))
    return true
  }
  if (plain || !html || !hasStructure(html)) return false
  const markdown = htmlToMarkdown(html)
  if (!markdown) return false
  view.dispatch(state.replaceSelection(markdown.includes('\n') ? separated(state, markdown) : markdown), {
    userEvent: 'input.paste',
    scrollIntoView: true,
  })
  return true
}
