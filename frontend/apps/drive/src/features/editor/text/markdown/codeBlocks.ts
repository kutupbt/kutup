// Code-block options in a Markdown note, read from the fence's info string
// after the language, in the convention Docusaurus, rehype-pretty-code and
// Expressive Code share (GitHub ignores it, so the file still renders there):
//
//   ```python title="greet.py" showLineNumbers {2,4-6}
//
// - `title="…"`: a file-name bar above the block;
// - `showLineNumbers`: numbered lines;
// - `{2,4-6}`: those lines highlighted.
//
// remarkCodeMeta puts them on the <code> element as data attributes (the
// sanitizer lets exactly these through); rehypeCodeLines, after
// highlight.js, wraps each line in a span so lines can be numbered and
// marked. The copy button needs no option: every block has one.

import type { Element, ElementContent, Root as HastRoot, Text } from 'hast'
import type { Code, Root as MdastRoot } from 'mdast'
import { defaultSchema, type Options as SanitizeSchema } from 'rehype-sanitize'
import { visit } from 'unist-util-visit'

export interface CodeMeta {
  title: string | null
  lineNumbers: boolean
  /** 1-based line numbers to highlight. */
  highlight: Set<number>
}

const MAX_TITLE = 200
/** Ranges past this are ignored (a typo like {1-99999999} must not loop forever). */
const MAX_LINE = 100_000

/** The options in a fence's meta string (what follows the language). */
export function parseCodeMeta(meta: string | null | undefined): CodeMeta {
  const text = meta ?? ''
  const title = /\btitle=(?:"([^"]*)"|'([^']*)')/.exec(text)
  const ranges = /\{([\d\s,-]+)\}/.exec(text)
  return {
    title: title ? (title[1] ?? title[2] ?? '').slice(0, MAX_TITLE) || null : null,
    lineNumbers: /(?:^|\s)showLineNumbers(?=\s|$)/.test(text),
    highlight: ranges ? parseRanges(ranges[1]) : new Set(),
  }
}

function parseRanges(spec: string): Set<number> {
  const lines = new Set<number>()
  for (const part of spec.split(',')) {
    const m = /^\s*(\d+)(?:\s*-\s*(\d+))?\s*$/.exec(part)
    if (!m) continue
    const from = Number(m[1])
    const to = Math.min(Number(m[2] ?? m[1]), MAX_LINE)
    for (let n = from; n <= to; n++) if (n > 0) lines.add(n)
  }
  return lines
}

/** remark: a fenced block's options onto its <code> element. */
export function remarkCodeMeta() {
  return (tree: MdastRoot) => {
    visit(tree, 'code', (node: Code) => {
      const meta = parseCodeMeta(node.meta)
      const properties: Record<string, string> = {}
      if (meta.title) properties.dataTitle = meta.title
      if (meta.lineNumbers) properties.dataLineNumbers = 'true'
      if (meta.highlight.size > 0) properties.dataHighlight = [...meta.highlight].join(',')
      if (Object.keys(properties).length === 0) return
      node.data = { ...node.data, hProperties: { ...(node.data?.hProperties ?? {}), ...properties } }
    })
  }
}

/**
 * The default (GitHub) schema, plus exactly the code-block options and the
 * `kutup:` scheme (a note's own images, `kutup:asset/…`, and links to Kutup
 * items), which the preview resolves itself.
 */
export const sanitizeSchema: SanitizeSchema = {
  ...defaultSchema,
  protocols: {
    ...defaultSchema.protocols,
    src: [...(defaultSchema.protocols?.src ?? []), 'kutup'],
    href: [...(defaultSchema.protocols?.href ?? []), 'kutup'],
  },
  // Highlights (==text==) and callouts (callouts.ts).
  tagNames: [...(defaultSchema.tagNames ?? []), 'mark'],
  attributes: {
    ...defaultSchema.attributes,
    div: [...(defaultSchema.attributes?.div ?? []), ['className', /^callout(-[a-z]+)?$/], 'dataCallout'],
    code: [...(defaultSchema.attributes?.code ?? []), 'dataTitle', 'dataLineNumbers', 'dataHighlight'],
  },
}

/**
 * The block's content as lines: highlight.js's spans may run across line
 * breaks, so each line gets its own copy of the spans it sits in.
 */
function splitLines(children: ElementContent[]): ElementContent[][] {
  const lines: ElementContent[][] = [[]]
  const wrap = (text: Text, ancestors: Element[]): ElementContent =>
    ancestors.reduceRight<ElementContent>(
      (inner, a) => ({ type: 'element', tagName: a.tagName, properties: a.properties, children: [inner] }),
      text,
    )
  const walk = (nodes: ElementContent[], ancestors: Element[]) => {
    for (const node of nodes) {
      if (node.type === 'text') {
        node.value.split('\n').forEach((part, i) => {
          if (i > 0) lines.push([])
          if (part) lines[lines.length - 1].push(wrap({ type: 'text', value: part }, ancestors))
        })
      } else if (node.type === 'element') {
        walk(node.children, [...ancestors, node])
      }
    }
  }
  walk(children, [])
  // The newline that ends the block is not a line of its own.
  if (lines.length > 1 && lines[lines.length - 1].length === 0) lines.pop()
  return lines
}

/** rehype, after highlighting: numbered or marked blocks get one span per line. */
export function rehypeCodeLines() {
  return (tree: HastRoot) => {
    visit(tree, 'element', (node: Element, _index, parent) => {
      if (node.tagName !== 'code' || !parent || parent.type !== 'element' || parent.tagName !== 'pre') return
      const numbered = node.properties.dataLineNumbers !== undefined
      const marked = new Set(String(node.properties.dataHighlight ?? '').split(',').filter(Boolean).map(Number))
      if (!numbered && marked.size === 0) return
      node.children = splitLines(node.children).map((line, i) => ({
        type: 'element',
        tagName: 'span',
        properties: { className: marked.has(i + 1) ? ['code-line', 'highlighted'] : ['code-line'] },
        children: line,
      }))
    })
  }
}
