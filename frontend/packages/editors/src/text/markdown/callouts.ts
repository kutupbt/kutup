// Obsidian's Markdown extras, in the notes preview:
//
//   ==highlighted text==          a highlight (<mark>)
//
//   > [!warning] Custom title     a callout: a coloured box with an icon and
//   > Its body, any Markdown.     a title (the type's name when none is given)
//
// Callout types and their aliases are Obsidian's, so notes written there
// look the same here. Unknown types show as notes.

import type { Blockquote, Paragraph, PhrasingContent, Root, Text } from 'mdast'
import { SKIP, visit } from 'unist-util-visit'

export const CALLOUT_KINDS = [
  'note', 'abstract', 'info', 'todo', 'tip', 'success', 'question', 'warning', 'failure', 'danger', 'bug', 'example', 'quote',
] as const
export type CalloutKind = (typeof CALLOUT_KINDS)[number]

const ALIASES: Record<string, CalloutKind> = {
  summary: 'abstract', tldr: 'abstract',
  hint: 'tip', important: 'tip',
  check: 'success', done: 'success',
  help: 'question', faq: 'question',
  caution: 'warning', attention: 'warning',
  fail: 'failure', missing: 'failure',
  error: 'danger',
  cite: 'quote',
}

/** A callout type as written (`[!Warning]`) → its kind; unknown ones are notes. */
export function calloutKind(type: string): CalloutKind {
  const t = type.toLowerCase()
  if ((CALLOUT_KINDS as readonly string[]).includes(t)) return t as CalloutKind
  return ALIASES[t] ?? 'note'
}

const MARKER = /^\[!([A-Za-z-]{1,24})\]([+-]?)[ \t]*([^\n]*)(?:\n|$)/

/** remark: `> [!type] title` blockquotes become callouts. `label` names a kind that has no title. */
export function remarkCallouts(options: { label: (kind: CalloutKind) => string }) {
  return (tree: Root) => {
    visit(tree, 'blockquote', (node: Blockquote) => {
      const first = node.children[0]
      if (!first || first.type !== 'paragraph') return
      const lead = first.children[0]
      if (!lead || lead.type !== 'text') return
      const m = MARKER.exec(lead.value)
      if (!m) return
      const kind = calloutKind(m[1])
      const title = m[3].trim() || options.label(kind)
      lead.value = lead.value.slice(m[0].length)
      // The marker line goes, with the line break after it (remark-breaks
      // makes one); a paragraph left empty goes too.
      if (!lead.value) first.children.shift()
      if (first.children[0]?.type === 'break') first.children.shift()
      if (first.children.length === 0) node.children.shift()
      const titleNode: Paragraph = {
        type: 'paragraph',
        data: { hName: 'div', hProperties: { className: ['callout-title'], dataCallout: kind } },
        children: [{ type: 'text', value: title }],
      }
      node.children.unshift(titleNode)
      node.data = { ...node.data, hName: 'div', hProperties: { className: ['callout', `callout-${kind}`], dataCallout: kind } }
    })
  }
}

const HIGHLIGHT = /==(?=\S)([^=\n]+?)(?<=\S)==/g

/** remark: `==text==` becomes a highlight. Code is left alone (it is not text). */
export function remarkHighlight() {
  return (tree: Root) => {
    visit(tree, 'text', (node: Text, index, parent) => {
      if (!parent || index === undefined || !node.value.includes('==')) return
      const parts: PhrasingContent[] = []
      let last = 0
      for (const m of node.value.matchAll(HIGHLIGHT)) {
        if (m.index > last) parts.push({ type: 'text', value: node.value.slice(last, m.index) })
        // An element of its own: rendered as <mark>.
        parts.push({ type: 'emphasis', data: { hName: 'mark' }, children: [{ type: 'text', value: m[1] }] })
        last = m.index + m[0].length
      }
      if (parts.length === 0) return
      if (last < node.value.length) parts.push({ type: 'text', value: node.value.slice(last) })
      ;(parent.children as PhrasingContent[]).splice(index, 1, ...parts)
      return [SKIP, index + parts.length]
    })
  }
}
