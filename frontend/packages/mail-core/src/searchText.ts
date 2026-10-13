// What body search indexes of a message (docs/plans/mail-body-search.md), as
// Proton's `cleanText`: its subject and its text, without styles, scripts,
// hidden elements or the quoted earlier message (a reply's quote would make
// every message of a thread match its first one's words).

const QUOTE = 'blockquote, .gmail_quote, .protonmail_quote, #divRplyFwdMsg, .moz-cite-prefix, [type="cite"]'
const BLOCKS = new Set(['P', 'DIV', 'BR', 'LI', 'TR', 'TD', 'TH', 'H1', 'H2', 'H3', 'H4', 'H5', 'H6', 'PRE', 'SECTION', 'ARTICLE', 'TABLE'])
/** The most text kept of one message. */
export const MAX_TEXT_CHARS = 100_000

function htmlText(html: string): string {
  const doc = new DOMParser().parseFromString(html.replace(/<!--[\s\S]*?-->/g, ''), 'text/html')
  doc.querySelectorAll('style, script, head, template, noscript').forEach((el) => el.remove())
  doc.querySelectorAll(QUOTE).forEach((el) => el.remove())
  doc.querySelectorAll<HTMLElement>('[style]').forEach((el) => {
    const style = (el.getAttribute('style') ?? '').replace(/\s/g, '').toLowerCase()
    if (style.includes('display:none') || style.includes('visibility:hidden')) el.remove()
  })
  doc.querySelectorAll('[hidden]').forEach((el) => el.remove())
  const out: string[] = []
  const walk = (node: Node) => {
    if (node.nodeType === Node.TEXT_NODE) {
      out.push(node.textContent ?? '')
      return
    }
    const block = node instanceof Element && BLOCKS.has(node.tagName)
    if (block) out.push('\n')
    node.childNodes.forEach(walk)
    if (block) out.push('\n')
  }
  walk(doc.body)
  return out.join('')
}

function plainText(text: string): string {
  // `>` lines are the quoted earlier message.
  return text
    .split('\n')
    .filter((line) => !line.trimStart().startsWith('>'))
    .join('\n')
}

/** The text body search indexes for a message. */
export function searchText(subject: string, body: { html?: string | null; text?: string | null }): string {
  const text = body.html ? htmlText(body.html) : plainText(body.text ?? '')
  return `${subject}\n${text}`.replace(/[ \t\r\f\v]+/g, ' ').replace(/\n\s*\n+/g, '\n').trim().slice(0, MAX_TEXT_CHARS)
}
