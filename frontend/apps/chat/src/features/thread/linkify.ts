export type TextPart = { kind: 'text'; value: string } | { kind: 'link'; value: string; href: string }

// http(s) URLs and bare www. addresses; trailing punctuation stays text.
const URL_PATTERN = /\b(?:https?:\/\/|www\.)[^\s<>"']+/giu
const TRAILING = /[.,;:!?)\]}'"»]+$/u

/**
 * Split message text into plain runs and links. Only http(s) links are
 * made clickable (a `javascript:` or `data:` text stays text), and each
 * opens in a new tab without the page as opener.
 */
export function linkify(text: string): TextPart[] {
  const parts: TextPart[] = []
  let last = 0
  for (const match of text.matchAll(URL_PATTERN)) {
    const start = match.index ?? 0
    let raw = match[0]
    const trailing = raw.match(TRAILING)?.[0] ?? ''
    if (trailing) raw = raw.slice(0, -trailing.length)
    if (!raw) continue
    const href = raw.toLowerCase().startsWith('www.') ? `https://${raw}` : raw
    try {
      const url = new URL(href)
      if (url.protocol !== 'http:' && url.protocol !== 'https:') continue
    } catch {
      continue
    }
    if (start > last) parts.push({ kind: 'text', value: text.slice(last, start) })
    parts.push({ kind: 'link', value: raw, href })
    last = start + raw.length
  }
  if (last < text.length) parts.push({ kind: 'text', value: text.slice(last) })
  return parts
}
