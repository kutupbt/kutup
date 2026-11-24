// Links in an event's location and description (Proton's `useUrlifyString`
// and `urlify`). The text is untrusted (a shared calendar's, an import's), so
// it is never read as HTML: it is cut into plain pieces and links, and React
// writes each as text. Only http, https and mailto links are made (Proton's
// also take ftps, file, tel and sms; Kutup leaves those as text).

/** Proton's `URL_REGEX`, with Kutup's schemes. */
const URL = /\b(?:https?:\/\/|mailto:)(?:(?!["<>^`{|}])\S)+/gi

export type Piece = { kind: 'text'; text: string } | { kind: 'link'; text: string; href: string }

/**
 * Punctuation that ends a sentence rather than the address: a trailing
 * full stop, comma and the like, and a closing bracket with no opening one
 * in the address (Proton keeps them; a link that 404s is worse).
 */
function trimEnd(match: string): string {
  let end = match.length
  for (;;) {
    const last = match[end - 1]
    if (last && '.,;:!?\'"'.includes(last)) end -= 1
    else if (last === ')' && (match.slice(0, end).match(/\(/g)?.length ?? 0) < (match.slice(0, end).match(/\)/g)?.length ?? 0)) end -= 1
    else break
  }
  return match.slice(0, end)
}

/** Whether `href` parses as an http, https or mailto address (the browser's own reading). */
function safeHref(href: string): boolean {
  try {
    const url = new globalThis.URL(href)
    if (url.protocol === 'mailto:') return url.pathname.length > 0
    return (url.protocol === 'http:' || url.protocol === 'https:') && url.hostname.length > 0
  } catch {
    return false
  }
}

/** `text` cut into plain pieces and links. */
export function linkify(text: string): Piece[] {
  const pieces: Piece[] = []
  let at = 0
  const push = (piece: string) => {
    if (!piece) return
    const last = pieces.at(-1)
    if (last?.kind === 'text') last.text += piece
    else pieces.push({ kind: 'text', text: piece })
  }
  for (const found of text.matchAll(URL)) {
    const start = found.index
    const href = trimEnd(found[0])
    push(text.slice(at, start))
    if (safeHref(href)) pieces.push({ kind: 'link', text: href, href })
    else push(href)
    at = start + href.length
  }
  push(text.slice(at))
  return pieces
}
