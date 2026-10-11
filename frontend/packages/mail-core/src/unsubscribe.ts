// A mailing list's ways out (RFC 2369 `List-Unsubscribe`, RFC 8058
// `List-Unsubscribe-Post`), read from the opened message's own headers:
// stored mail is encrypted, so only the reader can see them. As Proton's
// UnsubscribeMethods: one click (the server sends it), a web page, or an
// email.

export interface UnsubscribeMethods {
  /** An https URL that takes RFC 8058's one-click POST. */
  oneClick?: string
  /** An https URL that explains how to unsubscribe. */
  http?: string
  mailto?: { to: string; subject: string; body: string }
}

/** The header fields of `raw`, unfolded, lowercased names (the first of each). */
function headers(raw: Uint8Array): Map<string, string> {
  const text = new TextDecoder().decode(raw.subarray(0, Math.min(raw.length, 256 * 1024)))
  const end = text.search(/\r?\n\r?\n/)
  const head = (end >= 0 ? text.slice(0, end) : text).replace(/\r?\n[ \t]+/g, ' ')
  const fields = new Map<string, string>()
  for (const line of head.split(/\r?\n/)) {
    const colon = line.indexOf(':')
    if (colon <= 0) continue
    const name = line.slice(0, colon).trim().toLowerCase()
    if (!fields.has(name)) fields.set(name, line.slice(colon + 1).trim())
  }
  return fields
}

/** The ways out a message offers, or `null` when it is not from a list. */
export function unsubscribeMethods(raw: Uint8Array): UnsubscribeMethods | null {
  const fields = headers(raw)
  const value = fields.get('list-unsubscribe')
  if (!value) return null
  const methods: UnsubscribeMethods = {}
  const oneClick = /List-Unsubscribe=One-Click/i.test(fields.get('list-unsubscribe-post') ?? '')
  for (const [, target] of value.matchAll(/<([^>]+)>/g)) {
    const uri = target.trim()
    if (/^https:\/\//i.test(uri) && !methods.http) {
      try {
        const url = new URL(uri).href
        methods.http = url
        if (oneClick) methods.oneClick = url
      } catch {
        // Not a URL: skipped.
      }
    } else if (/^mailto:/i.test(uri) && !methods.mailto) {
      const [address, query = ''] = uri.slice(7).split('?')
      const params = new URLSearchParams(query)
      const to = decodeURIComponent(address ?? '').trim()
      if (/^[^@\s]+@[^@\s]+$/.test(to)) {
        methods.mailto = { to, subject: params.get('subject') || 'Unsubscribe', body: params.get('body') || 'Please, unsubscribe me' }
      }
    }
  }
  return methods.http || methods.mailto ? methods : null
}
