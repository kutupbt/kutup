import type { Mailbox } from '@kutup/mail-core/mime'
import { parseRecipients } from './recipients'

/** What a `mailto:` link (RFC 6068) asks to write. */
export interface Mailto {
  to: Mailbox[]
  cc: Mailbox[]
  bcc: Mailbox[]
  subject: string
  body: string
}

/** The hash a mailto link reaches Kutup Mail with (`#mailto=mailto:…`), as Proton's handler uses. */
export const MAILTO_HASH = '#mailto='

const decode = (value: string) => {
  try {
    return decodeURIComponent(value.replace(/\+/g, '%20'))
  } catch {
    return value
  }
}

/** A `mailto:` URL, raw or encoded once (as the browser hands it over), read into fields. */
export function parseMailto(link: string): Mailto | null {
  let url = link.trim()
  if (/^mailto%3a/i.test(url)) url = decode(url)
  if (!/^mailto:/i.test(url)) return null
  const rest = url.slice('mailto:'.length)
  const split = rest.search(/[?]/)
  const toPart = decode(split === -1 ? rest : rest.slice(0, split))
  const params = new URLSearchParams(split === -1 ? '' : rest.slice(split + 1))
  const field = (name: string) => [...params.entries()].filter(([key]) => key.toLowerCase() === name).map(([, value]) => value)
  return {
    to: parseRecipients([toPart, ...field('to')].filter(Boolean).join(',')),
    cc: parseRecipients(field('cc').join(',')),
    bcc: parseRecipients(field('bcc').join(',')),
    subject: field('subject')[0] ?? '',
    body: field('body')[0] ?? '',
  }
}

/** Asks the browser to open mailto links in Kutup Mail (Proton's "default email application"). */
export function registerMailtoHandler(origin = window.location.origin): boolean {
  if (!('registerProtocolHandler' in navigator)) return false
  navigator.registerProtocolHandler('mailto', `${origin}/${MAILTO_HASH}%s`)
  return true
}
