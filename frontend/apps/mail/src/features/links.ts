// Where a link in a message goes (Proton's useLinkHandler, LinkConfirmationModal).

/** Bidi controls that can make a URL read as another one (Proton's rtlSanitize, SEC-574). */
const BIDI = /[‎‏‪-‮⁦-⁩]/g

/** The URL as the browser will open it: host in punycode, no bidi controls. */
export function shownUrl(href: string): string {
  try {
    return new URL(href).href.replace(BIDI, '')
  } catch {
    return href.replace(BIDI, '')
  }
}

/** Whether `href` leads outside Kutup's own sites (this domain and its subdomains). */
export function leadsOutside(href: string, here: string = window.location.hostname): boolean {
  let host: string
  try {
    const url = new URL(href)
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return false
    host = url.hostname.toLowerCase()
  } catch {
    return false
  }
  // The app runs on <app>.<domain>: the domain and its subdomains are Kutup's.
  const parts = here.toLowerCase().split('.')
  const domain = parts.length > 2 ? parts.slice(1).join('.') : here.toLowerCase()
  return host !== domain && !host.endsWith(`.${domain}`)
}
