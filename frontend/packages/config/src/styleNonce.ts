/**
 * The style nonce (docs/content-security-policy.md). The apps' strict policy
 * allows a `<style>` element only with the page's nonce (`style-src 'self'
 * 'nonce-…'`), never inline styles in general. The frontend container's
 * nginx makes a fresh nonce for every page response, puts it in the policy
 * and writes it over [`CSP_NONCE_PLACEHOLDER`] in the page's
 * `<meta name="csp-nonce">` (frontend/docker/40-kutup-hosts.sh).
 *
 * The libraries the apps use (Radix's scroll lock, sonner, next-themes,
 * tiptap, CodeMirror, pdf.js, mermaid, emoji-mart, …) add their `<style>`
 * elements from script, most with no way to pass a nonce. [`styleNonce`],
 * run as a classic script before any module, makes every `<style>` element
 * script creates carry the page's nonce: what the policy keeps out is style
 * markup injected into the page (HTML parsing never calls createElement),
 * while the apps' own scripts, the only ones the policy lets run, may style
 * the page as they could anyway (CSSOM, constructed style sheets).
 *
 * Written without imports or outer names: the build serves this function's
 * source as `/kutup-style-nonce.js` ([`styleNonceScript`]).
 */
export function styleNonce(doc: Document): void {
  const meta = doc.querySelector('meta[name="csp-nonce"]')
  const nonce = meta ? meta.getAttribute('content') : null
  // No nonce, or the page as built (the Vite dev server, which sends no
  // policy; the placeholder has underscores, which a nonce, base64 or hex,
  // never does): nothing to do.
  if (!nonce || !/^[A-Za-z0-9+/=-]{16,}$/.test(nonce)) return
  // Document.prototype: every document of this window (the page, DOMParser
  // results), not just `doc`; a frame has a window, and prototypes, of its own.
  const proto = doc.defaultView ? doc.defaultView.Document.prototype : Document.prototype
  // Called below with the document they were called on as `this`.
  // eslint-disable-next-line @typescript-eslint/unbound-method
  const create = proto.createElement
  // eslint-disable-next-line @typescript-eslint/unbound-method
  const createNS = proto.createElementNS
  const mark = (element: Element) => {
    // `style` in HTML and SVG alike; both are style blocks the policy checks.
    if (element.localName === 'style') (element as HTMLStyleElement).nonce = nonce
    return element
  }
  proto.createElement = function (this: Document, ...args: Parameters<Document['createElement']>) {
    return mark(create.apply(this, args))
  } as Document['createElement']
  proto.createElementNS = function (this: Document, ...args: [string | null, string, (string | ElementCreationOptions)?]) {
    return mark(createNS.apply(this, args))
  } as Document['createElementNS']
}

/** What the built page holds until nginx writes the nonce over it. */
export const CSP_NONCE_PLACEHOLDER = '__KUTUP_CSP_NONCE__'

/** `/kutup-style-nonce.js`: [`styleNonce`] on the page's document. */
export function styleNonceScript(): string {
  return `(${styleNonce.toString()})(document);\n`
}
