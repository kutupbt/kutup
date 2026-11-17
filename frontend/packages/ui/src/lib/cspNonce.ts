/**
 * The page's style nonce, for `<style>` elements that reach the page as
 * markup rather than through `createElement` (which gives them the nonce
 * itself: frontend/packages/config/src/styleNonce.ts): mermaid's SVG, the
 * Mail reader's frame document. nginx writes it into
 * `<meta name="csp-nonce">` for each page response
 * (docs/content-security-policy.md). Undefined without one, or with the
 * page as built (the Vite dev server, which sends no policy; its
 * placeholder has underscores, which a nonce, base64 or hex, never does).
 */
export function styleNonce(doc: Document = document): string | undefined {
  const nonce = doc.querySelector('meta[name="csp-nonce"]')?.getAttribute('content')
  return nonce && /^[A-Za-z0-9+/=-]{16,}$/.test(nonce) ? nonce : undefined
}
