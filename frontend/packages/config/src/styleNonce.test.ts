import { afterEach, describe, expect, it } from 'vitest'
import { CSP_NONCE_PLACEHOLDER, styleNonce, styleNonceScript } from './styleNonce'

const SVG = 'http://www.w3.org/2000/svg'
const NONCE = '0123456789abcdef0123456789abcdef'
// Put back after each test (the tests call them with the document as `this`).
// eslint-disable-next-line @typescript-eslint/unbound-method
const { createElement, createElementNS } = Document.prototype

/** The page's meta holding `nonce`, then the script's function run on it. */
function page(nonce: string | null) {
  if (nonce !== null) {
    const meta = document.createElement('meta')
    meta.name = 'csp-nonce'
    meta.content = nonce
    document.head.append(meta)
  }
  styleNonce(document)
}

const nonceOf = (element: Element) => (element as HTMLStyleElement).nonce

afterEach(() => {
  Document.prototype.createElement = createElement
  Document.prototype.createElementNS = createElementNS
  document.head.replaceChildren()
})

describe('styleNonce', () => {
  it('is served as its own source, run on the document', () => {
    expect(styleNonceScript()).toBe(`(${styleNonce.toString()})(document);\n`)
  })

  it('gives every <style> element script creates the page nonce, HTML and SVG', () => {
    page(NONCE)
    expect(nonceOf(document.createElement('style'))).toBe(NONCE)
    expect(nonceOf(document.createElement('STYLE'))).toBe(NONCE)
    expect(nonceOf(document.createElementNS(SVG, 'style'))).toBe(NONCE)
  })

  it('leaves other elements alone', () => {
    page(NONCE)
    expect(nonceOf(document.createElement('div'))).toBeFalsy()
    expect(nonceOf(document.createElement('script'))).toBeFalsy()
  })

  it('does nothing without a nonce or with the page as built', () => {
    for (const nonce of [null, '', CSP_NONCE_PLACEHOLDER]) {
      page(nonce)
      expect(nonceOf(document.createElement('style'))).toBeFalsy()
      document.head.replaceChildren()
    }
  })

  it('does not nonce style markup parsed into the page', () => {
    page(NONCE)
    const holder = document.createElement('div')
    holder.innerHTML = '<style>body{}</style>'
    expect(nonceOf(holder.firstElementChild!)).toBeFalsy()
  })
})
