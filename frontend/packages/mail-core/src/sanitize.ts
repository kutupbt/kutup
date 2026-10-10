import DOMPurify from 'dompurify'

// Mail HTML is hostile until proven otherwise (docs/plans/mail.md), as in
// Proton's `packages/sanitize`: no scripts, forms, frames, embeds or style
// sheets; remote images, backgrounds and CSS urls blocked until the reader
// allows them for that message (a remote load tells the sender the mail was
// read, and from where); `cid:` images shown from the message's own parts;
// links open in a new tab without a referrer. The result is shown in a
// sandboxed iframe with its own CSP, which blocks anything this misses.

export interface SanitizeOptions {
  /** Load remote images and CSS backgrounds. */
  allowRemote: boolean
  /** Content-ID (without brackets) → blob: URL of that part. */
  inlineImages?: ReadonlyMap<string, string>
}

export interface SanitizedHtml {
  /** A whole document for the iframe's `srcdoc`. */
  document: string
  /** Whether something remote was held back. */
  remoteBlocked: boolean
}

const FORBID_TAGS = ['script', 'style', 'link', 'meta', 'base', 'iframe', 'frame', 'frameset', 'object', 'embed', 'form', 'input', 'button', 'textarea', 'select', 'option', 'svg', 'math', 'audio', 'video', 'source', 'track']
const URL_ATTRIBUTES = ['src', 'background', 'poster']
const REMOTE = /^\s*(https?:)?\/\//i
const CSS_URL = /url\(\s*(['"]?)(.*?)\1\s*\)/gi

function rewriteStyle(style: string, options: SanitizeOptions, blocked: () => void): string {
  return style.replace(CSS_URL, (whole, _quote: string, url: string) => {
    const target = url.trim()
    if (target.toLowerCase().startsWith('cid:')) {
      const blob = options.inlineImages?.get(target.slice(4).replace(/^<|>$/g, ''))
      return blob ? `url("${blob}")` : 'none'
    }
    if (target.toLowerCase().startsWith('data:image/')) return whole
    if (REMOTE.test(target) && options.allowRemote) return whole
    if (REMOTE.test(target)) blocked()
    return 'none'
  })
}

/** Sanitises a message's HTML for the reading pane. */
export function sanitizeMailHtml(html: string, options: SanitizeOptions): SanitizedHtml {
  const purify = DOMPurify(window)
  let remoteBlocked = false
  const blocked = () => {
    remoteBlocked = true
  }
  purify.addHook('uponSanitizeAttribute', (node, data) => {
    const name = data.attrName.toLowerCase()
    if (name === 'style') {
      data.attrValue = rewriteStyle(data.attrValue, options, blocked)
      return
    }
    if (!URL_ATTRIBUTES.includes(name)) return
    const value = data.attrValue.trim()
    if (value.toLowerCase().startsWith('cid:')) {
      const blob = options.inlineImages?.get(value.slice(4).replace(/^<|>$/g, ''))
      if (blob) {
        // Not forceKeepAttr: that keeps the original value, not this one.
        data.attrValue = blob
      } else {
        data.keepAttr = false
      }
      return
    }
    if (value.toLowerCase().startsWith('data:image/')) return
    if (REMOTE.test(value)) {
      if (options.allowRemote) {
        data.forceKeepAttr = true
        return
      }
      blocked()
    }
    data.keepAttr = false
    if (node.nodeName === 'IMG') (node as HTMLElement).setAttribute('data-kutup-blocked', '')
  })
  purify.addHook('afterSanitizeAttributes', (node) => {
    if (node.nodeName === 'A') {
      const href = node.getAttribute('href') ?? ''
      if (!/^(https?:|mailto:)/i.test(href.trim())) {
        node.removeAttribute('href')
      } else {
        node.setAttribute('target', '_blank')
        node.setAttribute('rel', 'noopener noreferrer nofollow')
      }
    }
    // srcset could load what src may not.
    node.removeAttribute('srcset')
  })
  const body = purify.sanitize(html, {
    FORBID_TAGS,
    FORBID_ATTR: ['srcset', 'for', 'action', 'formaction', 'ping'],
    ALLOW_DATA_ATTR: false,
    USE_PROFILES: { html: true },
    ALLOWED_URI_REGEXP: /^(?:https?:|mailto:|cid:|data:image\/|blob:)/i,
    ADD_ATTR: ['target'],
    WHOLE_DOCUMENT: false,
  })
  purify.removeAllHooks()
  const images = options.allowRemote ? 'data: blob: https: http:' : 'data: blob:'
  return {
    document: frame(body, images),
    remoteBlocked,
  }
}

function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!)
}

/** Plain text as a document: escaped, line breaks kept, links clickable. */
export function plainTextDocument(text: string): string {
  const linked = escapeHtml(text).replace(
    /\b(https?:\/\/[^\s<>"']+[^\s<>"'.,;:!?)])/g,
    '<a href="$1" target="_blank" rel="noopener noreferrer nofollow">$1</a>',
  )
  return frame(`<div style="white-space: pre-wrap; overflow-wrap: anywhere">${linked}</div>`, 'data: blob:')
}

function frame(body: string, images: string): string {
  return `<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src ${images}; style-src 'unsafe-inline'; font-src data:">
<style>
  html { color-scheme: light; }
  body { margin: 0; padding: 4px 2px; font: 14px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; color: #111827; background: #fff; overflow-wrap: anywhere; }
  img { max-width: 100%; height: auto; }
  img[data-kutup-blocked] { display: none; }
  table { max-width: 100%; }
  blockquote { margin: 0 0 0 8px; padding-left: 12px; border-left: 3px solid #d1d5db; color: #4b5563; }
  pre { white-space: pre-wrap; }
</style></head><body>${body}</body></html>`
}
