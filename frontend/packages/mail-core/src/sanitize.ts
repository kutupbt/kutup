import DOMPurify from 'dompurify'

// Mail HTML is hostile until proven otherwise (docs/plans/mail.md), as in
// Proton's `packages/sanitize`: no scripts, forms, frames, embeds or style
// sheets; remote images, backgrounds and CSS urls blocked until the reader
// allows them for that message (a remote load tells the sender the mail was
// read, and from where); `cid:` images shown from the message's own parts;
// links open in a new tab without a referrer. The result is shown in a
// sandboxed iframe with its own CSP, which blocks anything this misses.

/**
 * How the body should look beside the app. In a dark theme, plain text and
 * HTML that sets no colours of its own take the theme's colours; HTML that
 * paints itself (newsletters, signatures in dark ink) stays as its sender
 * made it, on white, as Proton shows it.
 */
export interface FrameLook {
  dark: boolean
  /** The theme's colours as CSS values, for a body that follows the theme. */
  colors?: { background: string; text: string; muted: string; link: string; border: string }
  /** The label of the button that shows quoted text ("Show quoted text"). */
  quoteLabel?: string
}

export interface SanitizeOptions {
  /** Load remote images and CSS backgrounds. */
  allowRemote: boolean
  /** Content-ID (without brackets) → blob: URL of that part. */
  inlineImages?: ReadonlyMap<string, string>
  look?: FrameLook
}

export interface SanitizedHtml {
  /** A whole document for the iframe's `srcdoc`. */
  document: string
  /** Whether something remote was held back. */
  remoteBlocked: boolean
  /** Whether the body takes the dark theme's colours (else it is on white). */
  dark: boolean
  /** Whether the body takes the theme's colours at all. */
  themed: boolean
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
  const adapts = !!options.look && paintsNothing(body)
  return {
    document: frame(foldQuote(body, options.look?.quoteLabel), images, adapts ? options.look : undefined),
    remoteBlocked,
    dark: adapts && !!options.look?.dark,
    themed: adapts,
  }
}

const BACKGROUND = /background(-color|-image)?\s*:|\bbgcolor\s*=|\bbackground\s*=/i
const COLOR_DECLARATION = /(?:^|[;\s"'])color\s*:\s*([^;"']+)|<font[^>]*\scolor\s*=\s*["']?([^"'\s>]+)/gi

/** Brightness 0–1 of a CSS colour, or null when it cannot be read here. */
function brightness(value: string): number | null {
  const color = value.trim().toLowerCase().replace(/\s*!important$/, '')
  const named: Record<string, string> = { black: '#000', white: '#fff', gray: '#808080', grey: '#808080', silver: '#c0c0c0', navy: '#000080', maroon: '#800000', darkblue: '#00008b', darkgreen: '#006400', red: '#f00', blue: '#00f', green: '#008000' }
  const hex = (named[color] ?? color).match(/^#([0-9a-f]{3,8})$/)
  let rgb: number[] | null = null
  if (hex) {
    const digits = hex[1].length <= 4 ? hex[1].slice(0, 3).split('').map((d) => d + d) : hex[1].slice(0, 6).match(/../g)!
    rgb = digits.map((d) => parseInt(d, 16))
  } else {
    const fn = color.match(/^rgba?\(\s*(\d+)[\s,]+(\d+)[\s,]+(\d+)/)
    if (fn) rgb = [Number(fn[1]), Number(fn[2]), Number(fn[3])]
  }
  if (!rgb) return color === 'inherit' || color === 'currentcolor' || color === 'initial' ? 1 : null
  return (0.299 * rgb[0] + 0.587 * rgb[1] + 0.114 * rgb[2]) / 255
}

/**
 * Whether HTML leaves its colours to the reader: no backgrounds, and no text
 * colour too dark to read on a dark background. Such mail (most personal
 * mail, and Kutup's own) can follow a dark theme.
 */
export function paintsNothing(html: string): boolean {
  if (BACKGROUND.test(html)) return false
  for (const match of html.matchAll(COLOR_DECLARATION)) {
    const level = brightness(match[1] ?? match[2] ?? '')
    if (level === null || level < 0.45) return false
  }
  return true
}

/**
 * Folds the quoted earlier message behind a "…" button (Proton's blockquote
 * toggle), with no script: a `<details>` element. Only a quote that follows
 * the new text is folded, with its "On …, … wrote:" line.
 */
function foldQuote(body: string, label: string | undefined): string {
  if (!label) return body
  const doc = new DOMParser().parseFromString(`<!doctype html><body>${body}`, 'text/html')
  const root = doc.body
  const marked = root.querySelector('.gmail_quote, .protonmail_quote, blockquote[type="cite"], #divRplyFwdMsg, .moz-cite-prefix')
  let start: Element | null = marked
  if (!start) {
    // A blockquote that ends the message, with nothing after it.
    const last = [...root.children].reverse().find((el) => el.textContent?.trim() || el.querySelector('img'))
    if (last?.tagName === 'BLOCKQUOTE') start = last
  }
  if (!start) return body
  // From its top-level ancestor to the end of the message.
  while (start.parentElement && start.parentElement !== root) start = start.parentElement
  const previous = start.previousElementSibling
  if (previous && /:\s*$/.test(previous.textContent ?? '') && (previous.textContent ?? '').length < 300) start = previous
  const nodes: ChildNode[] = []
  for (let node: ChildNode | null = start; node; node = node.nextSibling) nodes.push(node)
  const before = [...root.childNodes].slice(0, [...root.childNodes].indexOf(start))
  if (!before.some((node) => node.textContent?.trim() || (node instanceof Element && node.querySelector('img')))) return body
  const details = doc.createElement('details')
  details.className = 'kutup-quote'
  const summary = doc.createElement('summary')
  summary.setAttribute('title', label)
  summary.setAttribute('aria-label', label)
  summary.textContent = '\u2026'
  details.append(summary, ...nodes)
  root.append(details)
  return root.innerHTML
}

function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!)
}

function linkify(text: string): string {
  return escapeHtml(text).replace(
    /\b(https?:\/\/[^\s<>"']+[^\s<>"'.,;:!?)])/g,
    '<a href="$1" target="_blank" rel="noopener noreferrer nofollow">$1</a>',
  )
}

/**
 * Plain text as a document: escaped, line breaks kept, links clickable, in
 * the theme's colours; the quoted earlier message at the end (`>` lines and
 * the "… wrote:" line before them) folded.
 */
export function plainTextDocument(text: string, look?: FrameLook): string {
  const lines = text.replace(/\s+$/, '').split('\n')
  let start = lines.length
  while (start > 0 && (lines[start - 1].startsWith('>') || (lines[start - 1].trim() === '' && start < lines.length))) start -= 1
  while (start < lines.length && lines[start].trim() === '') start += 1
  const quoted = start < lines.length && lines.slice(start).some((line) => line.startsWith('>'))
  if (quoted && start > 0 && /:\s*$/.test(lines[start - 1]) && lines[start - 1].length < 300) start -= 1
  const own = quoted ? lines.slice(0, start).join('\n') : text
  const fold =
    quoted && look?.quoteLabel && own.trim()
      ? `<details class="kutup-quote"><summary title="${escapeHtml(look.quoteLabel)}" aria-label="${escapeHtml(look.quoteLabel)}">\u2026</summary>${linkify(lines.slice(start).join('\n'))}</details>`
      : ''
  const shown = fold ? `${own.trimEnd()}\n` : text
  return frame(`<div style="white-space: pre-wrap; overflow-wrap: anywhere">${linkify(shown)}${fold}</div>`, 'data: blob:', look)
}

function frame(body: string, images: string, look?: FrameLook): string {
  const fallback = look?.dark
    ? { background: '#111318', text: '#e5e7eb', muted: '#9ca3af', link: '#93c5fd', border: '#374151' }
    : { background: '#fff', text: '#111827', muted: '#4b5563', link: '#0b62c4', border: '#e5e7eb' }
  const c = look?.colors ?? fallback
  const theme = look
    ? `html { color-scheme: ${look.dark ? 'dark' : 'light'}; }
  body { color: ${c.text}; background: ${c.background}; }
  a { color: ${c.link}; }
  blockquote { border-left-color: ${c.border}; color: ${c.muted}; }
  details.kutup-quote > summary { background: ${c.border}; color: ${c.text}; }`
    : ''
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
  details.kutup-quote { margin-top: 8px; }
  details.kutup-quote > summary { display: inline-block; list-style: none; cursor: pointer; padding: 0 8px; border-radius: 999px; background: #e5e7eb; color: #374151; font-weight: 700; line-height: 1.4; letter-spacing: 1px; user-select: none; }
  details.kutup-quote > summary::-webkit-details-marker { display: none; }
  details.kutup-quote[open] > summary { margin-bottom: 8px; }
  @media print { body { color: #000 !important; background: #fff !important; } }
  ${theme}
</style></head><body>${body}</body></html>`
}
