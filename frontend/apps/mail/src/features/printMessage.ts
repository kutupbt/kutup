import type { Mailbox, ParsedMessage } from '@kutup/mail-core/mime'
import { plainTextDocument, sanitizeMailHtml } from '@kutup/mail-core/sanitize'

/** `Name <address>` as people read it. */
const shown = (mailbox: Mailbox) => (mailbox.name ? `${mailbox.name} <${mailbox.address}>` : mailbox.address)

const escape = (text: string) => text.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]!)

export interface PrintLabels {
  from: string
  to: string
  cc: string
  date: string
}

/**
 * The message as Proton prints it (MessagePrintModal): subject, From, To,
 * Cc and date over the body, light, remote content still blocked. The body
 * is the sanitized one the reader shows; the page holds no scripts.
 */
export function printDocument(parsed: ParsedMessage, labels: PrintLabels, date: string, inlineImages: ReadonlyMap<string, string>): string {
  const look = { dark: false }
  const body = parsed.html ? sanitizeMailHtml(parsed.html, { allowRemote: false, inlineImages, look }).document : plainTextDocument(parsed.text ?? '', look)
  const opened = new DOMParser().parseFromString(body, 'text/html')
  const rows = [
    [labels.from, parsed.from ? shown(parsed.from) : ''],
    [labels.to, parsed.to.map(shown).join(', ')],
    [labels.cc, parsed.cc.map(shown).join(', ')],
    [labels.date, date],
  ].filter(([, value]) => value)
  const header = `<header style="font-family:system-ui,sans-serif;border-bottom:1px solid #ccc;margin-bottom:16px;padding-bottom:8px">
<h1 style="font-size:20px;margin:0 0 8px">${escape(parsed.subject)}</h1>
<table style="font-size:12px;border-collapse:collapse">${rows.map(([label, value]) => `<tr><th style="text-align:left;padding:2px 12px 2px 0;color:#555">${escape(label)}</th><td>${escape(value)}</td></tr>`).join('')}</table>
</header>`
  opened.body.insertAdjacentHTML('afterbegin', header)
  opened.title = parsed.subject
  return `<!doctype html>${opened.documentElement.outerHTML}`
}

/** Prints `html` from a hidden frame that runs no scripts. */
export function printHtml(html: string) {
  const frame = document.createElement('iframe')
  frame.setAttribute('sandbox', 'allow-same-origin allow-modals')
  frame.setAttribute('aria-hidden', 'true')
  frame.style.cssText = 'position:fixed;width:0;height:0;border:0;right:0;bottom:0'
  frame.srcdoc = html
  frame.addEventListener('load', () => {
    frame.contentWindow?.focus()
    frame.contentWindow?.print()
    setTimeout(() => frame.remove(), 60_000)
  })
  document.body.append(frame)
}
