import { describe, expect, it } from 'vitest'
import { paintsNothing, plainTextDocument, sanitizeMailHtml } from './sanitize'

function body(document: string): string {
  return document.slice(document.indexOf('<body>') + 6, document.lastIndexOf('</body>'))
}

describe('sanitizeMailHtml', () => {
  const hostile = `
    <script>alert(1)</script><style>body{background:url(https://t.example/s.png)}</style>
    <img src="https://t.example/pixel.gif" onerror="alert(2)">
    <img src="cid:logo@x"><img src="cid:missing@x">
    <img src="data:image/png;base64,AAAA">
    <table><tr><td background="https://t.example/bg.png" style="color:red;background:url('https://t.example/b.png')">x</td></tr></table>
    <a href="javascript:alert(3)">bad</a> <a href="https://example.org/a">good</a>
    <form action="https://evil"><input name="p"></form><iframe src="https://evil"></iframe>
    <svg><circle/></svg>`
  const images = new Map([['logo@x', 'blob:https://mail.kutup.dev/1']])

  it('removes active content and holds remote content back', () => {
    const result = sanitizeMailHtml(hostile, { allowRemote: false, inlineImages: images })
    const html = body(result.document)
    expect(result.remoteBlocked).toBe(true)
    expect(html).not.toMatch(/<script|<style|<form|<input|<iframe|<svg|onerror|javascript:/i)
    expect(html).not.toContain('t.example')
    expect(html).toContain('src="blob:https://mail.kutup.dev/1"')
    expect(html).toContain('data:image/png;base64,AAAA')
    expect(html).toContain('color:red')
    expect(html).toContain('href="https://example.org/a"')
    expect(html).toContain('rel="noopener noreferrer nofollow"')
    expect(html).toContain('target="_blank"')
    expect(result.document).toContain("img-src data: blob:;")
  })

  it('loads remote images when the reader allows them', () => {
    const result = sanitizeMailHtml(hostile, { allowRemote: true, inlineImages: images })
    const html = body(result.document)
    expect(result.remoteBlocked).toBe(false)
    expect(html).toContain('src="https://t.example/pixel.gif"')
    expect(html).toContain("url('https://t.example/b.png')")
    expect(html).not.toMatch(/<script|onerror|javascript:/i)
    expect(result.document).toContain('img-src data: blob: https: http:')
  })

  it('shows plain text escaped, with links', () => {
    const document = plainTextDocument('a <b> & https://example.org/x.\nnext')
    expect(document).toContain('a &lt;b&gt; &amp; <a href="https://example.org/x" target="_blank"')
    expect(document).toContain('white-space: pre-wrap')
  })

  it('folds a quoted earlier message behind a button', () => {
    const look = { dark: false, quoteLabel: 'Show quoted text' }
    const html = body(sanitizeMailHtml('<p>Thanks!</p><p>On Monday, Ayşe wrote:</p><blockquote><p>Hi</p></blockquote>', { allowRemote: false, look }).document)
    expect(html).toMatch(/^<p>Thanks!<\/p><details class="kutup-quote"><summary[^>]*>…<\/summary><p>On Monday, Ayşe wrote:<\/p><blockquote>/)
    // A message that is all quote stays open.
    expect(body(sanitizeMailHtml('<blockquote><p>Hi</p></blockquote>', { allowRemote: false, look }).document)).not.toContain('<details')
    const text = plainTextDocument('Thanks!\n\nOn Monday, Ayşe wrote:\n> Hi\n>\n> there\n', look)
    expect(text).toContain('Thanks!\n<details class="kutup-quote">')
    expect(text).toContain('On Monday, Ayşe wrote:\n&gt; Hi')
  })

  it('follows a dark theme only when the mail paints nothing itself', () => {
    expect(paintsNothing('<p>Hello <b>there</b></p><p style="color:#888">sig</p>')).toBe(true)
    expect(paintsNothing('<table bgcolor="#fff"><tr><td>x</td></tr></table>')).toBe(false)
    expect(paintsNothing('<div style="background-color: #f4f4f4">x</div>')).toBe(false)
    expect(paintsNothing('<p style="color: #000">x</p>')).toBe(false)
    expect(paintsNothing('<font color="black">x</font>')).toBe(false)
    const look = { dark: true }
    expect(sanitizeMailHtml('<p>Hello</p>', { allowRemote: false, look }).dark).toBe(true)
    expect(sanitizeMailHtml('<p>Hello</p>', { allowRemote: false, look }).document).toContain('color-scheme: dark')
    expect(sanitizeMailHtml('<p style="color:#111">Hello</p>', { allowRemote: false, look }).dark).toBe(false)
    expect(plainTextDocument('Hello', look)).toContain('color-scheme: dark')
    expect(plainTextDocument('Hello')).not.toContain('color-scheme: dark')
  })
})
