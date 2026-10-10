import { describe, expect, it } from 'vitest'
import { plainTextDocument, sanitizeMailHtml } from './sanitize'

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
})
