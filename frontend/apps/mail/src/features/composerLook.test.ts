import { describe, expect, it } from 'vitest'
import { buildMessage, parseMessage } from '@kutup/mail-core/mime'
import { plainToHtml, wrapHtml } from './composerLook'

describe('composer look', () => {
  it('wraps the HTML with font, size and direction', () => {
    expect(wrapHtml('<p>x</p>', { fontFace: 'georgia', fontSize: 18, rtl: true })).toBe('<div style="font-family: Georgia, serif; font-size: 18px;" dir="rtl"><p>x</p></div>')
    expect(wrapHtml('<p>x</p>', { fontFace: 'unknown', fontSize: 14, rtl: false })).toBe('<div style="font-family: Arial, sans-serif; font-size: 14px;"><p>x</p></div>')
  })

  it('turns plain text into paragraphs, escaped', () => {
    expect(plainToHtml('a < b\nc')).toBe('<p>a &lt; b</p><p>c</p>')
  })

  it('sends plain text as text/plain alone', async () => {
    const raw = buildMessage({ from: { address: 'a@kutup.dev', name: '' }, to: [{ address: 'b@kutup.dev', name: '' }], cc: [], subject: 'Düz', messageId: 'p@kutup.dev', html: '', text: 'Merhaba\nDünya', plain: true })
    const text = new TextDecoder().decode(raw)
    expect(text).toContain('Content-Type: text/plain')
    expect(text).not.toContain('text/html')
    const parsed = await parseMessage(raw)
    expect(parsed.text).toContain('Merhaba\nDünya')
    expect(parsed.html).toBeNull()
  })
})
