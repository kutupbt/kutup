import { describe, expect, it } from 'vitest'
import { attachmentPart, buildMessage, describePart, encodeHeaderText, formatMailbox, parseMessage } from './mime'

const decoder = new TextDecoder()

describe('mime', () => {
  it('builds a message that parses back to what was written', async () => {
    const raw = buildMessage({
      from: { address: 'alice@kutup.dev', name: 'Çağla Öztürk' },
      to: [{ address: 'bob@example.org', name: 'Bob "B" Smith' }],
      cc: [{ address: 'carol@kutup.dev', name: '' }],
      subject: 'Toplantı: şubat planı 🗓️',
      messageId: 'abc@kutup.dev',
      inReplyTo: 'parent@example.org',
      references: ['root@example.org', 'parent@example.org'],
      date: new Date('2026-10-10T08:00:00Z'),
      html: '<p>Merhaba <b>dünya</b></p>',
      text: 'Merhaba dünya',
      attachments: [attachmentPart({ name: 'rapor ğüş.pdf', type: 'application/pdf', bytes: new Uint8Array([1, 2, 3, 250]) })],
    })
    const text = decoder.decode(raw)
    expect(text).not.toMatch(/^bcc:/im)
    expect(text.split('\r\n').every((line) => line.length <= 998)).toBe(true)
    const parsed = await parseMessage(raw)
    expect(parsed.subject).toBe('Toplantı: şubat planı 🗓️')
    expect(parsed.from).toEqual({ address: 'alice@kutup.dev', name: 'Çağla Öztürk' })
    expect(parsed.to).toEqual([{ address: 'bob@example.org', name: 'Bob "B" Smith' }])
    expect(parsed.cc).toEqual([{ address: 'carol@kutup.dev', name: '' }])
    expect(parsed.messageId).toBe('abc@kutup.dev')
    expect(parsed.inReplyTo).toBe('parent@example.org')
    expect(parsed.references).toEqual(['root@example.org', 'parent@example.org'])
    expect(parsed.date?.toISOString()).toBe('2026-10-10T08:00:00.000Z')
    expect(parsed.html).toContain('<b>dünya</b>')
    expect(parsed.text?.trim()).toBe('Merhaba dünya')
    expect(parsed.attachments).toHaveLength(1)
    expect(parsed.attachments[0].filename).toBe('rapor ğüş.pdf')
    expect(parsed.attachments[0].mimeType).toBe('application/pdf')
    expect([...parsed.attachments[0].content]).toEqual([1, 2, 3, 250])
  })

  it('keeps plain headers plain and encodes the rest in short words', () => {
    expect(encodeHeaderText('Hello')).toBe('Hello')
    const long = encodeHeaderText('ğ'.repeat(200))
    expect(long.split('\r\n ').every((word) => word.length <= 75)).toBe(true)
    expect(formatMailbox({ address: 'a@b.org', name: '' })).toBe('a@b.org')
    expect(formatMailbox({ address: 'a@b.org', name: 'A, B' })).toBe('"A, B" <a@b.org>')
  })

  it('reads mail from elsewhere: groups, missing fields, inline images', async () => {
    const raw = new TextEncoder().encode(
      [
        'From: Team: a@x.org, B <b@x.org>;',
        'Subject: =?ISO-8859-9?Q?Toplant=FD?=',
        'Content-Type: multipart/related; boundary=r',
        '',
        '--r',
        'Content-Type: text/html; charset=utf-8',
        '',
        '<img src="cid:logo@x">',
        '--r',
        'Content-Type: image/png',
        'Content-ID: <logo@x>',
        'Content-Transfer-Encoding: base64',
        '',
        'iVBORw0KGgo=',
        '--r--',
        '',
      ].join('\r\n'),
    )
    const parsed = await parseMessage(raw)
    expect(parsed.subject).toBe('Toplantı')
    expect(parsed.from?.address).toBe('a@x.org')
    expect(parsed.date).toBeNull()
    expect(parsed.attachments[0]).toMatchObject({ inline: true, contentId: 'logo@x', mimeType: 'image/png' })
  })

  it('describes an attachment part from its headers', () => {
    const part = attachmentPart({ name: 'şirket raporu.pdf', type: 'application/pdf', bytes: new Uint8Array(1000) })
    expect(describePart(part)).toEqual({ name: 'şirket raporu.pdf', type: 'application/pdf', size: 1000 })
  })
})
