import { describe, expect, it } from 'vitest'
import { attachmentPart, buildInlineMessage, inlineContentId, buildMessage, describePart, encodeHeaderText, formatMailbox, isAutoReply, parseMessage, partContent } from './mime'

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

describe('auto-replies', () => {
  it('are known by their headers, as Proton reads them', async () => {
    expect(isAutoReply([{ key: 'x-autoreply', value: 'yes' }])).toBe(true)
    expect(isAutoReply([{ key: 'auto-submitted', value: 'auto-replied' }])).toBe(true)
    expect(isAutoReply([{ key: 'auto-submitted', value: 'auto-generated' }])).toBe(false)
    expect(isAutoReply([{ key: 'subject', value: 'Auto: hi' }])).toBe(false)
    const raw = new TextEncoder().encode('From: a@b.c\r\nTo: d@e.f\r\nSubject: Auto: hi\r\nAuto-Submitted: auto-replied\r\n\r\nAway.\r\n')
    expect((await parseMessage(raw)).autoReply).toBe(true)
  })
})

describe('Inline PGP', () => {
  const header = {
    from: { address: 'ayse@kutup.dev', name: 'Ayşe' },
    to: [{ address: 'bob@example.org', name: '' }],
    cc: [],
    subject: 'Satır içi',
    messageId: 'm1@kutup.dev',
  }
  const armored = '-----BEGIN PGP MESSAGE-----\n\nwcBMA0…\n-----END PGP MESSAGE-----\n'

  it('is a plain-text body holding the armored text', async () => {
    const parsed = await parseMessage(buildInlineMessage(header, armored, []))
    expect(parsed.subject).toBe('Satır içi')
    expect(parsed.text?.replace(/\r\n/g, '\n').trim()).toBe(armored.trim())
    expect(parsed.html).toBeNull()
    expect(parsed.attachments).toHaveLength(0)
  })

  it('carries each file on its own after the text', async () => {
    const file = attachmentPart({ name: 'rapor.pdf.pgp', type: 'application/pgp-encrypted', bytes: new TextEncoder().encode(armored) })
    const parsed = await parseMessage(buildInlineMessage(header, armored, [file]))
    expect(parsed.text?.trim().startsWith('-----BEGIN PGP MESSAGE-----')).toBe(true)
    expect(parsed.attachments.map((a) => a.filename)).toEqual(['rapor.pdf.pgp'])
  })

  it('reads a part back to its file', () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 255])
    expect(partContent(attachmentPart({ name: 'a.bin', type: 'application/octet-stream', bytes }))).toEqual(bytes)
  })
})

describe('read receipts (RFC 8098)', () => {
  const base = { from: { address: 'ayse@kutup.dev', name: 'Ayşe' }, to: [{ address: 'ali@kutup.dev', name: '' }], cc: [], subject: 'Toplantı', messageId: 'm1@kutup.dev', html: '<p>x</p>', text: 'x' }

  it('asks for one, and the request is read back', async () => {
    const raw = buildMessage({ ...base, requestReceipt: true })
    expect(new TextDecoder().decode(raw)).toContain('Disposition-Notification-To: =?UTF-8?')
    expect((await parseMessage(raw)).receiptTo).toContain('ayse@kutup.dev')
    expect((await parseMessage(buildMessage(base))).receiptTo).toBeNull()
  })

  it('sends one as a multipart/report with the disposition', async () => {
    const raw = buildMessage({ ...base, subject: 'Read: Toplantı', text: 'Okundu.', receipt: { finalRecipient: 'ali@kutup.dev', originalMessageId: 'orig@kutup.dev' } })
    const text = new TextDecoder().decode(raw)
    expect(text).toContain('Content-Type: multipart/report; report-type=disposition-notification')
    expect(text).toContain('Content-Type: message/disposition-notification')
    expect(text).toContain('Final-Recipient: rfc822;ali@kutup.dev')
    expect(text).toContain('Original-Message-ID: <orig@kutup.dev>')
    expect(text).toContain('Disposition: manual-action/MDN-sent-manually; displayed')
    expect((await parseMessage(raw)).text).toContain('Okundu.')
  })
})

describe('inline images', () => {
  it('go with the text in multipart/related, files after in multipart/mixed', async () => {
    const png = new Uint8Array([137, 80, 78, 71])
    const image = attachmentPart({ name: 'logo.png', type: 'image/png', bytes: png }, 'logo@kutup')
    const file = attachmentPart({ name: 'rapor.pdf', type: 'application/pdf', bytes: new Uint8Array([1, 2]) })
    expect(inlineContentId(image)).toBe('logo@kutup')
    expect(inlineContentId(file)).toBeNull()
    const raw = buildMessage({ from: { address: 'a@kutup.dev', name: '' }, to: [], cc: [], subject: 'Resim', messageId: 'r@kutup.dev', html: '<p><img src="cid:logo@kutup"></p>', text: '', attachments: [image, file] })
    const text = new TextDecoder().decode(raw)
    expect(text.indexOf('multipart/mixed')).toBeLessThan(text.indexOf('multipart/related'))
    const parsed = await parseMessage(raw)
    const logo = parsed.attachments.find((a) => a.filename === 'logo.png')!
    expect(logo.inline).toBe(true)
    expect(logo.contentId).toBe('logo@kutup')
    expect(parsed.attachments.find((a) => a.filename === 'rapor.pdf')!.inline).toBe(false)
  })
})
