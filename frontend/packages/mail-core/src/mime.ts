import PostalMime, { decodeWords, type Address } from 'postal-mime'

// MIME in the browser (docs/plans/mail.md): every stored message is one RFC
// 5322 message, opened here after decryption. Parsing uses postal-mime;
// building is small enough to do here, so a sent message is exactly what
// Kutup wrote.

export interface Mailbox {
  address: string
  name: string
}

export interface ParsedAttachment {
  filename: string
  mimeType: string
  /** `inline` parts with a Content-ID are images the HTML refers to. */
  inline: boolean
  contentId: string | null
  content: Uint8Array
}

export interface ParsedMessage {
  subject: string
  from: Mailbox | null
  to: Mailbox[]
  cc: Mailbox[]
  replyTo: Mailbox[]
  date: Date | null
  messageId: string | null
  inReplyTo: string | null
  references: string[]
  html: string | null
  text: string | null
  attachments: ParsedAttachment[]
}

function mailboxes(list: Address[] | undefined): Mailbox[] {
  return (list ?? []).flatMap((entry) =>
    'group' in entry && entry.group
      ? entry.group.map((m) => ({ address: m.address.toLowerCase(), name: m.name }))
      : entry.address
        ? [{ address: entry.address.toLowerCase(), name: entry.name }]
        : [],
  )
}

function bareId(value: string | undefined): string | null {
  const id = value?.trim().replace(/^<|>$/g, '').trim()
  return id ? id : null
}

/** Parses a decrypted message for the reading pane. */
export async function parseMessage(raw: Uint8Array): Promise<ParsedMessage> {
  const email = await PostalMime.parse(raw, { attachmentEncoding: 'arraybuffer' })
  const date = email.date ? new Date(email.date) : null
  return {
    subject: email.subject ?? '',
    from: mailboxes(email.from ? [email.from] : [])[0] ?? null,
    to: mailboxes(email.to),
    cc: mailboxes(email.cc),
    replyTo: mailboxes(email.replyTo),
    date: date && !Number.isNaN(date.getTime()) ? date : null,
    messageId: bareId(email.messageId),
    inReplyTo: bareId(email.inReplyTo),
    references: (email.references ?? '').split(/\s+/).map((id) => bareId(id)).filter((id): id is string => !!id),
    html: email.html ?? null,
    text: email.text ?? null,
    attachments: email.attachments.map((a) => ({
      filename: a.filename ?? '',
      mimeType: a.mimeType || 'application/octet-stream',
      inline: a.disposition === 'inline' || (!!a.related && !!a.contentId),
      contentId: bareId(a.contentId),
      content:
        a.content instanceof Uint8Array
          ? a.content
          : typeof a.content === 'string'
            ? new TextEncoder().encode(a.content)
            : new Uint8Array(a.content),
    })),
  }
}

const encoder = new TextEncoder()

function base64(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  }
  return btoa(binary)
}

/** Base64 in lines of 76 characters, as RFC 2045 requires. */
function base64Lines(bytes: Uint8Array): string {
  return (base64(bytes).match(/.{1,76}/g) ?? []).join('\r\n')
}

/** An RFC 2047 encoded word for non-ASCII header text, split to fit lines. */
export function encodeHeaderText(text: string): string {
  const single = text.replace(/[\r\n]+/g, ' ')
  if (/^[\x20-\x7e]*$/.test(single)) return single
  const words: string[] = []
  let chunk = ''
  for (const char of single) {
    // At most 45 bytes per word keeps each encoded word within 75 characters.
    if (encoder.encode(chunk + char).length > 45) {
      words.push(chunk)
      chunk = ''
    }
    chunk += char
  }
  if (chunk) words.push(chunk)
  return words.map((w) => `=?UTF-8?B?${base64(encoder.encode(w))}?=`).join('\r\n ')
}

/** `"Name" <address>`, the name encoded when it needs to be. */
export function formatMailbox(mailbox: Mailbox): string {
  const name = mailbox.name.trim()
  if (!name) return mailbox.address
  const display = /^[\x20-\x7e]*$/.test(name) ? `"${name.replace(/["\\]/g, '\\$&')}"` : encodeHeaderText(name)
  return `${display} <${mailbox.address}>`
}

function headerList(name: string, list: Mailbox[]): string[] {
  return list.length ? [`${name}: ${list.map(formatMailbox).join(',\r\n ')}`] : []
}

function boundary(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(18))
  return `kutup-${base64(bytes).replace(/[+/=]/g, '')}`
}

function textPart(mimeType: 'text/plain' | 'text/html', text: string): string {
  return [`Content-Type: ${mimeType}; charset=utf-8`, 'Content-Transfer-Encoding: base64', '', base64Lines(encoder.encode(text))].join(
    '\r\n',
  )
}

/** A file as a MIME part, ready to be put inside a message as it is. */
export function attachmentPart(file: { name: string; type: string; bytes: Uint8Array }): Uint8Array {
  const name = encodeHeaderText(file.name).replace(/"/g, '')
  const type = /^[\w.+-]+\/[\w.+-]+$/.test(file.type) ? file.type : 'application/octet-stream'
  return encoder.encode(
    [
      `Content-Type: ${type}; name="${name}"`,
      `Content-Disposition: attachment; filename="${name}"`,
      'Content-Transfer-Encoding: base64',
      '',
      base64Lines(file.bytes),
    ].join('\r\n'),
  )
}

export interface OutgoingMessage {
  from: Mailbox
  to: Mailbox[]
  cc: Mailbox[]
  subject: string
  /** `id@domain`, without angle brackets. */
  messageId: string
  inReplyTo?: string | null
  references?: string[]
  date?: Date
  html: string
  text: string
  /** Parts made by `attachmentPart`. */
  attachments?: Uint8Array[]
  /**
   * The sender's OpenPGP key (binary, base64) for an Autocrypt header
   * (Level 1, `prefer-encrypt=mutual`), so OpenPGP mail programs can write
   * back encrypted and offer to trust it (docs/plans/mail.md, C3).
   */
  autocryptKey?: string
}

function concat(chunks: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0))
  let offset = 0
  for (const chunk of chunks) {
    out.set(chunk, offset)
    offset += chunk.length
  }
  return out
}

/** `Autocrypt: addr=…; prefer-encrypt=mutual; keydata=…`, folded. */
export function autocryptHeader(address: string, publicKey: string): string {
  const keydata = publicKey.replace(/\s/g, '')
  return `Autocrypt: addr=${address}; prefer-encrypt=mutual; keydata=\r\n ${(keydata.match(/.{1,76}/g) ?? []).join('\r\n ')}`
}

/** The message's own header fields, without its Content-Type. */
function headerFields(message: OutgoingMessage): string[] {
  const date = message.date ?? new Date()
  return [
    `From: ${formatMailbox(message.from)}`,
    ...headerList('To', message.to),
    ...headerList('Cc', message.cc),
    `Subject: ${encodeHeaderText(message.subject)}`,
    `Date: ${date.toUTCString().replace('GMT', '+0000')}`,
    `Message-ID: <${message.messageId}>`,
    ...(message.inReplyTo ? [`In-Reply-To: <${message.inReplyTo}>`] : []),
    ...(message.references?.length ? [`References: ${message.references.map((id) => `<${id}>`).join('\r\n ')}`] : []),
    ...(message.autocryptKey ? [autocryptHeader(message.from.address, message.autocryptKey)] : []),
    'MIME-Version: 1.0',
  ]
}

/**
 * The message's body as one MIME entity, from its Content-Type on:
 * multipart/alternative (text and HTML), inside multipart/mixed when there
 * are attachments. What PGP/MIME encrypts (RFC 3156).
 */
export function buildBody(message: Pick<OutgoingMessage, 'html' | 'text' | 'attachments'>): Uint8Array {
  const alternativeBoundary = boundary()
  const alternative = [
    `Content-Type: multipart/alternative; boundary="${alternativeBoundary}"`,
    '',
    `--${alternativeBoundary}`,
    textPart('text/plain', message.text),
    `--${alternativeBoundary}`,
    textPart('text/html', message.html),
    `--${alternativeBoundary}--`,
    '',
  ].join('\r\n')
  const attachments = message.attachments ?? []
  if (attachments.length === 0) return encoder.encode(alternative)
  const mixedBoundary = boundary()
  const chunks: Uint8Array[] = [
    encoder.encode(`Content-Type: multipart/mixed; boundary="${mixedBoundary}"\r\n\r\n--${mixedBoundary}\r\n${alternative}`),
  ]
  for (const part of attachments) {
    chunks.push(encoder.encode(`\r\n--${mixedBoundary}\r\n`), part)
  }
  chunks.push(encoder.encode(`\r\n--${mixedBoundary}--\r\n`))
  return concat(chunks)
}

/**
 * The message as sent in plaintext: its header fields and `buildBody`.
 * Never a Bcc header: Bcc recipients get the same message, and only the
 * sender's row keeps them.
 */
export function buildMessage(message: OutgoingMessage): Uint8Array {
  return concat([encoder.encode(`${headerFields(message).join('\r\n')}\r\n`), buildBody(message)])
}

/**
 * The message as sent to OpenPGP recipients (RFC 3156 `multipart/encrypted`):
 * the same header fields, and `armored`, the body (`buildBody`) encrypted
 * and signed. The subject stays readable, as at Proton.
 */
export function buildPgpMessage(message: Omit<OutgoingMessage, 'html' | 'text' | 'attachments'>, armored: string): Uint8Array {
  const outer = boundary()
  return encoder.encode(
    [
      ...headerFields({ ...message, html: '', text: '' }),
      `Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="${outer}"`,
      '',
      'This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)',
      `--${outer}`,
      'Content-Type: application/pgp-encrypted',
      'Content-Description: PGP/MIME version identification',
      '',
      'Version: 1',
      '',
      `--${outer}`,
      'Content-Type: application/octet-stream; name="encrypted.asc"',
      'Content-Description: OpenPGP encrypted message',
      'Content-Disposition: inline; filename="encrypted.asc"',
      '',
      armored.replace(/\r?\n/g, '\r\n').trimEnd(),
      `--${outer}--`,
      '',
    ].join('\r\n'),
  )
}

/** A new Message-ID on this server's domain. */
export function newMessageId(domain: string): string {
  return `${crypto.randomUUID()}@${domain}`
}

/** The name, type and decoded size of a part made by `attachmentPart`. */
export function describePart(part: Uint8Array): { name: string; type: string; size: number } {
  const text = new TextDecoder().decode(part)
  const split = text.indexOf('\r\n\r\n')
  const head = split >= 0 ? text.slice(0, split) : text
  const body = split >= 0 ? text.slice(split + 4).replace(/\s+/g, '') : ''
  const name = /filename="([^"]*)"/i.exec(head)?.[1] ?? /name="([^"]*)"/i.exec(head)?.[1] ?? ''
  const type = /^Content-Type:\s*([^;\s]+)/im.exec(head)?.[1] ?? 'application/octet-stream'
  const padding = body.endsWith('==') ? 2 : body.endsWith('=') ? 1 : 0
  return { name: decodeWords(name.replace(/\r\n /g, '')), type, size: Math.max(0, (body.length * 3) / 4 - padding) }
}
