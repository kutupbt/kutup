// OpenPGP mail from outside Kutup (docs/plans/mail.md, C3), opened in the
// browser once the stored message is: RFC 3156 `multipart/encrypted` and
// `multipart/signed`, inline PGP messages and cleartext signatures. The
// result is the message to show: the outer header fields over the opened
// body. Signatures count only against keys the person pinned, as at Proton.

/** Decrypts an OpenPGP message with the address key, checking its signature with `signerKey` (base64) when given. */
export type Decrypt = (message: Uint8Array, signerKey?: string) => Promise<{ data: Uint8Array; signed: boolean; verified: boolean }>

export interface PgpCrypto {
  decrypt: Decrypt
  verifyDetached: (signature: Uint8Array, content: Uint8Array, signerKey: string) => Promise<boolean>
  verifyCleartext: (message: string, signerKey?: string) => Promise<{ text: string; verified: boolean }>
}

export interface PgpOpened {
  /** The message to show, as RFC 5322 bytes. */
  message: Uint8Array
  /** The body was encrypted by its sender. */
  encrypted: boolean
  /** It carried a signature. */
  signed: boolean
  /** The signature checks with one of the sender's pinned keys. */
  verified: boolean
}

const BEGIN_MESSAGE = '-----BEGIN PGP MESSAGE-----'
const END_MESSAGE = '-----END PGP MESSAGE-----'
const BEGIN_SIGNED = '-----BEGIN PGP SIGNED MESSAGE-----'
const END_SIGNATURE = '-----END PGP SIGNATURE-----'

/** Bytes as a string of the same code units, so MIME structure can be found without decoding. */
function binary(bytes: Uint8Array): string {
  let out = ''
  for (let i = 0; i < bytes.length; i += 0x8000) out += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  return out
}

function bytesOf(text: string): Uint8Array {
  const out = new Uint8Array(text.length)
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff
  return out
}

interface Entity {
  /** The header block, without the blank line after it. */
  head: string
  body: string
}

function entity(raw: string): Entity {
  const crlf = raw.indexOf('\r\n\r\n')
  const lf = raw.indexOf('\n\n')
  if (crlf >= 0 && (lf < 0 || crlf <= lf)) return { head: raw.slice(0, crlf), body: raw.slice(crlf + 4) }
  if (lf >= 0) return { head: raw.slice(0, lf), body: raw.slice(lf + 2) }
  return { head: raw, body: '' }
}

/** Header fields, unfolded, as [name, value] in order. */
function fields(head: string): [string, string][] {
  return head
    .replace(/\r?\n[ \t]+/g, ' ')
    .split(/\r?\n/)
    .flatMap((line): [string, string][] => {
      const colon = line.indexOf(':')
      return colon > 0 ? [[line.slice(0, colon).trim().toLowerCase(), line.slice(colon + 1).trim()]] : []
    })
}

interface ContentType {
  type: string
  params: Record<string, string>
}

function contentType(head: string): ContentType {
  const value = fields(head).find(([name]) => name === 'content-type')?.[1] ?? 'text/plain'
  const [type, ...rest] = value.split(';')
  const params: Record<string, string> = {}
  for (const param of rest) {
    const eq = param.indexOf('=')
    if (eq < 0) continue
    params[param.slice(0, eq).trim().toLowerCase()] = param
      .slice(eq + 1)
      .trim()
      .replace(/^"(.*)"$/, '$1')
  }
  return { type: type.trim().toLowerCase(), params }
}

/**
 * A multipart body's parts, each exactly as it stands between its
 * delimiters (the line break before a delimiter belongs to the delimiter),
 * as RFC 3156 signs them.
 */
function parts(body: string, boundary: string): string[] {
  const delimiter = new RegExp(`(?:^|\\r?\\n)--${boundary.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(--)?[ \\t]*(?:\\r?\\n|$)`, 'g')
  const found: string[] = []
  let start = -1
  for (let match = delimiter.exec(body); match; match = delimiter.exec(body)) {
    if (start >= 0) found.push(body.slice(start, match.index))
    if (match[1]) return found
    start = match.index + match[0].length
  }
  return found
}

/** The outer header fields that describe the message, not its content. */
function outerFields(head: string): string[] {
  // Split between fields, keeping each field's folded lines with it.
  return head
    .split(/\r?\n(?![ \t])/)
    .filter((line) => !/^(content-[\w-]+|mime-version)\s*:/i.test(line))
}

/** The outer header fields over an opened body entity; header fields the body repeats (protected headers) win. */
function rewrap(outerHead: string, inner: string): Uint8Array {
  const { head } = entity(inner)
  const repeated = new Set(fields(head).map(([name]) => name))
  const kept = outerFields(outerHead).filter((line) => {
    const name = line.slice(0, line.indexOf(':')).trim().toLowerCase()
    return !repeated.has(name)
  })
  return bytesOf(`${[...kept, 'MIME-Version: 1.0'].join('\r\n')}\r\n${inner}`)
}

/** The outer header fields over a plain text body. */
function rewrapText(outerHead: string, text: string): Uint8Array {
  const utf8 = binary(new TextEncoder().encode(text))
  return bytesOf(
    `${[...outerFields(outerHead), 'MIME-Version: 1.0', 'Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: 8bit'].join('\r\n')}\r\n\r\n${utf8}`,
  )
}

function decodeBody(head: string, body: string): string {
  const encoding = fields(head).find(([name]) => name === 'content-transfer-encoding')?.[1].toLowerCase()
  if (encoding === 'base64') {
    try {
      return atob(body.replace(/[^A-Za-z0-9+/=]/g, ''))
    } catch {
      return body
    }
  }
  if (encoding === 'quoted-printable') {
    return body.replace(/=\r?\n/g, '').replace(/=([0-9A-Fa-f]{2})/g, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)))
  }
  return body
}

/** Decrypts with each key in turn until a signature checks (or with none when there is no key). */
async function decryptChecked(crypto: PgpCrypto, message: Uint8Array, keys: string[]) {
  let opened = await crypto.decrypt(message, keys[0])
  for (const key of keys.slice(1)) {
    if (!opened.signed || opened.verified) break
    opened = await crypto.decrypt(message, key)
  }
  return opened
}

async function verifyDetached(crypto: PgpCrypto, signature: Uint8Array, content: Uint8Array, keys: string[]): Promise<boolean> {
  for (const key of keys) {
    if (await crypto.verifyDetached(signature, content, key).catch(() => false)) return true
  }
  return false
}

async function verifyCleartext(crypto: PgpCrypto, text: string, keys: string[]) {
  let result = await crypto.verifyCleartext(text, keys[0])
  for (const key of keys.slice(1)) {
    if (result.verified) break
    result = await crypto.verifyCleartext(text, key)
  }
  return result
}

/** A `multipart/signed` entity: its signed part (rewrapped under `outerHead`) and whether it verifies. */
async function openSigned(crypto: PgpCrypto, outerHead: string, signed: Entity, keys: string[]) {
  const type = contentType(signed.head)
  const boundary = type.params.boundary
  if (type.type !== 'multipart/signed' || type.params.protocol?.toLowerCase() !== 'application/pgp-signature' || !boundary) return null
  const [content, signaturePart] = parts(signed.body, boundary)
  if (content === undefined || signaturePart === undefined) return null
  const signature = entity(signaturePart)
  const verified = await verifyDetached(crypto, bytesOf(decodeBody(signature.head, signature.body)), bytesOf(content), keys)
  return { message: rewrap(outerHead, content), verified }
}

function wholeArmor(text: string, begin: string, end: string): boolean {
  const trimmed = text.trim()
  return trimmed.startsWith(begin) && trimmed.endsWith(end)
}

/**
 * Opens a message that arrived OpenPGP-encrypted or signed; `null` for any
 * other message. `keys` are the sender's pinned keys (base64) that may sign.
 */
export async function openPgp(raw: Uint8Array, crypto: PgpCrypto, keys: string[]): Promise<PgpOpened | null> {
  const outer = entity(binary(raw))
  const type = contentType(outer.head)

  if (type.type === 'multipart/encrypted') {
    if (type.params.protocol?.toLowerCase() !== 'application/pgp-encrypted' || !type.params.boundary) return null
    const payload = parts(outer.body, type.params.boundary)
      .slice(1)
      .map(entity)
      .find((part) => contentType(part.head).type === 'application/octet-stream')
    if (!payload) return null
    const opened = await decryptChecked(crypto, bytesOf(decodeBody(payload.head, payload.body).trim()), keys)
    const inner = binary(opened.data)
    // Signed and encrypted in two layers (RFC 3156 section 6.1).
    const signed = await openSigned(crypto, outer.head, entity(inner), keys)
    if (signed) return { message: signed.message, encrypted: true, signed: true, verified: signed.verified }
    return { message: rewrap(outer.head, inner), encrypted: true, signed: opened.signed, verified: opened.signed && opened.verified }
  }

  if (type.type === 'multipart/signed') {
    const signed = await openSigned(crypto, outer.head, outer, keys)
    return signed ? { message: signed.message, encrypted: false, signed: true, verified: signed.verified } : null
  }

  if (type.type === 'text/plain') {
    const text = decodeBody(outer.head, outer.body)
    if (wholeArmor(text, BEGIN_MESSAGE, END_MESSAGE)) {
      const opened = await decryptChecked(crypto, bytesOf(text.trim()), keys)
      const plain = new TextDecoder().decode(opened.data)
      // An inline message may itself be cleartext-signed inside.
      if (wholeArmor(plain, BEGIN_SIGNED, END_SIGNATURE)) {
        const result = await verifyCleartext(crypto, plain.trim(), keys)
        return { message: rewrapText(outer.head, result.text), encrypted: true, signed: true, verified: result.verified }
      }
      return { message: rewrapText(outer.head, plain), encrypted: true, signed: opened.signed, verified: opened.signed && opened.verified }
    }
    if (wholeArmor(text, BEGIN_SIGNED, END_SIGNATURE)) {
      const charset = type.params.charset?.toLowerCase()
      const decoded = charset && charset !== 'utf-8' && charset !== 'us-ascii' ? text : new TextDecoder().decode(bytesOf(text))
      const result = await verifyCleartext(crypto, decoded.trim(), keys)
      return { message: rewrapText(outer.head, result.text), encrypted: false, signed: true, verified: result.verified }
    }
  }
  return null
}

/**
 * The key an outside sender offers in `raw`: its Autocrypt header for the
 * From address (Level 1), binary. Keys attached as files are found by the
 * caller among the parsed attachments.
 */
export function autocryptKey(raw: Uint8Array, from: string): Uint8Array | null {
  const { head } = entity(binary(raw.subarray(0, Math.min(raw.length, 256 * 1024))))
  for (const [name, value] of fields(head)) {
    if (name !== 'autocrypt') continue
    const attributes = new Map<string, string>()
    for (const attribute of value.split(';')) {
      const eq = attribute.indexOf('=')
      if (eq > 0) attributes.set(attribute.slice(0, eq).trim().toLowerCase(), attribute.slice(eq + 1).trim())
    }
    // Unknown critical attributes (not starting with `_`) make it unusable.
    const known = new Set(['addr', 'prefer-encrypt', 'keydata'])
    if ([...attributes.keys()].some((key) => !known.has(key) && !key.startsWith('_'))) continue
    if (attributes.get('addr')?.toLowerCase() !== from.toLowerCase()) continue
    const keydata = attributes.get('keydata')?.replace(/\s/g, '')
    if (!keydata) continue
    try {
      return bytesOf(atob(keydata))
    } catch {
      continue
    }
  }
  return null
}
