import { describe, expect, it } from 'vitest'
import { buildBody, buildMessage, buildPgpMessage, parseMessage } from './mime'
import { autocryptKey, openPgp, type PgpCrypto } from './pgp'

const encoder = new TextEncoder()
const bytes = (text: string) => encoder.encode(text)
const decoder = new TextDecoder()

const ARMORED = '-----BEGIN PGP MESSAGE-----\r\n\r\nwcBMA0pretend\r\n-----END PGP MESSAGE-----'
const INNER =
  'Content-Type: multipart/alternative; boundary="alt"\r\n\r\n--alt\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nMerhaba dünya\r\n--alt\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Merhaba dünya</p>\r\n--alt--\r\n'
const HEADERS = 'From: Dave <dave@example.org>\r\nTo: alice@kutup.dev\r\nSubject: Gizli\r\nMessage-ID: <m1@example.org>\r\nMIME-Version: 1.0\r\n'

/** Crypto that "decrypts" ARMORED to `inner`, signed by key "dave" alone. */
function fakeCrypto(inner: string, signed = true): PgpCrypto & { decrypted: string[] } {
  const decrypted: string[] = []
  return {
    decrypted,
    decrypt: (message, signerKey) => {
      decrypted.push(decoder.decode(message))
      if (decoder.decode(message) !== ARMORED) return Promise.reject(new Error('not for me'))
      return Promise.resolve({ data: bytes(inner), signed, verified: signed && signerKey === 'dave' })
    },
    verifyDetached: (signature, content, key) =>
      Promise.resolve(decoder.decode(signature).includes('sig-over') && decoder.decode(content).startsWith('Content-Type: text/plain') && key === 'dave'),
    verifyCleartext: (message, key) =>
      Promise.resolve({ text: message.split('\r\n\r\n')[1].split('\r\n-----BEGIN PGP SIGNATURE')[0], verified: key === 'dave' }),
  }
}

const pgpMime = (armored = ARMORED) =>
  `${HEADERS}Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="b"\r\n\r\nThis is an OpenPGP/MIME encrypted message\r\n--b\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n\r\n--b\r\nContent-Type: application/octet-stream; name="encrypted.asc"\r\n\r\n${armored}\r\n--b--\r\n`

describe('pgp', () => {
  it('opens PGP/MIME under the outer header fields, verified only with a pinned key', async () => {
    const crypto = fakeCrypto(INNER)
    const opened = await openPgp(bytes(pgpMime()), crypto, ['eve', 'dave'])
    expect(opened).toMatchObject({ encrypted: true, signed: true, verified: true })
    const parsed = await parseMessage(opened!.message)
    expect(parsed.subject).toBe('Gizli')
    expect(parsed.from).toEqual({ address: 'dave@example.org', name: 'Dave' })
    expect(parsed.text?.trim()).toBe('Merhaba dünya')
    expect(parsed.html).toContain('<p>Merhaba dünya</p>')
    expect(crypto.decrypted[0]).toBe(ARMORED)

    // Without a pinned key the signature is there but not checked.
    expect(await openPgp(bytes(pgpMime()), fakeCrypto(INNER), [])).toMatchObject({ signed: true, verified: false })
    expect(await openPgp(bytes(pgpMime()), fakeCrypto(INNER, false), ['dave'])).toMatchObject({ signed: false, verified: false })
  })

  it('lets protected headers in the encrypted part win', async () => {
    const inner = `Subject: Real subject\r\n${INNER}`
    const parsed = await parseMessage((await openPgp(bytes(pgpMime()), fakeCrypto(inner), []))!.message)
    expect(parsed.subject).toBe('Real subject')
  })

  it('verifies multipart/signed over the exact signed part', async () => {
    const signedPart = 'Content-Type: text/plain; charset=utf-8\r\n\r\nSigned text\r\n'
    const raw = `${HEADERS}Content-Type: multipart/signed; micalg=pgp-sha256; protocol="application/pgp-signature"; boundary="s"\r\n\r\n--s\r\n${signedPart}\r\n--s\r\nContent-Type: application/pgp-signature\r\n\r\n-----BEGIN PGP SIGNATURE-----\r\nsig-over\r\n-----END PGP SIGNATURE-----\r\n--s--\r\n`
    const opened = await openPgp(bytes(raw), fakeCrypto(''), ['dave'])
    expect(opened).toMatchObject({ encrypted: false, signed: true, verified: true })
    expect((await parseMessage(opened!.message)).text?.trim()).toBe('Signed text')
    expect(await openPgp(bytes(raw), fakeCrypto(''), ['eve'])).toMatchObject({ signed: true, verified: false })
  })

  it('opens inline PGP and cleartext signatures', async () => {
    const inline = `${HEADERS}Content-Type: text/plain; charset=us-ascii\r\n\r\n${ARMORED}\r\n`
    const opened = await openPgp(bytes(inline), fakeCrypto('Gizli metin ğ'), ['dave'])
    expect(opened).toMatchObject({ encrypted: true, verified: true })
    expect((await parseMessage(opened!.message)).text?.trim()).toBe('Gizli metin ğ')

    const clear = `${HEADERS}Content-Type: text/plain; charset=utf-8\r\n\r\n-----BEGIN PGP SIGNED MESSAGE-----\r\nHash: SHA256\r\n\r\nImzalı ğ\r\n-----BEGIN PGP SIGNATURE-----\r\nx\r\n-----END PGP SIGNATURE-----\r\n`
    const signed = await openPgp(bytes(clear), fakeCrypto(''), ['dave'])
    expect(signed).toMatchObject({ encrypted: false, signed: true, verified: true })
    expect((await parseMessage(signed!.message)).text?.trim()).toBe('Imzalı ğ')
  })

  it('leaves other mail alone', async () => {
    expect(await openPgp(bytes(`${HEADERS}Content-Type: text/plain\r\n\r\nSee ${ARMORED} below\r\n`), fakeCrypto(''), [])).toBeNull()
    expect(await openPgp(bytes(pgpMime().replace('application/pgp-encrypted"', 'application/pkcs7-mime"')), fakeCrypto(''), [])).toBeNull()
    expect(await openPgp(bytes(`${HEADERS}\r\nplain`), fakeCrypto(''), [])).toBeNull()
  })

  it('reads the Autocrypt key for the From address only', () => {
    const raw = (addr: string, extra = '') =>
      bytes(`From: dave@example.org\r\nAutocrypt: addr=${addr}; prefer-encrypt=mutual;${extra} keydata=\r\n AQID\r\n BA==\r\nSubject: x\r\n\r\nbody`)
    expect([...autocryptKey(raw('Dave@Example.org'), 'dave@example.org')!]).toEqual([1, 2, 3, 4])
    expect(autocryptKey(raw('eve@example.org'), 'dave@example.org')).toBeNull()
    expect(autocryptKey(raw('dave@example.org', ' critical=yes;'), 'dave@example.org')).toBeNull()
    expect(autocryptKey(raw('dave@example.org', ' _optional=yes;'), 'dave@example.org')).not.toBeNull()
  })

  it('builds PGP/MIME that opens back, with the same header fields and an Autocrypt header', async () => {
    const header = {
      from: { address: 'alice@kutup.dev', name: 'Alice' },
      to: [{ address: 'dave@example.org', name: '' }],
      cc: [],
      subject: 'Şifreli',
      messageId: 'm2@kutup.dev',
      date: new Date('2026-10-10T08:00:00Z'),
      autocryptKey: 'A'.repeat(200),
    }
    const body = buildBody({ html: '<p>gizli</p>', text: 'gizli' })
    const raw = buildPgpMessage(header, '-----BEGIN PGP MESSAGE-----\n\nwcBMA0pretend\n-----END PGP MESSAGE-----\n')
    const text = decoder.decode(raw)
    expect(text).toContain('Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"')
    expect(text).toContain(`\r\n${ARMORED}\r\n`)
    expect(text).not.toContain('gizli')
    expect(text.split('\r\n').every((line) => line.length <= 998)).toBe(true)
    const opened = await openPgp(raw, fakeCrypto(decoder.decode(body)), [])
    const parsed = await parseMessage(opened!.message)
    expect(parsed.subject).toBe('Şifreli')
    expect(parsed.messageId).toBe('m2@kutup.dev')
    expect(parsed.text?.trim()).toBe('gizli')

    // The plaintext message carries the same Autocrypt header, folded.
    const plain = buildMessage({ ...header, html: '<p>x</p>', text: 'x' })
    const key = autocryptKey(plain, 'alice@kutup.dev')
    expect(key).not.toBeNull()
    expect(btoa(String.fromCharCode(...key!))).toBe('A'.repeat(200))
    expect(decoder.decode(plain).split('\r\n').every((line) => line.length <= 78)).toBe(true)
  })
})
