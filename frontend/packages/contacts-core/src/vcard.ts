import ICAL from 'ical.js'
import { emptyDraft, type ContactDraft, type ContactEmailPgp, type ContactKey } from './model'

// vCard text in and out, with ical.js as Proton does (docs/plans/contacts.md).
// Kutup writes vCard 4.0; it reads 3.0 and 4.0, one card or many in a file.
// Trusted OpenPGP keys are written as Proton writes them
// (docs/plans/contact-keys.md): each email in its own group (`ITEM1.EMAIL`),
// its keys in the same group in order (`ITEM1.KEY;PREF=1:data:application/
// pgp-keys;base64,…`, `PREF=2`, …) and its preferences beside them:
// `ITEM1.X-PM-ENCRYPT` (or `X-PM-ENCRYPT-UNTRUSTED` without keys),
// `ITEM1.X-PM-SIGN`, `ITEM1.X-PM-SCHEME`.

const KEY_PREFIX = 'data:application/pgp-keys;base64,'

const PRODID = '-//Kutup//Contacts//EN'

/** A value ical.js hands back: strings, numbers, arrays of them, or a typed object with toString(). */
function scalar(value: unknown): string {
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  if (value && typeof value === 'object' && typeof (value as { toString?: unknown }).toString === 'function') {
    return (value as { toString(): string }).toString()
  }
  return ''
}

function label(property: ICAL.Property): string | undefined {
  const type: unknown = property.getParameter('type')
  const types = (Array.isArray(type) ? type : [type]).map((t) => scalar(t).toLowerCase())
  return types.find((t) => t && t !== 'pref' && t !== 'internet')
}

function text(value: unknown): string {
  if (Array.isArray(value)) return value.map(text).join(' ').trim()
  return value == null ? '' : scalar(value).trim()
}

/** One card's properties into a draft (unknown properties are dropped). */
function componentToDraft(card: ICAL.Component): ContactDraft {
  const draft = emptyDraft()
  draft.name = text(card.getFirstPropertyValue('fn'))
  const n = card.getFirstPropertyValue('n')
  if (Array.isArray(n)) {
    draft.familyName = text(n[0])
    draft.givenName = text(n[1])
  }
  const groups = new Map<string, string>()
  for (const property of card.getAllProperties('email')) {
    const address = text(property.getFirstValue()).replace(/^mailto:/i, '')
    if (!address) continue
    const group = scalar(property.getParameter('group')).toLowerCase()
    const pgp = group ? pgpOf(card, group) : undefined
    draft.emails.push({ address, label: label(property), ...(pgp ? { pgp } : {}) })
    if (group && !groups.has(group)) groups.set(group, address.toLowerCase())
  }
  draft.keys = keysOf(card, groups)
  for (const property of card.getAllProperties('tel')) {
    const value = text(property.getFirstValue()).replace(/^tel:/i, '')
    if (value) draft.phones.push({ value, label: label(property) })
  }
  for (const property of card.getAllProperties('adr')) {
    const value = property.getFirstValue()
    const parts = Array.isArray(value) ? value.map(text) : [text(value)]
    // pobox, extended, street, locality, region, postcode, country
    const address = {
      street: [parts[1], parts[2]].filter(Boolean).join(', '),
      locality: parts[3] ?? '',
      region: parts[4] ?? '',
      postcode: parts[5] ?? '',
      country: parts[6] ?? '',
      label: label(property),
    }
    if (address.street || address.locality || address.region || address.postcode || address.country) draft.addresses.push(address)
  }
  const org = card.getFirstPropertyValue('org')
  draft.organization = text(Array.isArray(org) ? org[0] : org)
  draft.title = text(card.getFirstPropertyValue('title'))
  const bday = card.getFirstPropertyValue('bday')
  draft.birthday = bday ? birthdayText(bday) : ''
  draft.notes = card.getAllProperties('note').map((p) => text(p.getFirstValue())).filter(Boolean).join('\n\n')
  draft.urls = card.getAllProperties('url').map((p) => text(p.getFirstValue())).filter(Boolean)
  const photo = card.getFirstProperty('photo')
  if (photo) draft.photo = photoText(photo)
  return draft
}

/** Each email group's keys in `PREF` order (`fingerprint` is filled in later). */
function keysOf(card: ICAL.Component, groups: Map<string, string>): ContactKey[] {
  const keys: ContactKey[] = []
  const byPref = (a: ICAL.Property, b: ICAL.Property) => Number(a.getParameter('pref') ?? 100) - Number(b.getParameter('pref') ?? 100)
  for (const property of [...card.getAllProperties('key')].sort(byPref)) {
    const group = scalar(property.getParameter('group')).toLowerCase()
    const address = groups.get(group)
    const value = text(property.getFirstValue())
    if (!address || !value.toLowerCase().startsWith(KEY_PREFIX)) continue
    const publicKey = value.slice(KEY_PREFIX.length).replace(/\s/g, '')
    if (!/^[A-Za-z0-9+/]+=*$/.test(publicKey) || keys.some((k) => k.address === address && k.publicKey === publicKey)) continue
    keys.push({ address, publicKey, fingerprint: '' })
  }
  return keys
}

/** An email group's preferences, when it has any. */
function pgpOf(card: ICAL.Component, group: string): ContactEmailPgp | undefined {
  const value = (name: string) => {
    const property = card.getAllProperties(name).find((p) => scalar(p.getParameter('group')).toLowerCase() === group)
    return property ? text(property.getFirstValue()).toLowerCase() : undefined
  }
  const flag = (raw: string | undefined) => (raw === 'true' ? true : raw === 'false' ? false : undefined)
  const pgp: ContactEmailPgp = {}
  const encrypt = flag(value('x-pm-encrypt')) ?? flag(value('x-pm-encrypt-untrusted'))
  if (encrypt !== undefined) pgp.encrypt = encrypt
  const sign = flag(value('x-pm-sign'))
  if (sign !== undefined) pgp.sign = sign
  const scheme = value('x-pm-scheme')
  if (scheme === 'pgp-inline') pgp.scheme = 'inline'
  else if (scheme === 'pgp-mime') pgp.scheme = 'pgp_mime'
  return Object.keys(pgp).length ? pgp : undefined
}

function birthdayText(value: unknown): string {
  const raw = scalar(value)
  const full = raw.match(/^(\d{4})-?(\d{2})-?(\d{2})/)
  if (full) return `${full[1]}-${full[2]}-${full[3]}`
  const noYear = raw.match(/^--(\d{2})-?(\d{2})/)
  return noYear ? `--${noYear[1]}-${noYear[2]}` : ''
}

function photoText(property: ICAL.Property): string {
  const value = text(property.getFirstValue())
  if (value.startsWith('data:image/')) return value
  // vCard 3.0: ENCODING=b;TYPE=JPEG with the base64 alone.
  const encoding = String(property.getParameter('encoding') ?? '').toLowerCase()
  if (encoding === 'b' || encoding === 'base64') {
    const type = String(property.getParameter('type') ?? 'jpeg').toLowerCase()
    return `data:image/${type === 'jpg' ? 'jpeg' : type};base64,${value.replace(/\s/g, '')}`
  }
  return ''
}

/** Every card in a .vcf file, as drafts with their UIDs where they had one. */
export function parseVCards(source: string): { uid?: string; draft: ContactDraft }[] {
  const parsed: unknown = ICAL.parse(source)
  const roots: unknown[] = Array.isArray(parsed) && typeof parsed[0] === 'string' ? [parsed] : (parsed as unknown[])
  return roots.map((root) => {
    const card = new ICAL.Component(root as never)
    const uid = text(card.getFirstPropertyValue('uid'))
    return { uid: uid || undefined, draft: componentToDraft(card) }
  })
}

function typed(property: ICAL.Property, value?: string) {
  if (value) property.setParameter('type', value)
  return property
}

/** A draft as vCard 4.0 text. */
export function toVCard(draft: ContactDraft, uid: string, name: string): string {
  const card = new ICAL.Component('vcard')
  card.addPropertyWithValue('version', '4.0')
  card.addPropertyWithValue('prodid', PRODID)
  card.addPropertyWithValue('uid', uid)
  card.addPropertyWithValue('fn', name)
  if (draft.givenName || draft.familyName) {
    const n = new ICAL.Property('n')
    n.setValue([draft.familyName, draft.givenName, '', '', ''] as never)
    card.addProperty(n)
  }
  draft.emails
    .filter((email) => email.address.trim())
    .forEach((email, i) => {
      const group = `item${i + 1}`
      const address = email.address.trim()
      const property = typed(new ICAL.Property('email'), email.label)
      property.setParameter('group', group)
      card.addProperty(property).setValue(address)
      const keys = draft.keys.filter((k) => k.address === address.toLowerCase())
      // A URI in vCard 4.0: its commas are not escaped as text's are.
      keys.forEach((key, index) => {
        card.addProperty(new ICAL.Property(['key', { group, pref: String(index + 1) }, 'uri', `${KEY_PREFIX}${key.publicKey}`], card))
      })
      const pgp = email.pgp ?? {}
      const flags: [string, string | undefined][] = [
        // Proton: X-PM-ENCRYPT with trusted keys, X-PM-ENCRYPT-UNTRUSTED for found ones only.
        [keys.length ? 'x-pm-encrypt' : 'x-pm-encrypt-untrusted', pgp.encrypt === undefined ? undefined : String(pgp.encrypt)],
        // Encrypting signs anyway.
        ['x-pm-sign', pgp.encrypt === true ? 'true' : pgp.sign === undefined ? undefined : String(pgp.sign)],
        ['x-pm-scheme', pgp.scheme === 'inline' ? 'pgp-inline' : pgp.scheme === 'pgp_mime' ? 'pgp-mime' : undefined],
      ]
      for (const [name, value] of flags) {
        if (value === undefined) continue
        const flag = new ICAL.Property(name)
        flag.setParameter('group', group)
        flag.setValue(value)
        card.addProperty(flag)
      }
    })
  for (const phone of draft.phones) {
    if (phone.value.trim()) card.addProperty(typed(new ICAL.Property('tel'), phone.label)).setValue(phone.value.trim())
  }
  for (const address of draft.addresses) {
    const adr = typed(new ICAL.Property('adr'), address.label)
    adr.setValue(['', '', address.street, address.locality, address.region, address.postcode, address.country] as never)
    card.addProperty(adr)
  }
  if (draft.organization) card.addPropertyWithValue('org', draft.organization)
  if (draft.title) card.addPropertyWithValue('title', draft.title)
  if (draft.birthday) {
    const bday = new ICAL.Property('bday')
    bday.setParameter('value', 'text')
    bday.setValue(draft.birthday)
    card.addProperty(bday)
  }
  if (draft.notes.trim()) card.addPropertyWithValue('note', draft.notes.trim())
  for (const url of draft.urls) if (url.trim()) card.addPropertyWithValue('url', url.trim())
  if (draft.photo) {
    const photo = new ICAL.Property('photo')
    photo.setParameter('value', 'uri')
    photo.setValue(draft.photo)
    card.addProperty(photo)
  }
  return card.toString().replace(/\r?\n/g, '\r\n') + '\r\n'
}
