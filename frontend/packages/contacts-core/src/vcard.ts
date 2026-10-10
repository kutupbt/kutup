import ICAL from 'ical.js'
import { emptyDraft, type ContactDraft, type ContactKey } from './model'

// vCard text in and out, with ical.js as Proton does (docs/plans/contacts.md).
// Kutup writes vCard 4.0; it reads 3.0 and 4.0, one card or many in a file.
// Pinned OpenPGP keys are written as Proton writes them: each email in its
// own group (`ITEM1.EMAIL`), its key and preferences in the same group
// (`ITEM1.KEY:data:application/pgp-keys;base64,…`, `ITEM1.X-PM-ENCRYPT`,
// `ITEM1.X-PM-SIGN`).

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
    draft.emails.push({ address, label: label(property) })
    const group = scalar(property.getParameter('group')).toLowerCase()
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

/** The first key of each email's group, with its preferences (`fingerprint` is filled in later). */
function keysOf(card: ICAL.Component, groups: Map<string, string>): ContactKey[] {
  const keys: ContactKey[] = []
  const flag = (name: string, group: string) =>
    card.getAllProperties(name).find((p) => scalar(p.getParameter('group')).toLowerCase() === group)
  const byPref = (a: ICAL.Property, b: ICAL.Property) => Number(a.getParameter('pref') ?? 100) - Number(b.getParameter('pref') ?? 100)
  for (const property of [...card.getAllProperties('key')].sort(byPref)) {
    const group = scalar(property.getParameter('group')).toLowerCase()
    const address = groups.get(group)
    const value = text(property.getFirstValue())
    if (!address || !value.toLowerCase().startsWith(KEY_PREFIX) || keys.some((k) => k.address === address)) continue
    const publicKey = value.slice(KEY_PREFIX.length).replace(/\s/g, '')
    if (!/^[A-Za-z0-9+/]+=*$/.test(publicKey)) continue
    // Absent preferences mean yes, as at Proton for a pinned key.
    const yes = (name: string) => text(flag(name, group)?.getFirstValue()).toLowerCase() !== 'false'
    keys.push({ address, publicKey, fingerprint: '', encrypt: yes('x-pm-encrypt'), sign: yes('x-pm-sign') })
  }
  return keys
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
      const key = draft.keys.find((k) => k.address === address.toLowerCase())
      if (!key) return
      // A URI in vCard 4.0: its commas are not escaped as text's are.
      card.addProperty(new ICAL.Property(['key', { group, pref: '1' }, 'uri', `${KEY_PREFIX}${key.publicKey}`], card))
      for (const [name, on] of [
        ['x-pm-encrypt', key.encrypt],
        ['x-pm-sign', key.sign],
      ] as const) {
        const flag = new ICAL.Property(name)
        flag.setParameter('group', group)
        flag.setValue(String(on))
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
