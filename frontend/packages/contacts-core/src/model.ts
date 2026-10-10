// A contact as the person edits it (docs/plans/contacts.md). It is written
// out as a vCard 4.0 (RFC 6350), sealed, and its name, emails and groups
// also go into the signed, readable summary the server indexes.

export interface ContactEmail {
  address: string
  /** "home", "work", or the person's own word. */
  label?: string
}

export interface ContactPhone {
  value: string
  label?: string
}

export interface ContactAddress {
  street: string
  locality: string
  region: string
  postcode: string
  country: string
  label?: string
}

/**
 * An outside OpenPGP key pinned for one of the contact's addresses
 * (docs/plans/mail.md, C3; Proton's vCard `KEY` with `X-PM-ENCRYPT` and
 * `X-PM-SIGN`). Its fingerprint also goes into the signed summary.
 */
export interface ContactKey {
  /** Lowercase; one of the contact's emails. */
  address: string
  /** The binary key, base64. */
  publicKey: string
  /** Lowercase hex, 40 digits. */
  fingerprint: string
  /** Encrypt mail to this address with it. */
  encrypt: boolean
  /** Expect mail from this address signed with it. */
  sign: boolean
}

export interface ContactDraft {
  /** Display name (vCard FN). */
  name: string
  givenName: string
  familyName: string
  emails: ContactEmail[]
  phones: ContactPhone[]
  addresses: ContactAddress[]
  organization: string
  title: string
  /** `YYYY-MM-DD`, or `--MM-DD` without a year. */
  birthday: string
  notes: string
  urls: string[]
  /** A small JPEG as a data: URL, or empty. */
  photo: string
  /** Contact group ids. */
  groups: string[]
  /** Pinned OpenPGP keys, at most one per address. */
  keys: ContactKey[]
}

export function emptyDraft(): ContactDraft {
  return {
    name: '',
    givenName: '',
    familyName: '',
    emails: [],
    phones: [],
    addresses: [],
    organization: '',
    title: '',
    birthday: '',
    notes: '',
    urls: [],
    photo: '',
    groups: [],
    keys: [],
  }
}

/** The name to show and sign: the display name, else given + family, else the first email. */
export function displayName(draft: Pick<ContactDraft, 'name' | 'givenName' | 'familyName' | 'emails'>): string {
  const name = draft.name.trim()
  if (name) return name
  const joined = `${draft.givenName.trim()} ${draft.familyName.trim()}`.trim()
  if (joined) return joined
  return draft.emails.find((email) => email.address.trim())?.address.trim() ?? ''
}

/** A contact as stored and opened. */
export interface Contact {
  id: string
  uid: string
  revision: number
  draft: ContactDraft
  updatedAt: string
}

export interface ContactGroup {
  id: string
  name: string
  color: string
  members: number
}

/** Initials for an avatar without a photo. */
export function initials(name: string): string {
  const words = name.trim().split(/\s+/).filter(Boolean)
  const letters = words.length > 1 ? [words[0][0], words[words.length - 1][0]] : [words[0]?.[0], words[0]?.[1]]
  return letters.filter(Boolean).join('').toLocaleUpperCase()
}

export function newUid(): string {
  return `urn:uuid:${crypto.randomUUID()}`
}

/** `ABCD 1234 …`: an OpenPGP fingerprint as people compare it. */
export function formatFingerprint(fingerprint: string): string {
  return (fingerprint.toUpperCase().match(/.{1,4}/g) ?? []).join(' ')
}
