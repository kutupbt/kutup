// A contact as the person edits it (docs/plans/contacts.md). It is written
// out as a vCard 4.0 (RFC 6350), sealed, and its name, emails and groups
// also go into the signed, readable summary the server indexes.

export interface ContactEmail {
  address: string
  /** "home", "work", or the person's own word. */
  label?: string
  /** How mail to this address is protected (Proton's email settings); unset parts follow the defaults. */
  pgp?: ContactEmailPgp
}

/**
 * PGP for one outside address, as Proton keeps it in the email's vCard group
 * (docs/plans/contact-keys.md): `X-PM-ENCRYPT` (or `X-PM-ENCRYPT-UNTRUSTED`
 * when only found keys exist), `X-PM-SIGN`, `X-PM-SCHEME`.
 */
export interface ContactEmailPgp {
  /** Encrypt to its keys; unset: yes when it has one. */
  encrypt?: boolean
  /** Sign mail to it; unset: the account's "Sign outside mail". Encrypting signs anyway. */
  sign?: boolean
  /** PGP/MIME or Inline; unset: the account's default scheme. */
  scheme?: 'pgp_mime' | 'inline'
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
 * An outside OpenPGP key the person trusts for one of the contact's
 * addresses (docs/plans/contact-keys.md; Proton's vCard `KEY` with `PREF`).
 * An address may have several, in order: the first that can encrypt is used
 * for sending, all of them check signatures, and old ones stay as history.
 * Each fingerprint also goes into the signed summary.
 */
export interface ContactKey {
  /** Lowercase; one of the contact's emails. */
  address: string
  /** The binary key, base64. */
  publicKey: string
  /** Lowercase hex, 40 digits. */
  fingerprint: string
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
  /** Trusted OpenPGP keys of its outside addresses, in order per address. */
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

/** An address's trusted keys, in order. */
export function keysFor(draft: Pick<ContactDraft, 'keys'>, address: string): ContactKey[] {
  const lower = address.trim().toLowerCase()
  return draft.keys.filter((key) => key.address === lower)
}

/** The PGP preferences of one of the contact's addresses. */
export function pgpFor(draft: Pick<ContactDraft, 'emails'>, address: string): ContactEmailPgp {
  const lower = address.trim().toLowerCase()
  return draft.emails.find((email) => email.address.trim().toLowerCase() === lower)?.pgp ?? {}
}
