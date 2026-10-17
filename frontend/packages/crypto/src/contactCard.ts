import { getCryptoWasm } from './rustWasm'

// Contacts (docs/plans/contacts.md): the readable summary signed by the
// account authority, and the vCard sealed under the contacts key, both bound
// to the account's key binding (`session.envelopeBinding`), never to its
// address, both in Rust (kutup-crypto `contact_card`). Both carry the
// contact's revision (a time in unix milliseconds; `RevisionGuard`): the
// card in its header, the summary in its signature.

/** A sealed value opened, with the revision it was sealed at. */
export interface Revisioned<T> {
  value: T
  revision: number
}

export interface ContactSummary {
  uid: string
  name: string
  emails: { address: string; label?: string }[]
  /** Contact group ids, sorted. */
  groups: string[]
  pinnedKeys: { address: string; fingerprint: string; encrypt: boolean; sign: boolean }[]
}

/** Canonicalizes and signs revision `revision` of a summary; returns the exact JSON text to store. */
export async function signContactSummary(
  masterKeyBase64: string,
  binding: string,
  revision: number,
  summary: ContactSummary,
): Promise<{ summary: string; signature: string }> {
  return (await getCryptoWasm()).signContactSummary(masterKeyBase64, binding, revision, JSON.stringify(summary))
}

/** Verifies a stored summary against the account authority, for its card's revision, and parses it. */
export async function verifyContactSummary(
  summary: string,
  signature: string,
  binding: string,
  revision: number,
  authorityPublicKeyBase64: string,
): Promise<ContactSummary> {
  return (await getCryptoWasm()).verifyContactSummary(summary, signature, binding, revision, authorityPublicKeyBase64)
}

export async function sealContactCard(masterKeyBase64: string, binding: string, uid: string, revision: number, vcard: string): Promise<string> {
  return (await getCryptoWasm()).sealContactCard(masterKeyBase64, binding, uid, revision, vcard)
}

/** The vCard text and the revision the card was sealed at. */
export async function openContactCard(masterKeyBase64: string, binding: string, uid: string, sealed: string): Promise<Revisioned<string>> {
  return (await getCryptoWasm()).openContactCard(masterKeyBase64, binding, uid, sealed)
}

/** What a sealed mail name names (docs/plans/mail-filters.md). */
export type MailNameKind = 'folder' | 'label' | 'filter'

/** Seals revision `revision` of a mail folder, label or filter name, bound to the binding, its kind and its id (a UUID). */
export async function sealMailName(
  masterKeyBase64: string,
  binding: string,
  kind: MailNameKind,
  id: string,
  revision: number,
  name: string,
): Promise<string> {
  return (await getCryptoWasm()).sealMailName(masterKeyBase64, binding, kind, id, revision, name)
}

/** The name and the revision it was sealed at. */
export async function openMailName(masterKeyBase64: string, binding: string, kind: MailNameKind, id: string, sealed: string): Promise<Revisioned<string>> {
  return (await getCryptoWasm()).openMailName(masterKeyBase64, binding, kind, id, sealed)
}
