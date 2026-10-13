import { getCryptoWasm } from './rustWasm'

// Contacts (docs/plans/contacts.md): the readable summary signed by the
// account authority, and the vCard sealed under the contacts key, both bound
// to the account's key binding (`session.envelopeBinding`), never to its
// address, both in Rust (kutup-crypto `contact_card`).

export interface ContactSummary {
  uid: string
  name: string
  emails: { address: string; label?: string }[]
  /** Contact group ids, sorted. */
  groups: string[]
  pinnedKeys: { address: string; fingerprint: string; encrypt: boolean; sign: boolean }[]
}

/** Canonicalizes and signs a summary; returns the exact JSON text to store. */
export async function signContactSummary(
  masterKeyBase64: string,
  binding: string,
  summary: ContactSummary,
): Promise<{ summary: string; signature: string }> {
  return (await getCryptoWasm()).signContactSummary(masterKeyBase64, binding, JSON.stringify(summary))
}

/** Verifies a stored summary against the account authority and parses it. */
export async function verifyContactSummary(
  summary: string,
  signature: string,
  binding: string,
  authorityPublicKeyBase64: string,
): Promise<ContactSummary> {
  return (await getCryptoWasm()).verifyContactSummary(summary, signature, binding, authorityPublicKeyBase64)
}

export async function sealContactCard(masterKeyBase64: string, binding: string, uid: string, vcard: string): Promise<string> {
  return (await getCryptoWasm()).sealContactCard(masterKeyBase64, binding, uid, vcard)
}

export async function openContactCard(masterKeyBase64: string, binding: string, uid: string, sealed: string): Promise<string> {
  return (await getCryptoWasm()).openContactCard(masterKeyBase64, binding, uid, sealed)
}

/** What a sealed mail name names (docs/plans/mail-filters.md). */
export type MailNameKind = 'folder' | 'label' | 'filter'

/** Seals a mail folder, label or filter name, bound to the binding, its kind and its id (a UUID). */
export async function sealMailName(masterKeyBase64: string, binding: string, kind: MailNameKind, id: string, name: string): Promise<string> {
  return (await getCryptoWasm()).sealMailName(masterKeyBase64, binding, kind, id, name)
}

export async function openMailName(masterKeyBase64: string, binding: string, kind: MailNameKind, id: string, sealed: string): Promise<string> {
  return (await getCryptoWasm()).openMailName(masterKeyBase64, binding, kind, id, sealed)
}
