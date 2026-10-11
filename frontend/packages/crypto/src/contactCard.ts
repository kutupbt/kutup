import { getCryptoWasm } from './rustWasm'

// Contacts (docs/plans/contacts.md): the readable summary signed by the
// account authority, and the vCard sealed under the contacts key, both in
// Rust (kutup-crypto `contact_card`).

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
  account: string,
  summary: ContactSummary,
): Promise<{ summary: string; signature: string }> {
  return (await getCryptoWasm()).signContactSummary(masterKeyBase64, account, JSON.stringify(summary))
}

/** Verifies a stored summary against the account authority and parses it. */
export async function verifyContactSummary(
  summary: string,
  signature: string,
  account: string,
  authorityPublicKeyBase64: string,
): Promise<ContactSummary> {
  return (await getCryptoWasm()).verifyContactSummary(summary, signature, account, authorityPublicKeyBase64)
}

export async function sealContactCard(masterKeyBase64: string, account: string, uid: string, vcard: string): Promise<string> {
  return (await getCryptoWasm()).sealContactCard(masterKeyBase64, account, uid, vcard)
}

export async function openContactCard(masterKeyBase64: string, account: string, uid: string, sealed: string): Promise<string> {
  return (await getCryptoWasm()).openContactCard(masterKeyBase64, account, uid, sealed)
}

/** What a sealed mail name names (docs/plans/mail-filters.md). */
export type MailNameKind = 'folder' | 'label' | 'filter'

/** Seals a mail folder, label or filter name, bound to the account, its kind and its id (a UUID). */
export async function sealMailName(masterKeyBase64: string, account: string, kind: MailNameKind, id: string, name: string): Promise<string> {
  return (await getCryptoWasm()).sealMailName(masterKeyBase64, account, kind, id, name)
}

export async function openMailName(masterKeyBase64: string, account: string, kind: MailNameKind, id: string, sealed: string): Promise<string> {
  return (await getCryptoWasm()).openMailName(masterKeyBase64, account, kind, id, sealed)
}
