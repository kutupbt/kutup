import type { MasterKeys } from './masterKeys'
import type { IdentityRoot } from './accountRoots'
import { getCryptoWasm } from './rustWasm'

// Contacts (docs/plans/contacts.md): the readable summary signed by the
// account authority, and the vCard sealed as an account record under the master key, both bound
// to the account's key binding (`session.envelopeBinding`), never to its
// address, both in Rust (kutup-crypto `contact_card`). Both carry the
// contact's revision (a time in unix milliseconds; `RevisionGuard`): the
// card in its header, the summary in its signature.

/** A sealed value opened, with the revision it was sealed at. */
export interface Revisioned<T> {
  value: T
  revision: number
}

/**
 * A contact's signed summary. `v` is its format version (1 when absent);
 * Rust keeps any field a newer client added, and signs every object with its
 * keys sorted (docs/plans/format-evolution.md).
 */
export interface ContactSummary {
  v?: number
  uid: string
  name: string
  emails: { address: string; label?: string }[]
  /** Contact group ids, sorted. */
  groups: string[]
  /** `keyVersion` is the OpenPGP key version: 4 (40 hex digits) or 6 (64). */
  pinnedKeys: { address: string; keyVersion: number; fingerprint: string; encrypt: boolean; sign: boolean }[]
}

const SUMMARY_FIELDS = new Set(['uid', 'name', 'emails', 'groups', 'pinnedKeys'])

/** A verified summary's version and the fields a newer client added: what a save signs again. */
export function contactSummaryRest(summary: ContactSummary): Record<string, unknown> {
  return Object.fromEntries(Object.entries(summary).filter(([key]) => !SUMMARY_FIELDS.has(key)))
}

/** Canonicalizes and signs revision `revision` of a summary; returns the exact JSON text to store. */
export async function signContactSummary(
  identityRoot: IdentityRoot,
  binding: string,
  revision: number,
  summary: ContactSummary,
): Promise<{ summary: string; signature: string }> {
  return (await getCryptoWasm()).signContactSummary(identityRoot, binding, revision, JSON.stringify({ v: 1, ...summary }))
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

export async function sealContactCard(masterKeys: MasterKeys, binding: string, uid: string, revision: number, vcard: string): Promise<string> {
  return (await getCryptoWasm()).sealContactCard(masterKeys, binding, uid, revision, vcard)
}

/** The vCard text and the revision the card was sealed at. */
export async function openContactCard(masterKeys: MasterKeys, binding: string, uid: string, sealed: string): Promise<Revisioned<string>> {
  return (await getCryptoWasm()).openContactCard(masterKeys, binding, uid, sealed)
}

/** What a sealed mail name names (docs/plans/mail-filters.md). */
export type MailNameKind = 'folder' | 'label' | 'filter'

/** Seals revision `revision` of a mail folder, label or filter name, bound to the binding, its kind and its id (a UUID). */
export async function sealMailName(
  masterKeys: MasterKeys,
  binding: string,
  kind: MailNameKind,
  id: string,
  revision: number,
  name: string,
): Promise<string> {
  return (await getCryptoWasm()).sealMailName(masterKeys, binding, kind, id, revision, name)
}

/** The name and the revision it was sealed at. */
export async function openMailName(masterKeys: MasterKeys, binding: string, kind: MailNameKind, id: string, sealed: string): Promise<Revisioned<string>> {
  return (await getCryptoWasm()).openMailName(masterKeys, binding, kind, id, sealed)
}
