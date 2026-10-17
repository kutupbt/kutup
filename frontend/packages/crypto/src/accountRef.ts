// Who an account is, for good (docs/plans/account-ids.md): its server and its
// permanent account id, Signal's ACI. A username or address is a handle that
// can change, and can later belong to someone else; nothing that must keep
// meaning the same person is keyed by one. Rust owns the rules
// (kutup-crypto account_ref).

import { getCryptoWasm } from './rustWasm'

/** One account: two fields, always. */
export interface AccountRef {
  /** The account's home server: a lowercase DNS name. */
  server: string
  /** Its permanent id: a lowercase hyphenated UUID. */
  accountId: string
}

/**
 * The single-string form, `aci:<uuid>@<server>`, for keys (a store key, a
 * route parameter, a libsignal address). Never shown to a person.
 */
export async function accountKey(account: AccountRef): Promise<string> {
  return (await getCryptoWasm()).accountRefString(account.server, account.accountId)
}

/** `aci:<uuid>@<server>` back to the account; throws for anything else (an address included). */
export async function parseAccountKey(value: string): Promise<AccountRef> {
  return (await getCryptoWasm()).parseAccountRef(value)
}

/** Whether two references are one account. */
export function sameAccount(a: AccountRef, b: AccountRef): boolean {
  return a.server === b.server && a.accountId === b.accountId
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/

/** Rust's `valid_server`: two labels or more of `a-z 0-9 -`, at most 253 bytes, no IP. */
function validServer(value: string): boolean {
  const labels = value.split('.')
  if (value.length === 0 || value.length > 253 || labels.length < 2 || !labels.every((label) => LABEL.test(label))) return false
  // An IPv4 address as Rust parses one: four decimal octets, no leading zeros.
  const octet = /^(?:0|[1-9]\d{0,2})$/
  return !(labels.length === 4 && labels.every((label) => octet.test(label) && Number(label) <= 255))
}

/**
 * Whether `value` is an account's string form, exactly as Rust writes it
 * (`AccountRef`'s Display): for synchronous checks of stored values, the
 * same rule as `parseAccountKey` (checked against the shared vectors).
 */
export function isAccountKey(value: string): boolean {
  if (!value.startsWith('aci:')) return false
  const rest = value.slice(4)
  const at = rest.indexOf('@')
  return at === 36 && UUID.test(rest.slice(0, at)) && validServer(rest.slice(at + 1))
}

/** An account's string form, `aci:<uuid>@<server>`; throws for a reference that is not canonical. */
export function accountKeyOf(account: AccountRef): string {
  const key = `aci:${account.accountId}@${account.server}`
  if (!isAccountKey(key)) throw new Error('not a canonical account reference')
  return key
}

/** The account a string form names; null for anything else (an address included). */
export function accountOfKey(value: string): AccountRef | null {
  return isAccountKey(value) ? { server: value.slice(41), accountId: value.slice(4, 40) } : null
}
