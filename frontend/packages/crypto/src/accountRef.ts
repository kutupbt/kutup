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
