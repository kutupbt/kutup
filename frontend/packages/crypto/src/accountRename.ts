// SPDX-FileCopyrightText: 2026 kutup contributors
// SPDX-License-Identifier: AGPL-3.0-only
//
// Account renames (docs/plans/username-renames.md): the format and its checks
// are Rust's (kutup-crypto account_rename); this is the browser's door to them.

import { getCryptoWasm } from './rustWasm'

/** One signed rename, as the server stores and serves it. */
export interface AccountRenameV1 {
  incarnationId: string
  sequence: number
  previous: string
  current: string
  issuedAtMs: number
  signature: string
}

/** What a verified chain says: where the account is now and where it has been. */
export interface RenameChainView {
  incarnationId: string
  first: string
  current: string
  /** Every address the account has had, oldest first. */
  addresses: string[]
  sequence: number
  /** One digest per statement: keep them, so a later chain must extend this one. */
  digests: string[]
}

/**
 * The folded form of a name (`kutup_crypto::names::fold`): lowercase,
 * without `.`, `_` and `-`. One account holds a folded name, so any spelling
 * finds it: compare names folded, show them as stored.
 */
export async function foldName(name: string): Promise<string> {
  return (await getCryptoWasm()).foldName(name)
}

/**
 * The folded form of an address (`kutup_crypto::names::fold_address`): the
 * local part folded, the domain lowercase; null for what is not an address.
 * Every comparison of an address with a saved one uses it.
 */
export async function foldAddress(address: string): Promise<string | null> {
  return (await getCryptoWasm()).foldAddress(address) ?? null
}

/** The next rename of this account, signed with its authority (from the master key). */
export async function signAccountRename(
  masterKeyBase64: string,
  sequence: number,
  previous: string,
  current: string,
  issuedAtMs: number,
): Promise<AccountRenameV1> {
  const json = (await getCryptoWasm()).signAccountRename(masterKeyBase64, sequence, previous, current, issuedAtMs)
  return JSON.parse(json) as AccountRenameV1
}

/**
 * Verifies a rename chain against the account's authority key. Pass the
 * digests of a chain verified before: the new one must extend it, or this
 * throws (a rolled-back or rewritten chain).
 */
export async function verifyAccountRenameChain(
  authorityPublicKey: string,
  chain: readonly AccountRenameV1[],
  knownDigests?: readonly string[],
): Promise<RenameChainView> {
  return (await getCryptoWasm()).verifyAccountRenameChain(
    authorityPublicKey,
    JSON.stringify(chain),
    knownDigests ? JSON.stringify(knownDigests) : null,
  )
}
