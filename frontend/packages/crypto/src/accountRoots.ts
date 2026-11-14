// The account's stored roots (docs/plans/identity-root.md): five random
// secrets, each an account record sealed under the master key, so a new
// master key changes nothing a contact sees. Each is its own branded type:
// a master key, or another root, passed where one belongs fails to compile.

import { toBase64 } from './base64'
import { MASTER_KEY_GENERATION } from './masterKeyGeneration'
import { getCryptoWasm } from './rustWasm'

declare const rootKind: unique symbol
type Root<Kind extends string> = string & { readonly [rootKind]: Kind }

/** The identity's root (base64): the authority and both Drive identity keys derive from it. */
export type IdentityRoot = Root<'identity'>
/** The root of the account's own Drive keys (base64). */
export type DriveRoot = Root<'drive'>
/** The root of the account's group pseudonyms (base64). */
export type PseudonymRoot = Root<'pseudonym'>
/** The root of the account's call-link owner secrets (base64). */
export type CallLinkRoot = Root<'callLink'>
/** The key of the account's hashed record ids (base64). */
export type ObjectIdKey = Root<'objectId'>

/** The account's current roots, as the session holds them. */
export interface AccountRoots {
  identityGeneration: number
  identityRoot: IdentityRoot
  driveGeneration: number
  driveRoot: DriveRoot
  pseudonymRoot: PseudonymRoot
  callLinkRoot: CallLinkRoot
  objectIdKey: ObjectIdKey
}

/**
 * What seals and signs as the account: its master key (account records and,
 * until the Drive root takes over, its own collection keys) and its roots.
 * A session is one.
 */
export interface AccountSecrets {
  masterKey: Uint8Array
  roots: AccountRoots
}

/** The start of the error the newest identity root not being the account's gives. */
export const IDENTITY_ROOT_MISMATCH = 'identityRootMismatch'

/** Whether `error` is the account's keys not matching its published authority (show it; no older root stands in). */
export function isIdentityRootMismatch(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error)
  return message.includes(IDENTITY_ROOT_MISMATCH)
}

/**
 * A new account's roots and their records (for the server), sealed under its
 * master key for the key `binding`: at sign-up and at an
 * administrator-made account's setup.
 */
export async function generateAccountRoots(
  masterKey: Uint8Array,
  binding: string,
): Promise<{ roots: AccountRoots; envelopes: string[] }> {
  return (await getCryptoWasm()).generateAccountRoots(toBase64(masterKey), MASTER_KEY_GENERATION, binding) as {
    roots: AccountRoots
    envelopes: string[]
  }
}

/** `roots` sealed again under the master key for the key `binding` (a sign-up whose binding was drawn again). */
export async function sealAccountRoots(masterKey: Uint8Array, binding: string, roots: AccountRoots): Promise<string[]> {
  return (await getCryptoWasm()).sealAccountRoots(toBase64(masterKey), MASTER_KEY_GENERATION, binding, roots)
}

/**
 * The account's roots from its records (`accountRoots` of the sign-in's
 * answer, or `GET /api/account/roots`), opened with its master key. The
 * newest identity root must derive `authorityPublicKey`, the account's
 * published authority; otherwise it throws ({@link isIdentityRootMismatch}).
 */
export async function openAccountRoots(
  masterKey: Uint8Array,
  binding: string,
  envelopes: string[],
  authorityPublicKey: string,
): Promise<AccountRoots> {
  return (await getCryptoWasm()).openAccountRoots(toBase64(masterKey), binding, envelopes, authorityPublicKey) as AccountRoots
}
