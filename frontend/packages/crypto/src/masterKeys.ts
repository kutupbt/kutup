// The account's master keys (docs/plans/mk-rotation-exercise.md): the
// current one, which everything new is sealed under, and every older one,
// reached through the keyring a rotation keeps, which still opens what was
// sealed before it. The WASM picks the key by the generation a record's
// header names; a page never chooses one.

import { fromBase64, toBase64 } from './base64'
import { getCryptoWasm } from './rustWasm'

declare const masterKeysBrand: unique symbol
/**
 * The set as the page holds and passes it: base64 of Rust
 * `MasterKeys::encode` (`KUTPMKS1`, a count, then each generation and key,
 * newest first). A branded string, so a bare master key passed where the
 * set belongs fails to compile.
 */
export type MasterKeys = string & { readonly [masterKeysBrand]: 'masterKeys' }

/** A new account's master key: generation 1. */
export const FIRST_MASTER_KEY_GENERATION = 1

const MAGIC = 'KUTPMKS1'
const ENTRY = 4 + 32

/** A new account's set: `masterKey` at generation 1, no keyring. */
export function firstMasterKeys(masterKey: Uint8Array): MasterKeys {
  if (masterKey.length !== 32) throw new Error('a master key is 32 bytes')
  const out = new Uint8Array(MAGIC.length + 2 + ENTRY)
  out.set(new TextEncoder().encode(MAGIC))
  out[MAGIC.length + 1] = 1
  new DataView(out.buffer).setUint32(MAGIC.length + 2, FIRST_MASTER_KEY_GENERATION)
  out.set(masterKey, MAGIC.length + 2 + 4)
  return toBase64(out) as MasterKeys
}

/** The current master key (32 bytes): the set's newest. */
export function currentMasterKey(keys: MasterKeys): Uint8Array {
  masterKeyGeneration(keys)
  return fromBase64(keys).slice(MAGIC.length + 2 + 4, MAGIC.length + 2 + ENTRY)
}

/** A master key and the generation it is the account's at: what a password or recovery wrap holds. */
export interface MasterKeyAt {
  key: Uint8Array
  generation: number
}

/** The set's current key, with its generation (for a password wrap). */
export function currentMasterKeyAt(keys: MasterKeys): MasterKeyAt {
  return { key: currentMasterKey(keys), generation: masterKeyGeneration(keys) }
}

/** The current master key's generation: what new records are sealed at. */
export function masterKeyGeneration(keys: MasterKeys): number {
  const bytes = fromBase64(keys)
  if (bytes.length < MAGIC.length + 2 + ENTRY || new TextDecoder().decode(bytes.subarray(0, MAGIC.length)) !== MAGIC) {
    throw new Error('not a master-key set')
  }
  return new DataView(bytes.buffer, bytes.byteOffset).getUint32(MAGIC.length + 2)
}

declare const masterKeysBytesBrand: unique symbol
/** The set as raw bytes, for the WASM calls that take bytes (Chat core, Pass, mail search). */
export type MasterKeysBytes = Uint8Array & { readonly [masterKeysBytesBrand]: 'masterKeys' }

export function masterKeysBytes(keys: MasterKeys): MasterKeysBytes {
  return fromBase64(keys) as MasterKeysBytes
}

/**
 * The account's set after a sign-in: `masterKey`, which `envelope` (the
 * password or recovery wrap) held, at the generation its header names, and
 * every older key through `keyring` (`masterKeyring` of the sign-in answer
 * or `GET /api/v1/account/roots`). Throws on a broken or newer keyring.
 */
export async function openMasterKeys(masterKey: Uint8Array, envelope: string, binding: string, keyring: readonly string[]): Promise<MasterKeys> {
  return (await getCryptoWasm()).openMasterKeys(toBase64(masterKey), envelope, binding, [...keyring]) as MasterKeys
}
