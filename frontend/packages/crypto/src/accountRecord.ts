import { fromBase64, toBase64 } from './base64'
import { getCryptoWasm } from './rustWasm'
import type { MasterKeys } from './masterKeys'

export const ACCOUNT_RECORD_PURPOSE = {
  passwordMasterKey: 1,
  recoveryMasterKey: 2,
  // 3 was the Drive X-Wing private key, now derived from the master key and
  // never stored (docs/plans/w6-key-hierarchy.md §1): reserved.
  chatBackupRoot: 4,
  /** A mail address's OpenPGP secret key. */
  mailAddressPrivateKey: 5,
  /** A Kutup Pass vault's password and key file. */
  passVaultSecret: 6,
} as const

export type AccountRecordPurpose =
  (typeof ACCOUNT_RECORD_PURPOSE)[keyof typeof ACCOUNT_RECORD_PURPOSE]

/**
 * Seals `plaintext` under `key`: the account's master key of `generation`
 * (its current one: `masterKeyGeneration(session.masterKeys)`), or another
 * key whose records name that generation (the recovery phrase's wrap holds
 * the master key of the generation it names).
 */
export async function sealAccountRecord(
  plaintext: Uint8Array,
  key: Uint8Array,
  purpose: AccountRecordPurpose,
  generation: number,
  /** What the account's keys are bound to (`session.envelopeBinding`), never a name. */
  binding: string,
): Promise<string> {
  const module = await getCryptoWasm()
  return module.sealAccountRecord(toBase64(plaintext), toBase64(key), purpose, generation, binding)
}

export async function openAccountRecord(
  envelopeBase64: string,
  key: Uint8Array,
  purpose: AccountRecordPurpose,
  binding: string,
): Promise<Uint8Array> {
  const module = await getCryptoWasm()
  return fromBase64(module.openAccountRecord(envelopeBase64, toBase64(key), purpose, binding))
}

/**
 * Opens a record sealed under the account's master key, under the one of
 * the generation its header names (`masterKeys`: `session.masterKeys`).
 */
export async function openMasterKeyRecord(
  envelopeBase64: string,
  masterKeys: MasterKeys,
  purpose: AccountRecordPurpose,
  binding: string,
): Promise<Uint8Array> {
  const module = await getCryptoWasm()
  return fromBase64(module.openAccountRecordWithMasterKeys(envelopeBase64, masterKeys, purpose, binding))
}

/** What a record's header says, unopened: its purpose and the master key's generation it names. */
export async function inspectAccountRecord(envelopeBase64: string): Promise<{ purpose: number; generation: number }> {
  return (await getCryptoWasm()).inspectAccountRecord(envelopeBase64)
}
