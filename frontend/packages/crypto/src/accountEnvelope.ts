import { fromBase64, toBase64 } from './base64'
import { getCryptoWasm } from './rustWasm'
import { MASTER_KEY_GENERATION } from './masterKeyGeneration'

export const ACCOUNT_ENVELOPE_PURPOSE = {
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

export type AccountEnvelopePurpose =
  (typeof ACCOUNT_ENVELOPE_PURPOSE)[keyof typeof ACCOUNT_ENVELOPE_PURPOSE]

export async function sealAccountEnvelope(
  plaintext: Uint8Array,
  key: Uint8Array,
  purpose: AccountEnvelopePurpose,
  /** What the account's keys are bound to (`session.envelopeBinding`), never a name. */
  binding: string,
): Promise<string> {
  const module = await getCryptoWasm()
  return module.sealAccountEnvelope(toBase64(plaintext), toBase64(key), purpose, MASTER_KEY_GENERATION, binding)
}

export async function openAccountEnvelope(
  envelopeBase64: string,
  key: Uint8Array,
  purpose: AccountEnvelopePurpose,
  binding: string,
): Promise<Uint8Array> {
  const module = await getCryptoWasm()
  return fromBase64(module.openAccountEnvelope(envelopeBase64, toBase64(key), purpose, binding))
}
