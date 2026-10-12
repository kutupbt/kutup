import { fromBase64, toBase64 } from './base64'
import { getCryptoWasm } from './rustWasm'

export const ACCOUNT_ENVELOPE_PURPOSE = {
  passwordMasterKey: 1,
  recoveryMasterKey: 2,
  driveHpkePrivateKey: 3,
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
  return module.sealAccountEnvelope(toBase64(plaintext), toBase64(key), purpose, binding)
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

/** An envelope sealed again under the same key for another binding (a re-seal). */
export async function resealAccountEnvelope(
  envelopeBase64: string,
  key: Uint8Array,
  purpose: AccountEnvelopePurpose,
  from: string,
  to: string,
): Promise<string> {
  const plain = await openAccountEnvelope(envelopeBase64, key, purpose, from)
  try {
    return await sealAccountEnvelope(plain, key, purpose, to)
  } finally {
    plain.fill(0)
  }
}
