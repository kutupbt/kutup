import { fromBase64, toBase64 } from './base64'
import { getCryptoWasm } from './rustWasm'

export const ACCOUNT_ENVELOPE_PURPOSE = {
  passwordMasterKey: 1,
  recoveryMasterKey: 2,
  driveHpkePrivateKey: 3,
} as const

export type AccountEnvelopePurpose =
  (typeof ACCOUNT_ENVELOPE_PURPOSE)[keyof typeof ACCOUNT_ENVELOPE_PURPOSE]

export async function sealAccountEnvelope(
  plaintext: Uint8Array,
  key: Uint8Array,
  purpose: AccountEnvelopePurpose,
  loginEmail: string,
): Promise<string> {
  const module = await getCryptoWasm()
  return module.sealAccountEnvelope(toBase64(plaintext), toBase64(key), purpose, loginEmail)
}

export async function openAccountEnvelope(
  envelopeBase64: string,
  key: Uint8Array,
  purpose: AccountEnvelopePurpose,
  loginEmail: string,
): Promise<Uint8Array> {
  const module = await getCryptoWasm()
  return fromBase64(module.openAccountEnvelope(envelopeBase64, toBase64(key), purpose, loginEmail))
}
