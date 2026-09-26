import { fromBase64, toBase64 } from './base64'
import { getCryptoWasm } from './rustWasm'

export interface NamedShareContextV1 {
  collectionId: string
  epoch: number
  senderAccount: string
  senderIncarnationId: string
  recipientAccount: string
  recipientIncarnationId: string
}

export async function sealNamedShareEnvelope(
  collectionKey: Uint8Array,
  senderMasterKey: Uint8Array,
  recipientHpkePublicKeyBase64: string,
  context: NamedShareContextV1,
): Promise<string> {
  const module = await getCryptoWasm()
  return module.sealNamedShareEnvelope(
    toBase64(collectionKey),
    toBase64(senderMasterKey),
    recipientHpkePublicKeyBase64,
    context.collectionId,
    context.epoch,
    context.senderAccount,
    context.senderIncarnationId,
    context.recipientAccount,
    context.recipientIncarnationId,
  )
}

export async function openNamedShareEnvelope(
  envelopeBase64: string,
  senderSigningPublicKeyBase64: string,
  recipientHpkePrivateKey: Uint8Array,
  expected: NamedShareContextV1,
): Promise<Uint8Array> {
  const module = await getCryptoWasm()
  return fromBase64(module.openNamedShareEnvelope(
    envelopeBase64,
    senderSigningPublicKeyBase64,
    toBase64(recipientHpkePrivateKey),
    expected.collectionId,
    expected.epoch,
    expected.senderAccount,
    expected.senderIncarnationId,
    expected.recipientAccount,
    expected.recipientIncarnationId,
  ))
}

/** Who a profile key goes from and to (docs/plans/unified-profile.md). */
export interface ProfileKeyPartiesV1 {
  senderAccount: string
  senderIncarnationId: string
  recipientAccount: string
  recipientIncarnationId: string
}

/** Your profile key, sealed to someone you share folders with and signed by you. */
export async function sealProfileKeyEnvelope(
  profileKey: Uint8Array,
  senderMasterKey: Uint8Array,
  recipientHpkePublicKeyBase64: string,
  parties: ProfileKeyPartiesV1,
): Promise<string> {
  const module = await getCryptoWasm()
  return module.sealProfileKeyEnvelope(
    toBase64(profileKey),
    toBase64(senderMasterKey),
    recipientHpkePublicKeyBase64,
    parties.senderAccount,
    parties.senderIncarnationId,
    parties.recipientAccount,
    parties.recipientIncarnationId,
  )
}

/** Someone's profile key, once it checks out as from them and to you. */
export async function openProfileKeyEnvelope(
  envelopeBase64: string,
  senderSigningPublicKeyBase64: string,
  recipientHpkePrivateKey: Uint8Array,
  expected: ProfileKeyPartiesV1,
): Promise<Uint8Array> {
  const module = await getCryptoWasm()
  return fromBase64(module.openProfileKeyEnvelope(
    envelopeBase64,
    senderSigningPublicKeyBase64,
    toBase64(recipientHpkePrivateKey),
    expected.senderAccount,
    expected.senderIncarnationId,
    expected.recipientAccount,
    expected.recipientIncarnationId,
  ))
}
