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
