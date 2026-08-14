// Thin browser adapter for the canonical Rust collaboration-frame suite.
// JavaScript holds the device signing key and performs the Ed25519 primitive;
// Rust owns the suite, header, parser, KDF, AAD, limits and signature slot.

import { fromBase64, toBase64 } from '@/crypto/base64'
import { getCryptoWasm } from '@/crypto/rustWasm'
import { ed25519Sign } from './sign'
import type { OpenedCollabFrameV1 } from './envelope'

export interface CollabFrameBindingV1 {
  fileId: string
  collectionId: string
  keyEpoch: number
}

export interface OutboundCollabFrameV1 extends CollabFrameBindingV1 {
  docKeyId: number
  deviceId: bigint
  sequence: bigint
}

export async function encryptCollabFrameV1(
  plaintext: Uint8Array,
  kind: number,
  context: OutboundCollabFrameV1,
  collectionKey: Uint8Array,
  signingPrivateKey: Uint8Array,
): Promise<Uint8Array> {
  const module = await getCryptoWasm()
  const unsigned = module.sealCollabFrame(
    toBase64(plaintext),
    toBase64(collectionKey),
    kind,
    context.keyEpoch,
    context.docKeyId,
    context.fileId,
    context.collectionId,
    context.deviceId.toString(),
    context.sequence.toString(),
  )
  const signature = await ed25519Sign(
    fromBase64(module.collabFrameSigningBytes(unsigned)),
    signingPrivateKey,
  )
  return fromBase64(module.attachCollabFrameSignature(unsigned, toBase64(signature)))
}

export async function openCollabFrameV1(
  packed: Uint8Array,
  collectionKey: Uint8Array,
  expected: CollabFrameBindingV1,
): Promise<OpenedCollabFrameV1> {
  const module = await getCryptoWasm()
  const opened = module.openCollabFrame(
    toBase64(packed),
    toBase64(collectionKey),
    expected.fileId,
    expected.collectionId,
    expected.keyEpoch,
  )
  return {
    kind: opened.kind,
    keyEpoch: opened.keyEpoch,
    docKeyId: opened.docKeyId,
    senderDeviceId: BigInt(opened.senderDeviceId),
    sequence: BigInt(opened.sequence),
    plaintext: fromBase64(opened.plaintext),
  }
}
