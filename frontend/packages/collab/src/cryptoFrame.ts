// Thin browser adapter for the canonical Rust collaboration-frame suite.
// JavaScript holds the device signing key and performs the Ed25519 primitive;
// Rust owns the suite, header, parser, KDF, AAD, limits and signature slot.

import { fromBase64, toBase64 } from '@kutup/crypto/base64'
import { getCryptoWasm } from '@kutup/crypto/rustWasm'
import { ed25519Sign } from './sign'
import type { OpenedCollabFrameV1 } from './envelope'

/**
 * What a frame is bound to: the file and the generation of the file key it
 * is sealed under — never the folder, so a document's log survives a move
 * (docs/plans/drive-move.md).
 */
export interface CollabFrameBindingV1 {
  fileId: string
  keyGeneration: number
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
  fileKey: Uint8Array,
  signingPrivateKey: Uint8Array,
): Promise<Uint8Array> {
  const module = await getCryptoWasm()
  const unsigned = module.sealCollabFrame(
    toBase64(plaintext),
    toBase64(fileKey),
    kind,
    context.keyGeneration,
    context.docKeyId,
    context.fileId,
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
  fileKey: Uint8Array,
  expected: CollabFrameBindingV1,
): Promise<OpenedCollabFrameV1> {
  const module = await getCryptoWasm()
  const opened = module.openCollabFrame(
    toBase64(packed),
    toBase64(fileKey),
    expected.fileId,
    expected.keyGeneration,
  )
  return {
    kind: opened.kind,
    keyGeneration: opened.keyGeneration,
    docKeyId: opened.docKeyId,
    senderDeviceId: BigInt(opened.senderDeviceId),
    sequence: BigInt(opened.sequence),
    plaintext: fromBase64(opened.plaintext),
  }
}

/**
 * Open a frame sealed under any generation of the file key up to the
 * current one — a frame replayed from the log may predate a re-key. The
 * generation named in the frame's public header picks the key; opening still
 * checks the whole binding under it.
 */
export async function openCollabFrameAtGenerationV1(
  packed: Uint8Array,
  keyAt: (generation: number) => Promise<Uint8Array>,
  expected: CollabFrameBindingV1,
): Promise<OpenedCollabFrameV1> {
  const module = await getCryptoWasm()
  const generation = module.collabFrameKeyGeneration(toBase64(packed))
  if (generation < 1 || generation > expected.keyGeneration) {
    throw new Error('collaboration frame from an unknown key generation')
  }
  return openCollabFrameV1(packed, await keyAt(generation), { ...expected, keyGeneration: generation })
}
