// Thin browser adapter for the canonical Rust collaboration-frame suite
// (V3, docs/plans/one-device-list.md §8). JavaScript holds the device signing
// key and performs the Ed25519 primitive; Rust owns the suite, header,
// parser, KDF, AAD, limits and signature slot.

import { fromBase64, toBase64 } from '@kutup/crypto/base64'
import { getCryptoWasm } from '@kutup/crypto/rustWasm'
import { ed25519Sign } from './sign'
import type { OpenedCollabFrame } from './envelope'

/**
 * What a frame is bound to: the file and the generation of the file key it
 * is sealed under — never the folder, so a document's log survives a move
 * (docs/plans/drive-move.md).
 */
export interface CollabFrameBinding {
  fileId: string
  keyGeneration: number
}

export interface OutboundCollabFrame extends CollabFrameBinding {
  docKeyId: number
  sequence: bigint
}

/**
 * Who seals a frame: a device of an account (`currentDevice()` is one). The
 * frame names its device id and the manifest it was listed under; the
 * signature covers the account as well.
 */
export interface FrameSender {
  deviceId: number
  /** `aci:<uuid>@<server>`. */
  account: string
  manifestSequence: bigint
  keypair: { privateKey: Uint8Array }
}

/**
 * Seal and sign a frame. The socket takes it as it is; the server delivers
 * it to the room with the sender's account in front.
 */
export async function encryptCollabFrame(
  plaintext: Uint8Array,
  kind: number,
  context: OutboundCollabFrame,
  fileKey: Uint8Array,
  sender: FrameSender,
): Promise<Uint8Array> {
  const module = await getCryptoWasm()
  const unsigned = module.sealCollabFrame(
    toBase64(plaintext),
    toBase64(fileKey),
    kind,
    context.keyGeneration,
    context.docKeyId,
    context.fileId,
    sender.deviceId,
    sender.manifestSequence.toString(),
    context.sequence.toString(),
  )
  const signature = await ed25519Sign(
    fromBase64(module.collabFrameSigningBytes(unsigned, sender.account)),
    sender.keypair.privateKey,
  )
  return fromBase64(module.attachCollabFrameSignature(unsigned, toBase64(signature)))
}

/**
 * Open a frame as a server delivers it (the sender's account, then the
 * packed frame: every binary message of a collab socket).
 */
export async function openCollabFrame(
  delivered: Uint8Array,
  fileKey: Uint8Array,
  expected: CollabFrameBinding,
): Promise<OpenedCollabFrame> {
  const module = await getCryptoWasm()
  const { sender, frame } = module.deliveredCollabFrame(toBase64(delivered))
  return openPacked(module, sender, frame, fileKey, expected)
}

function openPacked(
  module: Awaited<ReturnType<typeof getCryptoWasm>>,
  sender: string,
  frame: string,
  fileKey: Uint8Array,
  expected: CollabFrameBinding,
): OpenedCollabFrame {
  const opened = module.openCollabFrame(frame, toBase64(fileKey), expected.fileId, expected.keyGeneration)
  return {
    sender,
    kind: opened.kind,
    keyGeneration: opened.keyGeneration,
    docKeyId: opened.docKeyId,
    deviceId: opened.deviceId,
    manifestSequence: BigInt(opened.manifestSequence),
    sequence: BigInt(opened.sequence),
    plaintext: fromBase64(opened.plaintext),
  }
}

/**
 * Open a delivered frame sealed under any generation of the file key up to
 * the current one — a frame replayed from the log may predate a re-key. The
 * generation named in the frame's public header picks the key; opening still
 * checks the whole binding under it.
 */
export async function openCollabFrameAtGeneration(
  delivered: Uint8Array,
  keyAt: (generation: number) => Promise<Uint8Array>,
  expected: CollabFrameBinding,
): Promise<OpenedCollabFrame> {
  const module = await getCryptoWasm()
  const { sender, frame } = module.deliveredCollabFrame(toBase64(delivered))
  const generation = module.collabFrameKeyGeneration(frame)
  if (generation < 1 || generation > expected.keyGeneration) {
    throw new Error('collaboration frame from an unknown key generation')
  }
  return openPacked(module, sender, frame, await keyAt(generation), { ...expected, keyGeneration: generation })
}
