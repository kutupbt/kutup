import { fromBase64, toBase64 } from './base64'
import { getCryptoWasm } from './rustWasm'

/**
 * The purposes whose context is two plain UUIDs. Whiteboard assets (6),
 * thumbnails (7) and previous folder keys (8) have their own typed wrappers
 * (whiteboardAsset.ts, thumbnail.ts, collectionKeyring.ts); the generic WASM
 * export refuses them.
 */
export const DRIVE_ENVELOPE_PURPOSE = {
  collectionKey: 1,
  collectionName: 2,
  fileKey: 3,
  fileMetadata: 4,
  publicLinkCollectionKey: 5,
  /** A public link's key, sealed for the folder owner (object = link id). */
  publicLinkKey: 9,
} as const

export type DriveEnvelopePurpose =
  (typeof DRIVE_ENVELOPE_PURPOSE)[keyof typeof DRIVE_ENVELOPE_PURPOSE]

export interface DriveEnvelopeContextV1 {
  purpose: DriveEnvelopePurpose
  epoch: number
  revision: bigint
  objectId: string
  parentId: string
}

export async function sealDriveEnvelope(
  plaintext: Uint8Array,
  rootKey: Uint8Array,
  context: DriveEnvelopeContextV1,
): Promise<string> {
  const module = await getCryptoWasm()
  return module.sealDriveEnvelope(
    toBase64(plaintext),
    toBase64(rootKey),
    context.purpose,
    context.epoch,
    context.revision,
    context.objectId,
    context.parentId,
  )
}

export async function openDriveEnvelope(
  envelopeBase64: string,
  rootKey: Uint8Array,
  expected: DriveEnvelopeContextV1,
): Promise<Uint8Array> {
  const module = await getCryptoWasm()
  return fromBase64(module.openDriveEnvelope(
    envelopeBase64,
    toBase64(rootKey),
    expected.purpose,
    expected.epoch,
    expected.revision,
    expected.objectId,
    expected.parentId,
  ))
}
