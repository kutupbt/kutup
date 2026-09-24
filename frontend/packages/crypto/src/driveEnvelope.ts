import { fromBase64, toBase64 } from './base64'
import { getCryptoWasm } from './rustWasm'

/**
 * The purposes whose context is two plain UUIDs. Whiteboard assets (6) and
 * thumbnails (7) bind a derived id and have their own typed wrappers
 * (whiteboardAsset.ts, thumbnail.ts); the generic WASM export refuses them.
 */
export const DRIVE_ENVELOPE_PURPOSE = {
  collectionKey: 1,
  collectionName: 2,
  fileKey: 3,
  fileMetadata: 4,
  publicLinkCollectionKey: 5,
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
