import {
  DRIVE_ENVELOPE_PURPOSE,
  openDriveEnvelope,
  sealDriveEnvelope,
} from './driveEnvelope'

export interface PublicLinkCollectionContextV1 {
  collectionId: string
  ownerUserId: string
  epoch: number
}

function envelopeContext(context: PublicLinkCollectionContextV1) {
  return {
    purpose: DRIVE_ENVELOPE_PURPOSE.publicLinkCollectionKey,
    epoch: context.epoch,
    revision: 1n,
    objectId: context.collectionId,
    parentId: context.ownerUserId,
  } as const
}

/** Wrap a collection key for a capability URL whose fragment holds linkKey. */
export function sealPublicLinkCollectionKeyV1(
  collectionKey: Uint8Array,
  linkKey: Uint8Array,
  context: PublicLinkCollectionContextV1,
): Promise<string> {
  return sealDriveEnvelope(collectionKey, linkKey, envelopeContext(context))
}

/** Open only the exact target/owner/epoch context returned by the share API. */
export function openPublicLinkCollectionKeyV1(
  envelope: string,
  linkKey: Uint8Array,
  expected: PublicLinkCollectionContextV1,
): Promise<Uint8Array> {
  return openDriveEnvelope(envelope, linkKey, envelopeContext(expected))
}
