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

export interface OwnerLinkKeyContextV1 {
  /** The link's id (client-chosen, the server's `public_shares.id`). */
  linkId: string
  ownerUserId: string
}

function ownerContext(context: OwnerLinkKeyContextV1) {
  return {
    purpose: DRIVE_ENVELOPE_PURPOSE.publicLinkKey,
    epoch: 1,
    revision: 1n,
    objectId: context.linkId,
    parentId: context.ownerUserId,
  } as const
}

/**
 * The link key sealed for the folder owner under their master key, so the
 * owner can list and copy the link later and keep it working when the
 * folder key rotates (docs/plans/drive-share-revocation.md).
 */
export function sealOwnerLinkKeyV1(
  linkKey: Uint8Array,
  masterKey: Uint8Array,
  context: OwnerLinkKeyContextV1,
): Promise<string> {
  return sealDriveEnvelope(linkKey, masterKey, ownerContext(context))
}

export function openOwnerLinkKeyV1(
  envelope: string,
  masterKey: Uint8Array,
  context: OwnerLinkKeyContextV1,
): Promise<Uint8Array> {
  return openDriveEnvelope(envelope, masterKey, ownerContext(context))
}
