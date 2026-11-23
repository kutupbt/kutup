import type { AccountRoots } from './accountRoots'
import { fromBase64, toBase64 } from './base64'
import {
  DRIVE_ENVELOPE_PURPOSE,
  openDriveEnvelope,
  sealDriveEnvelope,
} from './driveEnvelope'
import { getCryptoWasm } from './rustWasm'

export interface PublicLinkCollectionContextV1 {
  collectionId: string
  ownerAccountId: string
  epoch: number
}

function envelopeContext(context: PublicLinkCollectionContextV1) {
  return {
    purpose: DRIVE_ENVELOPE_PURPOSE.publicLinkCollectionKey,
    epoch: context.epoch,
    revision: 1n,
    objectId: context.collectionId,
    parentId: context.ownerAccountId,
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
  ownerAccountId: string
}

/**
 * The link key sealed for the folder owner under their Drive root, at the
 * root's generation, so the owner can list and copy the link later and keep
 * it working when the folder key rotates (docs/plans/drive-share-revocation.md,
 * docs/plans/identity-rotation.md §3).
 */
export async function sealOwnerLinkKeyV1(
  linkKey: Uint8Array,
  roots: Pick<AccountRoots, 'driveRoot' | 'driveGeneration'>,
  context: OwnerLinkKeyContextV1,
): Promise<string> {
  return (await getCryptoWasm()).sealOwnerLinkKey(toBase64(linkKey), roots.driveRoot, roots.driveGeneration, context.linkId, context.ownerAccountId)
}

export async function openOwnerLinkKeyV1(
  envelope: string,
  roots: Pick<AccountRoots, 'driveRoot' | 'driveGeneration'>,
  context: OwnerLinkKeyContextV1,
): Promise<Uint8Array> {
  return fromBase64((await getCryptoWasm()).openOwnerLinkKey(envelope, roots.driveRoot, roots.driveGeneration, context.linkId, context.ownerAccountId))
}

export interface PublicLinkFileContextV1 {
  fileId: string
  ownerAccountId: string
  /** The file key's generation. */
  generation: number
}

function fileContext(context: PublicLinkFileContextV1) {
  return {
    purpose: DRIVE_ENVELOPE_PURPOSE.publicLinkFileKey,
    epoch: context.generation,
    revision: 1n,
    objectId: context.fileId,
    parentId: context.ownerAccountId,
  } as const
}

/** Wrap one file's key for a link to that file (docs/plans/drive-file-sharing.md, slice 3). */
export function sealPublicLinkFileKeyV1(
  fileKey: Uint8Array,
  linkKey: Uint8Array,
  context: PublicLinkFileContextV1,
): Promise<string> {
  return sealDriveEnvelope(fileKey, linkKey, fileContext(context))
}

/** Open only the exact file/owner/generation the link's record names. */
export function openPublicLinkFileKeyV1(
  envelope: string,
  linkKey: Uint8Array,
  expected: PublicLinkFileContextV1,
): Promise<Uint8Array> {
  return openDriveEnvelope(envelope, linkKey, fileContext(expected))
}

// A link's password (docs/plans/drive-link-password.md): the URL fragment
// holds the link's secret; with a password the target is sealed under a
// separate link key, itself sealed under a key the secret and the password
// derive (Argon2id, then HKDF). All of it is kutup-crypto's, through WASM.

/** A password's salt and cost, as `GET /drive/public-links/{token}/password` returns them. */
export interface LinkPasswordParams {
  linkId: string
  salt: string
  operations: number
  memory: number
}

/** What a link's secret and password derive: the proof the server checks, and the key that opens the link key. */
export interface LinkPasswordKeys {
  /** Base64; sent as `X-Kutup-Link-Proof`. */
  proof: string
  wrapKey: Uint8Array
}

export async function deriveLinkPasswordV1(secret: Uint8Array, password: string, params: LinkPasswordParams): Promise<LinkPasswordKeys> {
  const keys = (await getCryptoWasm()).deriveLinkPassword(toBase64(secret), password, params.salt, params.operations, params.memory, params.linkId)
  return { proof: keys.proof, wrapKey: fromBase64(keys.wrapKey) }
}

export interface LinkPasswordContextV1 {
  linkId: string
  ownerAccountId: string
  /** The link's key revision the envelope is bound to. */
  keyRevision: number
}

/** Opens a protected link's key (purpose 14) with the wrap key `deriveLinkPasswordV1` gave. */
export async function openLinkPasswordKeyV1(envelope: string, wrapKey: Uint8Array, context: LinkPasswordContextV1): Promise<Uint8Array> {
  return fromBase64((await getCryptoWasm()).openLinkPasswordKey(envelope, toBase64(wrapKey), context.linkId, context.ownerAccountId, context.keyRevision))
}

/** A password set on a link, as `PUT /drive/public-links/{token}/password` takes it (less the owner's copy). */
export interface LinkPasswordProtection {
  salt: string
  operations: number
  memory: number
  verifier: string
  linkKeyEnvelope: string
}

/** Protects `linkKey` with the link's URL `secret` and `password`, a fresh salt at the current cost. */
export async function protectLinkPasswordV1(
  secret: Uint8Array,
  password: string,
  linkKey: Uint8Array,
  context: LinkPasswordContextV1,
): Promise<LinkPasswordProtection> {
  return (await getCryptoWasm()).protectLinkPassword(
    toBase64(secret),
    password,
    toBase64(linkKey),
    context.linkId,
    context.ownerAccountId,
    context.keyRevision,
  )
}

/** A protected link's URL secret and password, sealed for its owner under their Drive root (purpose 15). */
export async function sealOwnerLinkSecretV1(
  secret: Uint8Array,
  password: string,
  roots: Pick<AccountRoots, 'driveRoot' | 'driveGeneration'>,
  context: OwnerLinkKeyContextV1,
): Promise<string> {
  return (await getCryptoWasm()).sealOwnerLinkSecret(toBase64(secret), password, roots.driveRoot, roots.driveGeneration, context.linkId, context.ownerAccountId)
}

export async function openOwnerLinkSecretV1(
  envelope: string,
  roots: Pick<AccountRoots, 'driveRoot' | 'driveGeneration'>,
  context: OwnerLinkKeyContextV1,
): Promise<{ secret: Uint8Array; password: string }> {
  const opened = (await getCryptoWasm()).openOwnerLinkSecret(envelope, roots.driveRoot, roots.driveGeneration, context.linkId, context.ownerAccountId)
  return { secret: fromBase64(opened.secret), password: opened.password }
}
