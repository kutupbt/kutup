import {
  DRIVE_ENVELOPE_PURPOSE,
  openDriveEnvelope,
  sealDriveEnvelope,
  type DriveEnvelopeContextV1,
} from './driveEnvelope'
import { sealPreviousFileKeyV1 } from './fileKeyring'
import { generateKey } from './symmetric'

/**
 * A file record (docs/plans/drive-move.md): a random file key, wrapped under
 * its folder's key — the one envelope that names the folder — and the
 * metadata sealed under the file key, bound to the file alone. `keyEpoch` is
 * the folder epoch the wrap is sealed at; `keyGeneration` counts the file's
 * own keys (a re-key adds one).
 */

export interface FileMetadataV1 {
  name: string
  mimeType: string
  size: number
}

export interface FileWireV1 {
  id: string
  collectionId: string
  metadataEnvelope: string
  fileKeyEnvelope: string
  keyEpoch: number
  keyGeneration: number
  metadataRevision: number
}

export interface CreatedFileRecordV1 {
  fileId: string
  fileKey: Uint8Array
  metadataEnvelope: string
  fileKeyEnvelope: string
  keyEpoch: number
  keyGeneration: 1
  metadataRevision: 1
}

function validateCounter(value: number, what: string): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > 0xffff_ffff) {
    throw new Error(`invalid ${what}`)
  }
}

function validateRevision(value: number): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error('invalid file metadata revision')
  }
}

function encodeMetadata(metadata: FileMetadataV1): Uint8Array {
  if (typeof metadata.name !== 'string' || metadata.name.length === 0
    || typeof metadata.mimeType !== 'string'
    || !Number.isSafeInteger(metadata.size) || metadata.size < 0) {
    throw new Error('invalid file metadata')
  }
  return new TextEncoder().encode(JSON.stringify({
    name: metadata.name,
    mimeType: metadata.mimeType,
    size: metadata.size,
  }))
}

function decodeMetadata(bytes: Uint8Array): FileMetadataV1 {
  const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('invalid file metadata')
  }
  const record = value as Record<string, unknown>
  if (Object.keys(record).sort().join(',') !== 'mimeType,name,size'
    || typeof record.name !== 'string' || record.name.length === 0
    || typeof record.mimeType !== 'string'
    || !Number.isSafeInteger(record.size) || (record.size as number) < 0) {
    throw new Error('invalid file metadata')
  }
  return {
    name: record.name,
    mimeType: record.mimeType,
    size: record.size as number,
  }
}

/** The file key's wrap under its folder's key at `keyEpoch`. */
function fileKeyContext(
  fileId: string,
  collectionId: string,
  keyEpoch: number,
  keyGeneration: number,
): DriveEnvelopeContextV1 {
  validateCounter(keyEpoch, 'folder key epoch')
  validateCounter(keyGeneration, 'file key generation')
  return {
    purpose: DRIVE_ENVELOPE_PURPOSE.fileKey,
    epoch: keyEpoch,
    revision: BigInt(keyGeneration),
    objectId: fileId,
    parentId: collectionId,
  }
}

/** The metadata under the file key of `keyGeneration`: the file's alone. */
function metadataContext(
  fileId: string,
  keyGeneration: number,
  revision: number,
): DriveEnvelopeContextV1 {
  validateCounter(keyGeneration, 'file key generation')
  validateRevision(revision)
  return {
    purpose: DRIVE_ENVELOPE_PURPOSE.fileMetadata,
    epoch: keyGeneration,
    revision: BigInt(revision),
    objectId: fileId,
    parentId: fileId,
  }
}

/** Construct both envelopes before any upload reaches the server. */
export async function createFileRecordV1(
  collectionId: string,
  keyEpoch: number,
  collectionKey: Uint8Array,
  metadata: FileMetadataV1,
): Promise<CreatedFileRecordV1> {
  const fileId = crypto.randomUUID().toLowerCase()
  const fileKey = await generateKey()
  const fileKeyEnvelope = await sealDriveEnvelope(
    fileKey,
    collectionKey,
    fileKeyContext(fileId, collectionId, keyEpoch, 1),
  )
  const metadataEnvelope = await sealDriveEnvelope(
    encodeMetadata(metadata),
    fileKey,
    metadataContext(fileId, 1, 1),
  )
  return {
    fileId,
    fileKey,
    metadataEnvelope,
    fileKeyEnvelope,
    keyEpoch,
    keyGeneration: 1,
    metadataRevision: 1,
  }
}

/** Open a file's key (under `collectionKey`, the folder key at the row's
 * `keyEpoch`) and its metadata, each only in its exact context. */
export async function openFileRecordV1(
  row: FileWireV1,
  collectionKey: Uint8Array,
): Promise<{ fileKey: Uint8Array; metadata: FileMetadataV1 }> {
  const fileKey = await openDriveEnvelope(
    row.fileKeyEnvelope,
    collectionKey,
    fileKeyContext(row.id, row.collectionId, row.keyEpoch, row.keyGeneration),
  )
  const metadataBytes = await openDriveEnvelope(
    row.metadataEnvelope,
    fileKey,
    metadataContext(row.id, row.keyGeneration, row.metadataRevision),
  )
  return { fileKey, metadata: decodeMetadata(metadataBytes) }
}

export async function renameFileRecordV1(
  row: Pick<FileWireV1, 'id' | 'keyGeneration' | 'metadataRevision'>,
  fileKey: Uint8Array,
  metadata: FileMetadataV1,
): Promise<{ metadataEnvelope: string; metadataRevision: number }> {
  validateRevision(row.metadataRevision)
  const metadataRevision = row.metadataRevision + 1
  const metadataEnvelope = await sealDriveEnvelope(
    encodeMetadata(metadata),
    fileKey,
    metadataContext(row.id, row.keyGeneration, metadataRevision),
  )
  return { metadataEnvelope, metadataRevision }
}

/**
 * A new file key for a file its folder has rotated past
 * (docs/plans/drive-share-revocation.md): the next generation, wrapped at the
 * folder's current `keyEpoch`, the same metadata (same revision) sealed under
 * it, and the key it leaves sealed under it too, so everything stored before
 * stays readable wherever the file goes (docs/plans/drive-move.md).
 */
export async function rekeyFileRecordV1(
  row: Pick<FileWireV1, 'id' | 'collectionId' | 'keyGeneration' | 'metadataRevision'>,
  currentFileKey: Uint8Array,
  keyEpoch: number,
  collectionKey: Uint8Array,
  metadata: FileMetadataV1,
): Promise<{
  fileKey: Uint8Array
  keyGeneration: number
  fileKeyEnvelope: string
  metadataEnvelope: string
  previousKeyEnvelope: string
}> {
  const keyGeneration = row.keyGeneration + 1
  const fileKey = await generateKey()
  const fileKeyEnvelope = await sealDriveEnvelope(
    fileKey,
    collectionKey,
    fileKeyContext(row.id, row.collectionId, keyEpoch, keyGeneration),
  )
  const metadataEnvelope = await sealDriveEnvelope(
    encodeMetadata(metadata),
    fileKey,
    metadataContext(row.id, keyGeneration, row.metadataRevision),
  )
  const previousKeyEnvelope = await sealPreviousFileKeyV1(
    currentFileKey,
    fileKey,
    row.id,
    keyGeneration,
  )
  return { fileKey, keyGeneration, fileKeyEnvelope, metadataEnvelope, previousKeyEnvelope }
}

/**
 * The file's current key wrapped for another folder, at that folder's
 * current epoch: everything a move sends (docs/plans/drive-move.md).
 */
export async function wrapFileKeyForV1(
  file: Pick<FileWireV1, 'id' | 'keyGeneration'>,
  fileKey: Uint8Array,
  collectionId: string,
  keyEpoch: number,
  collectionKey: Uint8Array,
): Promise<string> {
  return sealDriveEnvelope(
    fileKey,
    collectionKey,
    fileKeyContext(file.id, collectionId, keyEpoch, file.keyGeneration),
  )
}
