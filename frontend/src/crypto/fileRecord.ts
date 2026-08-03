import { DRIVE_ENVELOPE_PURPOSE, openDriveEnvelope, sealDriveEnvelope } from './driveEnvelope'
import { generateKey } from './symmetric'

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
  metadataRevision: number
}

export interface CreatedFileRecordV1 {
  fileId: string
  fileKey: Uint8Array
  metadataEnvelope: string
  fileKeyEnvelope: string
  keyEpoch: number
  metadataRevision: 1
}

function validateEpoch(value: number): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > 0xffff_ffff) {
    throw new Error('invalid file key epoch')
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

/** Construct both object-bound envelopes before any upload reaches the server. */
export async function createFileRecordV1(
  collectionId: string,
  keyEpoch: number,
  collectionKey: Uint8Array,
  metadata: FileMetadataV1,
): Promise<CreatedFileRecordV1> {
  validateEpoch(keyEpoch)
  const fileId = crypto.randomUUID().toLowerCase()
  const fileKey = await generateKey()
  const fileKeyEnvelope = await sealDriveEnvelope(fileKey, collectionKey, {
    purpose: DRIVE_ENVELOPE_PURPOSE.fileKey,
    epoch: keyEpoch,
    revision: 1n,
    objectId: fileId,
    parentId: collectionId,
  })
  const metadataEnvelope = await sealDriveEnvelope(encodeMetadata(metadata), fileKey, {
    purpose: DRIVE_ENVELOPE_PURPOSE.fileMetadata,
    epoch: keyEpoch,
    revision: 1n,
    objectId: fileId,
    parentId: collectionId,
  })
  return {
    fileId,
    fileKey,
    metadataEnvelope,
    fileKeyEnvelope,
    keyEpoch,
    metadataRevision: 1,
  }
}

/** Open a file only under its exact collection, epoch, id, and revision. */
export async function openFileRecordV1(
  row: FileWireV1,
  collectionKey: Uint8Array,
): Promise<{ fileKey: Uint8Array; metadata: FileMetadataV1 }> {
  validateEpoch(row.keyEpoch)
  validateRevision(row.metadataRevision)
  const fileKey = await openDriveEnvelope(row.fileKeyEnvelope, collectionKey, {
    purpose: DRIVE_ENVELOPE_PURPOSE.fileKey,
    epoch: row.keyEpoch,
    revision: 1n,
    objectId: row.id,
    parentId: row.collectionId,
  })
  const metadataBytes = await openDriveEnvelope(row.metadataEnvelope, fileKey, {
    purpose: DRIVE_ENVELOPE_PURPOSE.fileMetadata,
    epoch: row.keyEpoch,
    revision: BigInt(row.metadataRevision),
    objectId: row.id,
    parentId: row.collectionId,
  })
  return { fileKey, metadata: decodeMetadata(metadataBytes) }
}

export async function renameFileRecordV1(
  row: Pick<FileWireV1, 'id' | 'collectionId' | 'keyEpoch' | 'metadataRevision'>,
  fileKey: Uint8Array,
  metadata: FileMetadataV1,
): Promise<{ metadataEnvelope: string; metadataRevision: number }> {
  validateEpoch(row.keyEpoch)
  validateRevision(row.metadataRevision)
  const metadataRevision = row.metadataRevision + 1
  validateRevision(metadataRevision)
  const metadataEnvelope = await sealDriveEnvelope(encodeMetadata(metadata), fileKey, {
    purpose: DRIVE_ENVELOPE_PURPOSE.fileMetadata,
    epoch: row.keyEpoch,
    revision: BigInt(metadataRevision),
    objectId: row.id,
    parentId: row.collectionId,
  })
  return { metadataEnvelope, metadataRevision }
}
