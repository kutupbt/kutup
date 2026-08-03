import { createCollectionEpochStatement, verifyCollectionEpochStatement } from './collectionEpoch'
import { DRIVE_ENVELOPE_PURPOSE, openDriveEnvelope, sealDriveEnvelope } from './driveEnvelope'
import { deriveAccountIdentityKeys } from './identity'
import { openNamedShareEnvelope } from './namedShare'
import { fromBase64, toBase64 } from './base64'
import { generateKey } from './symmetric'

export interface OwnedCollectionWireV1 {
  id: string
  ownerUserId: string
  nameEnvelope: string
  ownerKeyEnvelope?: string
  keyEpoch: number
  nameRevision: number
  epochStatement: string
  epochStatementHash: string
}

export interface CreateOwnedCollectionV1 {
  payload: {
    id: string
    nameEnvelope: string
    ownerKeyEnvelope: string
    epochStatement: string
    parentCollectionId: string | null
  }
  collectionKey: Uint8Array
  epochStatementHash: string
}

/** Build the complete epoch-1 record before the server sees the collection. */
export async function createOwnedCollectionV1(
  masterKey: Uint8Array,
  ownerUserId: string,
  name: string,
  parentCollectionId: string | null,
): Promise<CreateOwnedCollectionV1> {
  const id = crypto.randomUUID().toLowerCase()
  const collectionKey = await generateKey()
  const ownerKeyEnvelope = await sealDriveEnvelope(collectionKey, masterKey, {
    purpose: DRIVE_ENVELOPE_PURPOSE.collectionKey,
    epoch: 1,
    revision: 1n,
    objectId: id,
    parentId: ownerUserId,
  })
  const nameEnvelope = await sealDriveEnvelope(new TextEncoder().encode(name), collectionKey, {
    purpose: DRIVE_ENVELOPE_PURPOSE.collectionName,
    epoch: 1,
    revision: 1n,
    objectId: id,
    parentId: ownerUserId,
  })
  const epochStatement = await createCollectionEpochStatement(
    masterKey,
    collectionKey,
    id,
    ownerUserId,
    1,
    undefined,
  )
  const identity = await deriveAccountIdentityKeys(toBase64(masterKey))
  const epochStatementHash = await verifyCollectionEpochStatement(
    epochStatement,
    identity.authorityPublicKey,
    collectionKey,
    id,
    ownerUserId,
    1,
    undefined,
  )
  return {
    payload: { id, nameEnvelope, ownerKeyEnvelope, epochStatement, parentCollectionId },
    collectionKey,
    epochStatementHash,
  }
}

/** Decrypt and independently verify a complete owner collection record. */
export async function openOwnedCollectionV1(
  row: OwnedCollectionWireV1,
  masterKey: Uint8Array,
): Promise<{ collectionKey: Uint8Array; name: string }> {
  if (!Number.isSafeInteger(row.nameRevision) || row.nameRevision < 1) {
    throw new Error('invalid collection name revision')
  }
  const collectionKey = await openOwnedCollectionKeyV1(row, masterKey)
  const name = await openDriveEnvelope(row.nameEnvelope, collectionKey, {
    purpose: DRIVE_ENVELOPE_PURPOSE.collectionName,
    epoch: row.keyEpoch,
    revision: BigInt(row.nameRevision),
    objectId: row.id,
    parentId: row.ownerUserId,
  })
  return { collectionKey, name: new TextDecoder().decode(name) }
}

export async function openOwnedCollectionKeyV1(
  row: Pick<OwnedCollectionWireV1,
    'id' | 'ownerUserId' | 'ownerKeyEnvelope' | 'keyEpoch' | 'epochStatement' | 'epochStatementHash'>,
  masterKey: Uint8Array,
): Promise<Uint8Array> {
  if (!row.ownerKeyEnvelope) throw new Error('owner key envelope missing')
  if (!Number.isSafeInteger(row.keyEpoch) || row.keyEpoch < 1) {
    throw new Error('invalid collection epoch')
  }
  const collectionKey = await openDriveEnvelope(row.ownerKeyEnvelope, masterKey, {
    purpose: DRIVE_ENVELOPE_PURPOSE.collectionKey,
    epoch: row.keyEpoch,
    revision: 1n,
    objectId: row.id,
    parentId: row.ownerUserId,
  })
  const identity = await deriveAccountIdentityKeys(toBase64(masterKey))
  const statementHash = await verifyCollectionEpochStatement(
    row.epochStatement,
    identity.authorityPublicKey,
    collectionKey,
    row.id,
    row.ownerUserId,
    row.keyEpoch,
    undefined,
  )
  if (statementHash !== row.epochStatementHash) {
    throw new Error('collection epoch statement hash mismatch')
  }
  return collectionKey
}

export async function renameOwnedCollectionV1(
  row: Pick<OwnedCollectionWireV1, 'id' | 'ownerUserId' | 'keyEpoch' | 'nameRevision'>,
  collectionKey: Uint8Array,
  name: string,
): Promise<{ nameEnvelope: string; nameRevision: number }> {
  const nameRevision = row.nameRevision + 1
  if (!Number.isSafeInteger(nameRevision)) throw new Error('collection name revision exhausted')
  const nameEnvelope = await sealDriveEnvelope(new TextEncoder().encode(name), collectionKey, {
    purpose: DRIVE_ENVELOPE_PURPOSE.collectionName,
    epoch: row.keyEpoch,
    revision: BigInt(nameRevision),
    objectId: row.id,
    parentId: row.ownerUserId,
  })
  return { nameEnvelope, nameRevision }
}

export async function openSharedCollectionV1(
  row: OwnedCollectionWireV1 & {
    namedShareEnvelope: string
    ownerAccount: string
    ownerIncarnationId: string
    ownerDriveSigningPublicKey: string
    ownerAuthorityPublicKey: string
  },
  recipientHpkePrivateKey: Uint8Array,
  recipientAccount: string,
  recipientIncarnationId: string,
): Promise<{ collectionKey: Uint8Array; name: string }> {
  const collectionKey = await openNamedShareEnvelope(
    row.namedShareEnvelope,
    row.ownerDriveSigningPublicKey,
    recipientHpkePrivateKey,
    {
      collectionId: row.id,
      epoch: row.keyEpoch,
      senderAccount: row.ownerAccount,
      senderIncarnationId: row.ownerIncarnationId,
      recipientAccount,
      recipientIncarnationId,
    },
  )
  const statementHash = await verifyCollectionEpochStatement(
    row.epochStatement,
    row.ownerAuthorityPublicKey,
    collectionKey,
    row.id,
    row.ownerUserId,
    row.keyEpoch,
  )
  if (statementHash !== row.epochStatementHash) {
    throw new Error('collection epoch statement hash mismatch')
  }
  const nameBytes = await openDriveEnvelope(row.nameEnvelope, collectionKey, {
    purpose: DRIVE_ENVELOPE_PURPOSE.collectionName,
    epoch: row.keyEpoch,
    revision: BigInt(row.nameRevision),
    objectId: row.id,
    parentId: row.ownerUserId,
  })
  return { collectionKey, name: new TextDecoder().decode(nameBytes) }
}

// Keep base64 conversion reachable from this canonical module for callers
// constructing named-share contexts without importing legacy crypto helpers.
export { fromBase64 }
