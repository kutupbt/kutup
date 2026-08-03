// Drive-specific enriched types (CollectionRow + decrypted fields)

export interface Collection {
  id: string
  ownerUserId: string
  nameEnvelope: string
  ownerKeyEnvelope?: string
  namedShareEnvelope?: string
  keyEpoch: number
  nameRevision: number
  epochStatement: string
  epochStatementHash: string
  ownerAccount?: string
  ownerIncarnationId?: string
  ownerDriveSigningPublicKey?: string
  ownerAuthorityPublicKey?: string
  parentCollectionId: string | null
  color: string | null
  // Server privilege fields
  isShared?: boolean
  canUpload?: boolean
  canDelete?: boolean
  uploadQuotaBytes?: number | null
  uploadUsedBytes?: number
  // Decrypted client-side
  decryptedName?: string
  collectionKey?: Uint8Array
  // Remote (federated) share
  isRemote?: boolean
  remoteShareId?: string
}

export interface DecryptedFile {
  id: string
  collectionId: string
  metadataEnvelope: string
  fileKeyEnvelope: string
  keyEpoch: number
  metadataRevision: number
  encryptedSizeBytes: number
  createdAt: string
  // Decrypted client-side
  decryptedName?: string
  decryptedMimeType?: string
  decryptedSize?: number
  _fileKey?: Uint8Array
}

export interface UploadState {
  active: boolean
  currentFile: number
  totalFiles: number
  filePercent: number
  overallPercent: number
  speedBps: number
}
