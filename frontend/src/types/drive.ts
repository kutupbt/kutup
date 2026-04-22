// Drive-specific enriched types (CollectionRow + decrypted fields)

export interface Collection {
  id: string
  ownerUserId: string
  encryptedName: string
  nameNonce: string
  encryptedKey: string
  encryptedKeyNonce: string
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
  encryptedMetadata: string
  metadataNonce: string
  encryptedFileKey: string
  fileKeyNonce: string
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
