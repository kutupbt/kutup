// TypeScript interfaces matching backend handlers/models.go

export interface CollectionRow {
  id: string
  ownerUserId: string
  encryptedName: string
  nameNonce: string
  encryptedKey: string
  encryptedKeyNonce: string
  parentCollectionId: string | null
  color: string | null
  canUpload: boolean
  canDelete: boolean
  uploadQuotaBytes: number | null
  uploadUsedBytes: number
  isShared: boolean
}

export interface FileRow {
  id: string
  collectionId: string
  uploaderUserId: string
  encryptedMetadata: string
  metadataNonce: string
  encryptedFileKey: string
  fileKeyNonce: string
  encryptedSizeBytes: number
  createdAt: string
  updatedAt: string
}

export interface UserRow {
  id: string
  email: string
  username: string
  storageQuotaBytes: number
  storageUsedBytes: number
  isAdmin: boolean
  isActive: boolean
  totpEnabled: boolean
  createdAt: string
}

export interface LoginResponse {
  accessToken: string
  userId: string
  username: string
  encryptedMasterKey: string
  masterKeyNonce: string
  encryptedPrivateKey: string
  privateKeyNonce: string
  publicKey: string
  isAdmin: boolean
  storageQuotaBytes: number
  storageUsedBytes: number
  totpEnabled?: boolean
}

export interface IncomingShare {
  id: string
  remoteServer: string
  encryptedCollectionKey: string
  encryptedName: string
  nameNonce: string
  canUpload: boolean
  canDelete: boolean
  uploadQuotaBytes: number | null
  createdAt: string
}

export interface AdminStats {
  totalUsers: number
  activeUsers: number
  totalFiles: number
  totalStorageUsedBytes: number
  totalCollections: number
  /**
   * Total storage capacity advertised by the server (S3 bucket / volume size).
   * `0` means "unknown" — the admin UI hides the capacity readout in that case.
   * Sourced from the `STORAGE_TOTAL_BYTES` env var on the backend; future PR
   * may auto-detect this from the SeaweedFS master.
   */
  storageTotalBytes: number
}

export interface AdminSettings {
  registrationEnabled: boolean
}

export interface MeResponse {
  userId: string
  email: string
  username: string
  storageQuotaBytes: number
  storageUsedBytes: number
  isAdmin: boolean
  totpEnabled: boolean
  publicKey: string
}

export interface UserByEmailResponse {
  userId: string
  username: string
  publicKey: string
}

export interface PublicShareData {
  id: string
  shareType: string
  targetId: string
  encryptedCollectionKey: string
  encryptedCollectionKeyNonce: string
  expiresAt?: string
}

export interface ErrorResponse {
  error: string
}
