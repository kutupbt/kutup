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
  /**
   * True for the break-glass admin (the account from the `ADMIN_ACCOUNT`
   * env var). The UI disables demote / disable / delete for this user —
   * the backend rejects those mutations with 403.
   */
  isProtected: boolean
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
   * Total storage capacity of the storage backend (S3 bucket / volume size).
   * `0` means "unknown" — the admin UI hides the capacity readout in that case.
   * Resolved from the live SeaweedFS probe (`SEAWEEDFS_MASTER_URL`); falls
   * back to the `STORAGE_TOTAL_BYTES` env var.
   */
  storageTotalBytes: number
  /**
   * Real on-disk bytes used by the storage backend, from the SeaweedFS
   * probe. `0` when no probe is available. Distinct from
   * `totalStorageUsedBytes`, which is the DB sum of per-account usage.
   */
  storageBackendUsedBytes: number
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
