// TypeScript interfaces matching backend handlers/models.go

export interface CollectionRow {
  id: string
  ownerUserId: string
  nameEnvelope: string
  ownerKeyEnvelope?: string
  namedShareEnvelope?: string
  keyEpoch: number
  nameRevision: number
  epochStatement: string
  epochStatementHash: string
  /** A shared folder's owner's server; with `ownerUserId`, the owner. */
  ownerServer?: string
  /** Shown only: the owner's address now. */
  ownerAccount?: string
  ownerIncarnationId?: string
  ownerDriveSigningPublicKey?: string
  ownerAuthorityPublicKey?: string
  parentCollectionId: string | null
  color: string | null
  canUpload: boolean
  canDelete: boolean
  uploadQuotaBytes: number | null
  uploadUsedBytes: number
  isShared: boolean
  /** Its name's hash in its place (docs/plans/drive-unique-names.md); absent until filled in. */
  nameHash?: string
}

/**
 * One generation of a file's key history (docs/plans/drive-move.md): the key
 * of `generation − 1`, sealed under the key of `generation`.
 */
export interface FileKeyHistoryEntry {
  generation: number
  previousKeyEnvelope: string
}

export interface FileRow {
  id: string
  collectionId: string
  uploaderUserId: string
  metadataEnvelope: string
  fileKeyEnvelope: string
  /** The folder epoch the file key is wrapped at. */
  keyEpoch: number
  /** The generation of the file's current key. */
  keyGeneration: number
  metadataRevision: number
  encryptedSizeBytes: number
  createdAt: string
  updatedAt: string
  /** When each thumbnail variant was stored (docs/plans/drive-thumbnails.md), and the key generation it was sealed under. */
  thumbnails?: { sm?: string; lg?: string; smKeyGeneration?: number; lgKeyGeneration?: number }
  /** A thumbnail exists but was drawn from other than the latest version. */
  thumbnailStale?: boolean
  /** The key generation the upload was sealed under. */
  originalKeyGeneration: number
  /** The key generation of what a download serves (latest whole-file version, else the upload). */
  contentKeyGeneration: number
  /** The file's older keys, generations 2 to `keyGeneration` in order. */
  keyHistory?: FileKeyHistoryEntry[]
  /** Shared with someone by itself; only its owner is told. */
  shared?: boolean
  /** Its name's and content's hashes in its folder (docs/plans/drive-unique-names.md); absent until known. */
  nameHash?: string
  contentHash?: string
}

export interface UserRow {
  id: string
  username: string
  storageQuotaBytes: number
  storageUsedBytes: number
  isAdmin: boolean
  isActive: boolean
  totpEnabled: boolean
  /**
   * Still on the admin-issued temp password — no key material yet. Gates the
   * admin "Rotate temp password" action (safe only in this state).
   */
  isFirstLogin: boolean
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
  masterKeyEnvelope: string
  drivePrivateKeyEnvelope: string
  publicKey: string
  isAdmin: boolean
  storageQuotaBytes: number
  storageUsedBytes: number
  totpEnabled?: boolean
}

export interface IncomingShare {
  id: string
  remoteDomain: string
  remoteCollectionId: string
  namedShareEnvelope: string
  nameEnvelope: string
  keyEpoch: number
  nameRevision: number
  epochStatement: string
  epochStatementHash: string
  ownerUserId: string
  ownerAccount: string
  ownerIncarnationId: string
  ownerSigningPublicKey: string
  ownerAuthorityPublicKey: string
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

/** Who may register (docs/plans/registration-codes.md). */
export type RegistrationMode = 'on' | 'code' | 'off'

/** A referral code as an administrator sees it: its hint, never the code. */
export interface RegistrationCode {
  id: string
  /** The code's last four characters. */
  hint: string
  note: string
  createdBy: string | null
  createdAt: string
  expiresAt: string | null
  /** `null`: unlimited. */
  maxUses: number | null
  uses: number
  revokedAt: string | null
  state: 'active' | 'expired' | 'usedUp' | 'revoked'
}

/** A code just made: the only time its text comes back. */
export interface CreatedRegistrationCode extends RegistrationCode {
  code: string
}

export interface RegistrationCodeUse {
  userId: string
  username: string
  usedAt: string
}

/** The code an account signed up with. */
export interface SignedUpWith {
  codeId: string
  hint: string
  note: string
  createdBy: string | null
  usedAt: string
}

export interface AdminSettings {
  registrationMode: RegistrationMode
  /** The storage quota new accounts get; existing accounts keep theirs. */
  defaultStorageQuotaBytes: number
  chatMailboxRetentionDays: number
  chatMediaDeliveryRetentionDays: number
  /** Joins and requests through group links, per minute per relay server and group. */
  chatGroupLinkJoinsPerRelayGroupPerMin: number
  /** The same, per minute per relay server across all groups. */
  chatGroupLinkJoinsPerRelayPerMin: number
  /** Multi-recipient group sends and group send endorsements (each an administrator's setting). */
  chatMultiMaxRecipients: number
  chatMultiMaxMessageBytes: number
  chatMultiBaseBytes: number
  chatMultiIpBytesPerMin: number
  chatMultiPerRecipientPerMin: number
  chatMultiPerTokenPerMin: number
  chatGroupSendEndorsementsPerDay: number
  chatGroupEndorsementUploadsPerDay: number
  chatGroupEndorsementPageSize: number
  chatMultiOriginRequestsPerMin: number
  chatMultiOriginBytesPerMin: number
  /** The largest group avatar blob hosted groups take (one of the avatar lengths). */
  chatGroupAvatarMaxBytes: number
  /** The most a hosted group's avatars may take, in bytes (at least twice the largest). */
  chatGroupAvatarStoragePerGroupBytes: number
  /** How long an avatar upload waits for a change to name it, in seconds. */
  chatGroupAvatarPendingSeconds: number
  /** The largest `.kdbx` file Kutup Pass takes in an upload, in bytes (1 MiB to 1 GiB). */
  passVaultMaxBytes: number
  /** Calendars (site_settings::CALENDAR_SETTINGS). */
  calendarsPerAccount: number
  calendarEventsPerCalendar: number
  calendarSyncBatch: number
  calendarMaxCount: number
  calendarRemindersPerEvent: number
  calendarDefaultReminders: number
  calendarReminderLatenessSeconds: number
  calendarAlarmsPage: number
  calendarAlarmTickSeconds: number
  calendarAlarmBatch: number
  calendarAlarmBatchPerAccount: number
  calendarAlarmSends: number
  calendarAlarmsPerAccount: number
  calendarRecomputeBatch: number
  calendarPushSubscriptionsPerAccount: number
  calendarWindowDays: number
  calendarEventsPage: number
  /** Every device of an account, of every app (site_settings::DEVICES_PER_ACCOUNT). */
  devicesPerAccount: number
  /** How long a new device's row waits to be listed (site_settings::DEVICE_LISTING_GRACE_SECONDS). */
  deviceListingGraceSeconds: number
  /** Linking Chat devices (site_settings::CHAT_IDENTITY_SETTINGS). */
  chatLinkTokenSeconds: number
  /** How many two-factor recovery codes are made at once. */
  twoFactorRecoveryCodes: number
  securityKeysPerAccount: number
  webauthnCeremonySeconds: number
  chatLinkTokensPerAccount: number
  chatProvisionBodyBytes: number
  chatMaxActiveDevices: number
  chatProvisioningTicketSeconds: number
  chatProvisioningSocketsPerAccount: number
  chatDistributionMessageBytes: number
  /** Drive uploads and streaming (site_settings::DRIVE_SETTINGS), sizes in bytes. */
  driveUploadMaxBytes: number
  driveVersionMaxBytes: number
  driveStreamMaxBytes: number
  driveStreamCacheBlocks: number
  driveStreamReadaheadBlocks: number
  driveStreamMaxConcurrent: number
  driveStreamResponseMaxBytes: number
  driveStreamBlobFallbackMaxBytes: number
}

export type FederationMode = 'disabled' | 'allowlist' | 'blocklist' | 'open'
export type FederationRuleAction = 'inherit' | 'allow' | 'block'
export type FederationMinimumTrust = 'tofu' | 'verified'
export type FederationTrustRequirement = 'inherit' | FederationMinimumTrust

export interface FederationFeaturePolicy {
  feature: 'chat' | 'drive'
  mode: FederationMode
  minimumTrust: FederationMinimumTrust
}

export interface FederationDomainRule {
  domain: string
  feature: 'chat' | 'drive'
  inbound: FederationRuleAction
  outbound: FederationRuleAction
  trustRequirement: FederationTrustRequirement
  createdAt: string
  updatedAt: string
}

export interface FederationPeer {
  domain: string
  trust: 'tofu' | 'verified' | 'quarantined'
  sequence: number
  fingerprint: string
  fingerprintDisplay: string
  apiBase: string | null
  capabilities: string[]
  firstSeenAt: string
  lastSeenAt: string
  verifiedAt: string | null
  discoveryExpiresAt: string | null
  quarantineReason: string | null
  pendingFingerprint: string | null
  lastDiscoveryError: string | null
  diagnostics: {
    chatPendingTransactions: number
    chatMismatchTransactions: number
    driveIncomingShares: number
    driveOutgoingShares: number
  }
}

export interface FederationPeerEvidenceDocument {
  sequence: number
  documentHash: string
  fingerprint: string
  fingerprintDisplay: string
  acceptance: 'accepted' | 'quarantined' | 'superseded'
  document: Record<string, unknown>
  recordedAt: string
}

export interface FederationPeerEvidence {
  domain: string
  trust: FederationPeer['trust']
  currentDocumentHash: string
  pendingDocumentHash: string | null
  quarantineReason: string | null
  documents: FederationPeerEvidenceDocument[]
  truncated: boolean
}

export interface BulkFederationPeerRetryResponse {
  results: Array<{
    domain: string
    refreshed: boolean
    error: string | null
  }>
}

export interface AdminFederationPolicy {
  /** False when the server has no persistent FEDERATION_SIGNING_KEY. */
  configured: boolean
  serverName: string | null
  fingerprint: string | null
  fingerprintDisplay: string | null
  identitySequence: number | null
  capabilities: string[]
  globalEnabled: boolean
  features: FederationFeaturePolicy[]
  rules: FederationDomainRule[]
  peers: FederationPeer[]
  operational: {
    peerTotal: number
    tofuPeers: number
    verifiedPeers: number
    quarantinedPeers: number
    chatPendingTransactions: number
    chatMismatchTransactions: number
    oldestChatPendingAt: string | null
    driveIncomingShares: number
    driveOutgoingShares: number
    activeReplayReservations: number
  }
}

/**
 * One admin audit-log row — `GET /admin/activity`. `adminUsername`/`targetUsername`
 * are the LIVE identities and go `null` once the referenced account is
 * deleted; `payload` keeps the at-action-time snapshot (`payload.username`).
 */
export interface AdminActivityEntry {
  id: number
  /** User, settings, and `federation.*` mutation action identifiers. */
  action: string
  adminUserId: string
  adminUsername: string | null
  targetUserId: string | null
  targetUsername: string | null
  payload: Record<string, unknown>
  occurredAt: string
}

export interface AdminActivityResponse {
  entries: AdminActivityEntry[]
  /** Pass as `?before=` for the next (older) page; `null` = no more pages. */
  nextBefore: number | null
}

export interface UserByAddressResponse {
  userId: string
  account: string
  driveHpkePublicKey: string
  accountIncarnationId: string
  driveSigningPublicKey: string
}

export interface PublicShareData {
  id: string
  shareType: string
  targetId: string
  collectionKeyEnvelope: string
  collectionKeyEpoch: number
  ownerUserId: string
  expiresAt?: string
}

export interface ErrorResponse {
  error: string
}
