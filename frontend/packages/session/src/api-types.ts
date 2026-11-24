// TypeScript interfaces matching backend handlers/models.go

export interface CollectionRow {
  id: string
  ownerAccountId: string
  nameEnvelope: string
  ownerKeyEnvelope?: string
  namedShareEnvelope?: string
  keyEpoch: number
  nameRevision: number
  epochStatement: string
  epochStatementHash: string
  /** A shared folder's owner's server; with `ownerAccountId`, the owner. */
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
  uploaderAccountId: string
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
  /** The original upload is gone (deleted from the history, or pruned by retention); absent while kept. */
  originalPruned?: boolean
}

export type SuspendedReason = 'admin' | 'operatorOrder' | 'security'

/** What an account may do on its server (`breakGlassAdmin`: the one `bootstrap_admin` made). */
export type AccountRole = 'member' | 'admin' | 'breakGlassAdmin'

/** The authenticator app: on, set up but not confirmed by a first code yet, or off. */
export type TwoFactorState = 'on' | 'pending' | 'off'

/** Administers the server (the break-glass administrator too). */
export function administers(role: AccountRole | undefined): boolean {
  return role === 'admin' || role === 'breakGlassAdmin'
}

export interface UserRow {
  id: string
  username: string
  storageQuotaBytes: number
  storageUsedBytes: number
  /** `breakGlassAdmin` is never demoted, suspended, closed or reset (the UI disables those). */
  role: AccountRole
  /** `active`, `suspended` or `closing` (docs/plans/server-personal-data.md, A5). */
  state: 'active' | 'suspended' | 'closing'
  /** Why a suspended account is. */
  suspendedReason?: SuspendedReason
  /** When a closing account is deleted. */
  closesAt?: string
  /** A legal hold's reference: while set, nothing deletes the account. */
  legalHoldReference?: string
  legalHoldAt?: string
  /** Failed tries at deleting this closing account past its date; 0 when none. */
  /** Whether it may share by public link, as an administrator set it. */
  publicSharing: 'on' | 'off'
  /** Whether its Chat and Drive talk to other servers. */
  federation: 'on' | 'off'
  deletionAttempts: number
  /** When its data key was found not to open: what was sealed under it is lost. */
  dataKeyLostAt?: string
  /** The authenticator app. */
  twoFactor: TwoFactorState
  /**
   * The account has set up its keys. Until then it is on the admin-issued
   * temp password, and "Rotate temp password" is safe (only then).
   */
  keysSetUp: boolean
  createdAt: string
}

export interface LoginResponse {
  accessToken: string
  accountId: string
  username: string
  masterKeyEnvelope: string
  /** The account's root records (docs/plans/identity-root.md), with the session only. */
  accountRoots?: string[]
  /** The authority the newest identity root must derive, with the session only. */
  accountAuthorityPublicKey?: string
  /** The account's Drive key (X-Wing), with the session only. */
  driveXwingPublicKey?: string
  /** With the session only. */
  role?: AccountRole
  storageQuotaBytes: number
  storageUsedBytes: number
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
  ownerAccountId: string
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
  /** Calendars at 90% or more of `calendar.key_generations` (their owners' apps compact them). */
  calendarsNearKeyLimit?: number
  totalAccounts: number
  activeAccounts: number
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
  accountId: string
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

/** A whole-number setting's Server settings section (site_settings::SettingSection). */
export type SettingSection = 'chatMulti' | 'calendar' | 'chatLinking' | 'twoFactor' | 'drive' | 'federation' | 'privacy' | 'backups' | 'mail' | 'accountRecords' | 'pass' | 'sessions'
/** What a whole-number setting counts. */
export type SettingUnit = 'bytes' | 'count' | 'seconds' | 'days'
/** Where a value in effect comes from. */
export type ValueSource = 'account' | 'site' | 'default'

/** One whole-number setting, as `GET /api/v1/admin/settings/registry` lists it. */
export interface RegistrySetting {
  key: string
  /** Its field in `/api/v1/admin/settings`. */
  field: keyof AdminSettings
  section: SettingSection
  unit: SettingUnit
  default: number
  min: number
  max: number
  /** Whether one account may have its own value. */
  perAccount: boolean
  value: number
  set: boolean
}

/** A setting that limits one account, as it stands for one account. */
export interface AccountSettingLimit {
  key: string
  field: keyof AdminSettings
  section: SettingSection
  unit: SettingUnit
  value: number
  source: ValueSource
  siteValue: number
  min: number
  max: number
}

/** A rate limit counted per account, as it stands for one account. */
export interface AccountRateLimitLimit {
  /** The rate limit's key, `<app>.rate.<name>` (what `PUT …/limits/{key}` takes). */
  key: string
  /** The rate limit's key, as Rate limits lists it (the same as `key`). */
  limit: string
  section: string
  unit: 'events' | 'attempts' | 'minutes' | 'bytes' | 'atOnce' | 'bytesAtOnce'
  windowSeconds: number | null
  value: number
  source: ValueSource
  siteValue: number
  min: number
  max: number
}

/** `GET /api/v1/admin/accounts/{id}/entitlements`. */
export interface AccountLimits {
  settings: AccountSettingLimit[]
  rateLimits: AccountRateLimitLimit[]
}

/** Who may open public links (docs/plans/server-personal-data.md, A11). */
export type PublicSharing = 'on' | 'off' | 'signedIn'

export interface AdminSettings {
  registrationMode: RegistrationMode
  publicSharing: PublicSharing
  /** Whether a new account talks to other servers. */
  federationDefault: boolean
  /** Whether turning federation on asks for the `federation` consent; new accounts then start off. */
  federationConsentRequired: boolean
  /** The storage quota new accounts get; existing accounts keep theirs. */
  defaultStorageQuotaBytes: number
  chatMailboxRetentionDays: number
  chatMediaDeliveryRetentionDays: number
  /** Joins and requests through group links, per minute per relay server and group. */
  chatGroupLinkJoinsPerRelayGroupPerMin: number
  /** The same, per minute per relay server across all groups. */
  chatGroupLinkJoinsPerRelayPerMin: number
  /** The most members and open invitations a group hosted here may have. */
  chatGroupMaxMembers: number
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
  /** The Drive version retention periods an account may choose, in days, ascending. */
  driveVersionRetentionChoices: number[]
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
  /** Calendar sharing (docs/plans/calendar-e3.md). */
  calendarMembersPerCalendar: number
  calendarLinksPerCalendar: number
  /** 1: links with the key in the address are allowed; 0: off. */
  calendarQueryLinksAllowed: number
  calendarInvitationDays: number
  calendarBusyWindowDays: number
  calendarKeyGenerations: number
  /** Every device of an account, of every app (site_settings::DEVICES_PER_ACCOUNT). */
  devicesPerAccount: number
  /** How long a new device's row waits to be listed (site_settings::DEVICE_LISTING_GRACE_SECONDS). */
  deviceListingGraceSeconds: number
  /** How long a cached manifest of another server's account is trusted (site_settings::REMOTE_MANIFEST_MAX_AGE_SECONDS). */
  remoteManifestMaxAgeSeconds: number
  /** Linking Chat devices (site_settings::CHAT_IDENTITY_SETTINGS). */
  chatLinkTokenSeconds: number
  /** How many two-factor recovery codes are made at once. */
  twoFactorRecoveryCodes: number
  /** Authenticator code steps taken either side of now (site_settings::TOTP_SKEW_STEPS). */
  totpSkewSteps: number
  securityKeysPerAccount: number
  webauthnCeremonySeconds: number
  chatLinkTokensPerAccount: number
  chatProvisionBodyBytes: number
  chatMaxActiveDevices: number
  chatProvisioningTicketSeconds: number
  chatProvisioningSocketsPerAccount: number
  chatDistributionMessageBytes: number
  /** Drive's trash, uploads and streaming (site_settings::DRIVE_SETTINGS), sizes in bytes. */
  driveTrashRetentionDays: number
  driveUploadMaxBytes: number
  driveVersionMaxBytes: number
  driveStreamMaxBytes: number
  driveStreamCacheBlocks: number
  driveStreamReadaheadBlocks: number
  driveStreamMaxConcurrent: number
  driveStreamResponseMaxBytes: number
  driveStreamBlobFallbackMaxBytes: number
  /** How old an incomplete multipart upload no upload names gets before it is aborted, in seconds. */
  storageIncompleteMultipartMaxAgeSeconds: number
  /** Federation deliveries (docs/plans/federation-outbox.md): backoff and worker in seconds, records and announces in days. */
  federationRetryBaseSeconds: number
  federationRetryMaxSeconds: number
  federationPeerUpgradeSeconds: number
  federationWorkerSeconds: number
  federationHeadsPerTick: number
  federationRecordDays: number
  federationAnnounceDays: number
  federationAnnouncePeerDays: number
  chatAttachmentSendLifetimeSeconds: number
  /** Backups and health (docs/plans/restore-drill-and-alerting.md), in seconds. */
  storageDeletedBlobRetentionSeconds: number
  storageDeletedBlobSweepSeconds: number
  healthBackupMaxAgeSeconds: number
  healthJobGraceSeconds: number
  healthProbeTimeoutSeconds: number
  /** The most keys one mail address's signed list may hold. */
  mailKeysPerAddress: number
  /** The account-records store (site_settings::ACCOUNT_RECORDS_SETTINGS). */
  accountRecordsPassSecrets: number
  accountRecordsChatGroups: number
  accountRecordsChatContacts: number
  accountRecordsPhotosLibrary: number
  accountRecordsChatAttachments: number
  accountRecordsContactGroups: number
  accountRecordsCalendarSettings: number
  accountRecordsJoinedMeetings: number
  accountRecordsBatchItems: number
  accountRecordsPage: number
  accountRecordsTombstoneDays: number
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
    chatMismatchesLastDay: number
    driveIncomingShares: number
    driveOutgoingShares: number
    deliveries: FederationDeliveryCounts[]
  }
}

/** One kind of delivery to other servers (docs/plans/federation-outbox.md). */
export interface FederationDeliveryCounts {
  kind: 'chat' | 'sealed' | 'media' | 'rename'
  pending: number
  /** Refused for good in the last day. */
  rejectedLastDay: number
  oldestPendingAt: string | null
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
    chatMismatchesLastDay: number
    oldestChatPendingAt: string | null
    driveIncomingShares: number
    driveOutgoingShares: number
    activeReplayReservations: number
    deliveries: FederationDeliveryCounts[]
  }
}

/**
 * One admin audit-log row — `GET /admin/activity`. `adminUsername`/`targetUsername`
 * are the LIVE identities and go `null` once the referenced account is
 * deleted; the payload names accounts by id only.
 */
export interface AdminActivityEntry {
  id: number
  /** `area.verb` (e.g. `account.create`, `federation.updatePolicy`); the list is `AdminAction` in audit_log.rs. */
  action: string
  adminAccountId: string
  adminUsername: string | null
  targetAccountId: string | null
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
  accountId: string
  account: string
  driveXwingPublicKey: string
  accountIncarnationId: string
  driveSigningPublicKey: string
}

export interface PublicShareData {
  id: string
  shareType: string
  targetId: string
  collectionKeyEnvelope: string
  collectionKeyEpoch: number
  ownerAccountId: string
  expiresAt?: string
}

export interface ErrorResponse {
  error: string
}
