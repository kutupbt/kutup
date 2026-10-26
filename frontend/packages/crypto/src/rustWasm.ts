// One loader for Kutup-owned browser cryptography. Feature adapters expose
// typed operations; this module owns only generated-module initialization.

import { freshUrl, retryLoad } from './retry'

// The runtime's path is its build (`crypto-wasm`, or `crypto-calendar-wasm`
// for the apps with calendars) and its content hash (the build passes it in,
// @kutup/config/vite), so a new build is a new URL and the files can be
// cached for good. Without it (tests) the files are looked for directly
// under /crypto-wasm/.
declare const __KUTUP_CRYPTO_WASM__: string | undefined
const BASE = typeof __KUTUP_CRYPTO_WASM__ === 'string' && /\/[0-9a-f]{16}$/.test(__KUTUP_CRYPTO_WASM__) ? `/${__KUTUP_CRYPTO_WASM__}` : '/crypto-wasm'
const MODULE_URL = `${BASE}/kutup_crypto_wasm.js`
const WASM_URL = `${BASE}/kutup_crypto_wasm_bg.wasm`

/** A shared mailbox's key as a member holds it, as WASM takes it. */
export interface GroupKeyHolder {
  account: { server: string; accountId: string }
  hpkePrivateKey: string
  share: string
  groupId: string
  fingerprint: string
}

/** A shared mailbox's signing key as an owner or manager holds it, as WASM takes it. */
export interface GroupSignerHolderJs {
  account: { server: string; accountId: string }
  hpkePrivateKey: string
  groupId: string
  signer: string
  signingShare: string
}

/** A verified shared-mailbox key-list chain. */
export interface GroupKeyChainViewJs {
  firstSigner: string
  signer: string
  signers: string[]
  sequence: number
  digests: string[]
  newest: unknown
}

/** A member a group key is shared with: their account and checked account key. */
export interface GroupKeyMember {
  account: { server: string; accountId: string }
  incarnationId: string
  hpkePublicKey: string
}

export interface CryptoWasmModule {
  default(input?: unknown): Promise<unknown>
  sealLocalState(
    plaintextBase64: string,
    keyBase64: string,
    purpose: number,
    profile: string,
  ): string
  openLocalState(
    envelopeBase64: string,
    keyBase64: string,
    purpose: number,
    profile: string,
  ): string
  deriveRecoveryAuthProof(recoveryEntropyBase64: string, binding: string): string
  deriveAccountIdentityKeys(masterKeyBase64: string): {
    authorityPublicKey: string
    authorityKeyId: string
    incarnationId: string
    driveHpkePublicKey: string
    driveHpkePrivateKey: string
    driveSigningPublicKey: string
  }
  signDriveKeyBinding(masterKeyBase64: string, account: { server: string; accountId: string }, bindingEpoch: number): string
  deriveSafetyNumber(
    local: { server: string; accountId: string },
    localAuthorityBase64: string,
    peer: { server: string; accountId: string },
    peerAuthorityBase64: string,
  ): { fingerprint: string; qrPayload: string }
  safetyQrMatches(
    local: { server: string; accountId: string },
    localAuthorityBase64: string,
    peer: { server: string; accountId: string },
    peerAuthorityBase64: string,
    scanned: string,
  ): boolean
  foldName(name: string): string
  /** `aci:<uuid>@<server>` → `{ server, accountId }`; throws for anything else. */
  parseAccountRef(value: string): { server: string; accountId: string }
  /** `{ server, accountId }` → `aci:<uuid>@<server>`, both checked. */
  accountRefString(server: string, accountId: string): string
  foldAddress(address: string): string | undefined
  signAccountRename(masterKeyBase64: string, sequence: number, previous: string, current: string, issuedAtMs: number): string
  verifyAccountRenameChain(
    authorityPublicBase64: string,
    chainJson: string,
    knownDigestsJson?: string | null,
  ): { incarnationId: string; first: string; current: string; addresses: string[]; sequence: number; digests: string[] }
  recordIdentityPin(
    pinsJson: string,
    account: { server: string; accountId: string },
    address: string | undefined,
    authorityPublicBase64: string,
    update: string,
    since: string,
  ): unknown
  lookupIdentityPin(
    pinsJson: string,
    account: { server: string; accountId: string },
    address?: string,
    publishedAuthorityBase64?: string,
  ): unknown
  identityPinsAt(pinsJson: string, address: string): unknown
  lookupGroupPin(pinsJson: string, server: string, groupId: string, signers: string[], digests: string[]): unknown
  recordGroupPin(pinsJson: string, server: string, groupId: string, signers: string[], digests: string[], update: string, since: string): unknown
  applyAccountRenameToPins(pinsJson: string, account: { server: string; accountId: string }, chainJson: string, since: string): unknown
  verifyDriveKeyBinding(
    account: { server: string; accountId: string },
    authorityPublicKeyBase64: string,
    driveHpkePublicKeyBase64: string,
    driveSigningPublicKeyBase64: string,
    bindingBase64: string,
    bindingEpoch: number,
  ): boolean
  incarnationIdOfAuthority(authorityPublicKeyBase64: string): string
  sealIdentityPins(masterKeyBase64: string, binding: string, revision: number, pinsJson: string): string
  openIdentityPins(masterKeyBase64: string, binding: string, sealedBase64: string): { value: string; revision: number }
  signContactSummary(masterKeyBase64: string, binding: string, revision: number, summaryJson: string): { summary: string; signature: string }
  verifyContactSummary(
    summary: string,
    signatureBase64: string,
    binding: string,
    revision: number,
    authorityPublicKeyBase64: string,
  ): import('./contactCard').ContactSummary
  sealContactCard(masterKeyBase64: string, binding: string, uid: string, revision: number, vcard: string): string
  openContactCard(masterKeyBase64: string, binding: string, uid: string, sealedBase64: string): { value: string; revision: number }
  sealMailName(masterKeyBase64: string, binding: string, kind: string, id: string, revision: number, name: string): string
  openMailName(masterKeyBase64: string, binding: string, kind: string, id: string, sealedBase64: string): { value: string; revision: number }
  inspectAccountEnvelope(envelopeBase64: string): number
  RevisionGuardKeys: new (masterKeyBase64: string) => import('./revisionGuard').GuardKeys & { free(): void }
  AccountHeadKeys: new (masterKeyBase64: string, binding: string, incarnationId: string) => AccountHeadKeysHandle
  OpaqueLogin: { start(password: string): OpaqueLoginHandle }
  OpaqueRegistration: { start(password: string): OpaqueRegistrationHandle }
  generateMailGroupKey(
    groupAddress: string,
    groupId: string,
    createdAtSecs: number,
    members: GroupKeyMember[],
  ): { publicKey: string; fingerprint: string; sha256Fingerprint: string; shares: string[] }
  reshareMailGroupKey(
    key: GroupKeyHolder,
    members: GroupKeyMember[],
  ): string[]
  openMailGroupMessage(
    key: GroupKeyHolder,
    message: Uint8Array,
    senderPublicKeyBase64?: string,
  ): { data: Uint8Array; signed: boolean; verified: boolean; free(): void }
  encryptMailMessageUnsigned(recipientPublicKeys: string[], plaintext: Uint8Array): { keyPackets: string[]; dataPacket: Uint8Array; free(): void }
  encryptMailPgpUnsigned(recipientPublicKeys: string[], plaintext: Uint8Array): string
  signMailDetached(masterKeyBase64: string, binding: string, address: string, envelopeBase64: string, fingerprintHex: string, content: Uint8Array): string
  signMailCleartext(masterKeyBase64: string, binding: string, address: string, envelopeBase64: string, fingerprintHex: string, text: string): string
  signMailCleartextAsGroup(
    key: GroupKeyHolder,
    text: string,
  ): string
  signMailDetachedAsGroup(
    key: GroupKeyHolder,
    content: Uint8Array,
  ): string
  encryptMailMessageAsGroup(
    key: GroupKeyHolder,
    recipientPublicKeys: string[],
    plaintext: Uint8Array,
  ): { keyPackets: string[]; dataPacket: Uint8Array; free(): void }
  encryptMailPgpAsGroup(
    key: GroupKeyHolder,
    recipientPublicKeys: string[],
    plaintext: Uint8Array,
  ): string
  exportMailAddressKey(
    masterKeyBase64: string,
    binding: string,
    address: string,
    envelopeBase64: string,
    fingerprintHex: string,
    passphrase: string,
  ): string
  importMailAddressKey(
    masterKeyBase64: string,
    binding: string,
    address: string,
    file: Uint8Array,
    passphrase: string,
  ): { publicKey: string; envelope: string; fingerprint: string; sha256Fingerprint: string }
  generateMailAddressKey(
    masterKeyBase64: string,
    binding: string,
    address: string,
    createdAtSecs: number,
  ): import('./mailKey').GeneratedMailAddressKey
  inspectMailAddressPublicKey(
    publicKeyBase64: string,
    address: string,
  ): { fingerprint: string; sha256Fingerprint: string; createdAt: number }
  armorMailPublicKey(publicKeyBase64: string): string
  verifyMailGroupKeyChain(
    groupId: string,
    firstSignerBase64: string,
    lists: { data: string; signature: string }[],
    handovers: string[],
  ): GroupKeyChainViewJs
  signMailGroupKeyList(holder: GroupSignerHolderJs, list: unknown): unknown
  newMailGroupSigner(
    groupId: string,
    members: GroupKeyMember[],
    list: unknown,
    outgoing: GroupSignerHolderJs | undefined,
    previousListHash: string | undefined,
  ): { publicKey: string; shares: string[]; keyList: unknown; handover?: string }
  reshareMailGroupSigner(holder: GroupSignerHolderJs, members: GroupKeyMember[]): string[]
  signMailKeyList(
    masterKeyBase64: string,
    list: import('./mailKey').MailKeyListInput,
  ): import('./mailKey').SignedMailKeyList
  verifyMailKeyList(
    dataBase64: string,
    signatureBase64: string,
    authorityPublicKeyBase64: string,
    previousDataBase64?: string,
    previousSignatureBase64?: string,
  ): import('./mailKey').SignedMailKeyList
  makeMailForwarding(
    masterKeyBase64: string,
    binding: string,
    forwarderAddress: string,
    envelopeBase64: string,
    fingerprintHex: string,
    forwardeeAddress: string,
    forwardeePublicKeyBase64: string,
    forwardingId: string,
    createdAtSecs: number,
    expiresAtSecs: number,
  ): import('./mailKey').MailForwardingMaterial
  acceptMailForwarding(
    masterKeyBase64: string,
    binding: string,
    forwardeeAddress: string,
    envelopeBase64: string,
    fingerprintHex: string,
    forwarderAddress: string,
    forwarderPublicKeyBase64: string,
    forwardingId: string,
    nowSecs: number,
    activation: string,
  ): import('./mailKey').AcceptedMailForwarding
  openForwardedMailMessage(
    masterKeyBase64: string,
    binding: string,
    address: string,
    envelopeBase64: string,
    fingerprintHex: string,
    message: Uint8Array,
    senderPublicKeyBase64?: string,
  ): { data: Uint8Array; signed: boolean; verified: boolean; free(): void }
  openMailMessage(
    masterKeyBase64: string,
    binding: string,
    address: string,
    envelopeBase64: string,
    fingerprintHex: string,
    message: Uint8Array,
    senderPublicKeyBase64?: string,
  ): { data: Uint8Array; signed: boolean; verified: boolean; free(): void }
  encryptMailMessage(
    masterKeyBase64: string,
    binding: string,
    address: string,
    envelopeBase64: string,
    fingerprintHex: string,
    recipientPublicKeys: string[],
    plaintext: Uint8Array,
  ): { keyPackets: string[]; dataPacket: Uint8Array; free(): void }
  inspectExternalMailKey(publicKey: Uint8Array, address: string): { publicKey: string; fingerprint: string; createdAt: number }
  describeExternalMailKey(publicKey: Uint8Array): { publicKey: string; fingerprint: string; createdAt: number }
  describeExternalMailKeyDetails(publicKey: Uint8Array, address: string): import('./mailKey').ExternalMailKeyDetails
  encryptMailPgp(
    masterKeyBase64: string,
    binding: string,
    address: string,
    envelopeBase64: string,
    fingerprintHex: string,
    recipientPublicKeys: string[],
    plaintext: Uint8Array,
  ): string
  verifyMailDetachedSignature(signature: Uint8Array, content: Uint8Array, signerPublicKeyBase64: string): boolean
  verifyMailCleartext(message: string, signerPublicKeyBase64?: string): { text: string; verified: boolean }
  sealAccountEnvelope(
    plaintextBase64: string,
    keyBase64: string,
    purpose: number,
    binding: string,
  ): string
  openAccountEnvelope(
    envelopeBase64: string,
    keyBase64: string,
    expectedPurpose: number,
    binding: string,
  ): string
  createChatBackupSignerAuthorization(
    masterKeyBase64: string,
    backupRootBase64: string,
    backupIncarnationId: string,
    createdAtUnix: bigint,
  ): unknown
  verifyChatBackupMetadata(
    signerAuthorization: unknown,
    manifest: unknown,
    masterKeyBase64: string,
    backupRootBase64: string,
    expectedBackupIncarnationId: string,
  ): { signerAuthorizationDigest: string; manifestDigest?: string }
  encodeChatBackupPlaintext(value: unknown, purpose: number): string
  decodeChatBackupPlaintext(plaintextBase64: string, purpose: number): unknown
  sealChatBackupObject(
    plaintextBase64: string,
    backupRootBase64: string,
    accountIncarnationId: string,
    backupIncarnationId: string,
    purpose: number,
    objectId: string,
    sourceDeviceId: number,
    deviceSequence: bigint,
    previousSegmentDigest: string,
  ): string
  openChatBackupObject(
    objectBase64: string,
    backupRootBase64: string,
    accountIncarnationId: string,
    backupIncarnationId: string,
    purpose: number,
    objectId: string,
    sourceDeviceId: number,
    deviceSequence: bigint,
    previousSegmentDigest: string,
  ): string
  signChatBackupManifest(
    unsignedManifest: unknown,
    backupRootBase64: string,
    accountIncarnationId: string,
    backupIncarnationId: string,
  ): unknown
  prepareChatBackupMedia(
    backupRootBase64: string,
    accountIncarnationId: string,
    backupIncarnationId: string,
    stableSourceBinding: string,
    sourceCiphertextBytes: bigint,
  ): {
    mediaId: string
    outerEncryptionKey: string
    objectHeader: string
    paddedPlaintextBytes: number
  }
  openChatBackupMediaHeader(
    headerBase64: string,
    backupRootBase64: string,
    expectedAccountIncarnationId: string,
    expectedBackupIncarnationId: string,
    expectedMediaId: string,
  ): {
    outerEncryptionKey: string
    sourceCiphertextBytes: number
    paddedPlaintextBytes: number
  }
  sealDriveEnvelope(
    plaintextBase64: string,
    rootKeyBase64: string,
    purpose: number,
    epoch: number,
    revision: bigint,
    objectId: string,
    parentId: string,
  ): string
  openDriveEnvelope(
    envelopeBase64: string,
    rootKeyBase64: string,
    expectedPurpose: number,
    expectedEpoch: number,
    expectedRevision: bigint,
    expectedObjectId: string,
    expectedParentId: string,
  ): string
  sealWhiteboardAsset(
    plaintextBase64: string,
    fileKeyBase64: string,
    fileId: string,
    assetId: string,
    generation: number,
  ): string
  openWhiteboardAsset(
    envelopeBase64: string,
    fileKeyBase64: string,
    expectedFileId: string,
    expectedAssetId: string,
    expectedGeneration: number,
  ): string
  sealThumbnail(
    imageBase64: string,
    format: number,
    width: number,
    height: number,
    variant: string,
    fileKeyBase64: string,
    fileId: string,
    generation: number,
  ): string
  openThumbnail(
    envelopeBase64: string,
    variant: string,
    fileKeyBase64: string,
    expectedFileId: string,
    expectedGeneration: number,
  ): { format: number; width: number; height: number; image: string }
  prepareDriveFileBlob(
    fileKeyBase64: string,
    fileId: string,
    generation: number,
  ): { objectHeader: string; streamKey: string }
  openDriveFileBlobHeader(
    objectHeaderBase64: string,
    fileKeyBase64: string,
    expectedFileId: string,
    expectedGeneration: number,
  ): string
  prepareChatMediaObject(
    attachmentKeyBase64: string,
    attachmentId: string,
  ): { objectHeader: string; streamKey: string }
  openChatMediaObjectHeader(
    objectHeaderBase64: string,
    attachmentKeyBase64: string,
    expectedAttachmentId: string,
  ): string
  deriveChatAttachmentLedgerKey(masterKeyBase64: string): string
  sealChatAttachmentLedger(
    plaintextBase64: string,
    ledgerKeyBase64: string,
    accountIncarnationId: string,
    entityId: string,
    revision: bigint,
    previousEnvelopeDigest: string,
  ): string
  openChatAttachmentLedger(
    envelopeBase64: string,
    ledgerKeyBase64: string,
    expectedAccountIncarnationId: string,
    expectedEntityId: string,
    expectedRevision: bigint,
    expectedPreviousEnvelopeDigest: string,
  ): string
  chatAttachmentLedgerEnvelopeDigest(envelopeBase64: string): string
  inspectChatAttachmentLedgerEnvelope(envelopeBase64: string): {
    suite: number
    accountIncarnationId: string
    entityId: string
    revision: string
    previousEnvelopeDigest: string
  }
  encodeChatAttachmentLedgerEntry(entry: unknown): string
  decodeChatAttachmentLedgerEntry(entryBase64: string): unknown
  sealCollabFrame(
    plaintextBase64: string,
    fileKeyBase64: string,
    kind: number,
    keyGeneration: number,
    docKeyId: number,
    fileId: string,
    deviceId: number,
    manifestSequence: string,
    sequence: string,
  ): string
  /** What the device's frame key signs: the frame under its sender account (`aci:<uuid>@<server>`). */
  collabFrameSigningBytes(frameBase64: string, senderAccount: string): string
  /** A frame as a server delivers it (the sender account's bytes, then the packed frame). */
  deliveredCollabFrame(deliveredBase64: string): { sender: string; frame: string }
  /** Whether `senderAccount` signed the frame with `frameKeyBase64` (its manifest's key for the frame's device). */
  verifyCollabFrame(frameBase64: string, senderAccount: string, frameKeyBase64: string): boolean
  attachCollabFrameSignature(frameBase64: string, signatureBase64: string): string
  openCollabFrame(
    frameBase64: string,
    fileKeyBase64: string,
    expectedFileId: string,
    expectedKeyGeneration: number,
  ): {
    kind: number
    keyGeneration: number
    docKeyId: number
    deviceId: number
    manifestSequence: string
    sequence: string
    plaintext: string
  }
  /**
   * The account's next manifest with `entry` listed (in place of any entry
   * of its id), signed with the authority the master key derives; `head`
   * null starts the account's first manifest, naming `account`.
   */
  listDeviceInManifest(
    head: unknown,
    entry: unknown,
    issuedAt: string,
    masterKeyBase64: string,
    account: string,
  ): unknown
  /** The account's next manifest without `deviceIds`, signed as above; it keeps at least one device. */
  removeDevicesFromManifest(head: unknown, deviceIds: Uint32Array, issuedAt: string, masterKeyBase64: string): unknown
  collabFrameKeyGeneration(frameBase64: string): number
  sealPreviousFileKey(
    previousKeyBase64: string,
    keyBase64: string,
    fileId: string,
    generation: number,
  ): string
  fileKeyAt(
    currentKeyBase64: string,
    fileId: string,
    generation: number,
    chain: { generation: number; previousKeyEnvelope: string }[],
    wanted: number,
  ): string
  sealPreviousCollectionKey(
    previousKeyBase64: string,
    keyBase64: string,
    collectionId: string,
    ownerUserId: string,
    epoch: number,
  ): string
  unlockCollectionKeyring(
    currentKeyBase64: string,
    collectionId: string,
    ownerUserId: string,
    ownerAuthorityPublicKeyBase64: string,
    chain: { epoch: number; epochStatement: string; previousKeyEnvelope?: string }[],
  ): string[]
  createCollectionEpochStatement(
    masterKeyBase64: string,
    collectionKeyBase64: string,
    collectionId: string,
    ownerUserId: string,
    epoch: number,
    previousStatementHash: string,
  ): string
  verifyCollectionEpochStatement(
    statementBase64: string,
    authorityPublicKeyBase64: string,
    collectionKeyBase64: string,
    expectedCollectionId: string,
    expectedOwnerUserId: string,
    expectedEpoch: number,
    expectedPreviousStatementHash: string,
  ): string
  sealNamedShareEnvelope(
    collectionKeyBase64: string,
    senderMasterKeyBase64: string,
    recipientHpkePublicKeyBase64: string,
    collectionId: string,
    epoch: number,
    sender: { server: string; accountId: string },
    senderIncarnationId: string,
    recipient: { server: string; accountId: string },
    recipientIncarnationId: string,
  ): string
  openNamedShareEnvelope(
    envelopeBase64: string,
    senderSigningPublicKeyBase64: string,
    recipientHpkePrivateKeyBase64: string,
    expectedCollectionId: string,
    expectedEpoch: number,
    expectedSender: { server: string; accountId: string },
    expectedSenderIncarnationId: string,
    expectedRecipient: { server: string; accountId: string },
    expectedRecipientIncarnationId: string,
  ): string
  sealFileShareEnvelope(
    fileKeyBase64: string,
    senderMasterKeyBase64: string,
    recipientHpkePublicKeyBase64: string,
    fileId: string,
    generation: number,
    sender: { server: string; accountId: string },
    senderIncarnationId: string,
    recipient: { server: string; accountId: string },
    recipientIncarnationId: string,
  ): string
  openFileShareEnvelope(
    envelopeBase64: string,
    senderSigningPublicKeyBase64: string,
    recipientHpkePrivateKeyBase64: string,
    expectedFileId: string,
    expectedGeneration: number,
    expectedSender: { server: string; accountId: string },
    expectedSenderIncarnationId: string,
    expectedRecipient: { server: string; accountId: string },
    expectedRecipientIncarnationId: string,
  ): string
  liveLocationSeal(
    keyBase64: string,
    streamIdHex: string,
    counter: number,
    lat: number,
    lon: number,
    accuracyM: number,
    atMs: number,
  ): string
  canonicalFileMetadata(json: string): string
  driveFolderHashKey(firstFolderKeyBase64: string, collectionId: string): string
  driveTopLevelHashKey(masterKeyBase64: string): string
  driveNameHash(hashKeyBase64: string, name: string): string
  driveContentHash(hashKeyBase64: string, contentSha256Base64: string): string
  driveCanonicalName(name: string): string
  yjsSeedClientId(fileId: string, content: Uint8Array): number
  photosLibraryKey(masterKeyBase64: string): string
  sealPhotosLibrary(
    libraryJson: string,
    keyBase64: string,
    accountIncarnationId: string,
    revision: number,
    previousDigest: string | undefined,
  ): { envelope: string; digest: string }
  openPhotosLibrary(
    envelopeBase64: string,
    keyBase64: string,
    accountIncarnationId: string,
    revision: number,
    previousDigest: string | undefined,
  ): string
  photosLibraryDigest(envelopeBase64: string): string
  inspectPhotosLibrary(envelopeBase64: string): { accountIncarnationId: string; revision: number; previousDigest?: string }
  ContentHasher: new () => { update(chunk: Uint8Array): void; finish(): string; free(): void }
  SuiteHasher: new () => { update(chunk: Uint8Array): void; finish(): Uint8Array; free(): void }
  signingKeyGenerate(): Uint8Array
  signingKeySign(privateKey: Uint8Array, message: Uint8Array): Uint8Array
  signingKeyVerify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean
  liveLocationOpen(keyBase64: string, streamIdHex: string, envelopeBase64: string): LiveLocationUpdate
  sealProfileKeyEnvelope(
    profileKeyBase64: string,
    senderMasterKeyBase64: string,
    recipientHpkePublicKeyBase64: string,
    sender: { server: string; accountId: string },
    senderIncarnationId: string,
    recipient: { server: string; accountId: string },
    recipientIncarnationId: string,
  ): string
  openProfileKeyEnvelope(
    envelopeBase64: string,
    senderSigningPublicKeyBase64: string,
    recipientHpkePrivateKeyBase64: string,
    expectedSender: { server: string; accountId: string },
    expectedSenderIncarnationId: string,
    expectedRecipient: { server: string; accountId: string },
    expectedRecipientIncarnationId: string,
  ): string
}

/** One opened live-location update. */
export interface LiveLocationUpdate {
  counter: number
  lat: number
  lon: number
  accuracyM: number
  atMs: number
}

let modulePromise: Promise<CryptoWasmModule> | null = null

/** The account head's keys and verified head (Rust `kutup_crypto::account_head`); kept in WASM. */
/** A verified account head (Rust `VerifiedHead`): each holder its own; free when done. */
export interface VerifiedAccountHeadHandle {
  anchor(): unknown
  head(): unknown
  copy(): VerifiedAccountHeadHandle
  free(): void
}

export interface AccountHeadCheckedHandle {
  status(): unknown
  takeVerified(): VerifiedAccountHeadHandle | undefined
  free(): void
}

export interface AccountHeadReanchoredHandle {
  record(): unknown
  takeVerified(): VerifiedAccountHeadHandle | undefined
  free(): void
}

export interface AccountHeadKeysHandle {
  writer(deviceId: string): string
  scope(scope: string, indexJson: string): unknown
  check(anchorJson: string | undefined, currentBase64: string, segmentJson: string | undefined): AccountHeadCheckedHandle
  reanchor(anchorJson: string, currentBase64: string, segmentJson: string | undefined, confirmed: boolean, atMs: number): AccountHeadReanchoredHandle
  checkIndex(verified: VerifiedAccountHeadHandle, scope: string, indexJson: string): unknown
  next(verified: VerifiedAccountHeadHandle, writer: string, scopesJson: string): string
  first(writer: string, scopesJson: string): string
  committed(verified: VerifiedAccountHeadHandle, sealedBase64: string): VerifiedAccountHeadHandle
  committedFirst(sealedBase64: string): VerifiedAccountHeadHandle
  localStateName(): string
  newLocalState(): unknown
  openLocalState(sealedBase64: string): unknown
  sealLocalState(stateJson: string): string
  advanceLocalState(stateJson: string, verified: VerifiedAccountHeadHandle, atMs: number): unknown
  reanchoredLocalState(stateJson: string, recordJson: string, verified: VerifiedAccountHeadHandle): unknown
  forgottenLocalState(stateJson: string, atMs: number): unknown
  free(): void
}

/** OPAQUE sign-in in progress (Rust `kutup_crypto::opaque`); the state stays in WASM. */
export interface OpaqueLoginHandle {
  readonly request: string
  finish(responseBase64: string): string
  openMasterKey(envelope: string, keyBinding: string): string
  /** Wipes the state and the export key. */
  close(): void
  free(): void
}

/** OPAQUE registration in progress (Rust `kutup_crypto::opaque`); the state stays in WASM. */
export interface OpaqueRegistrationHandle {
  readonly request: string
  finish(responseBase64: string): string
  sealMasterKey(masterKeyBase64: string, keyBinding: string): string
  /** Wipes the state and the export key. */
  close(): void
  free(): void
}

export async function getCryptoWasm(): Promise<CryptoWasmModule> {
  if (!modulePromise) {
    // A fetch cut off by a network change is tried again, the script under
    // a fresh URL (the browser remembers a failed module); a failure is not
    // kept, so a later call starts over.
    modulePromise = retryLoad(async (n) => {
      const url = n === 0 ? MODULE_URL : freshUrl(MODULE_URL, n)
      const module = (await import(/* @vite-ignore */ url)) as CryptoWasmModule
      await module.default({ module_or_path: WASM_URL })
      return module
    })
    modulePromise.catch(() => {
      modulePromise = null
    })
  }
  return modulePromise
}
