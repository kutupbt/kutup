// One loader for Kutup-owned browser cryptography. Feature adapters expose
// typed operations; this module owns only generated-module initialization.

// Epoch 2 escapes the pre-fix immutable browser cache used by the original
// stable URLs. Future deployments rely on mandatory revalidation and do not
// need an epoch bump unless the public path itself changes again.
const RUNTIME_CACHE_EPOCH = '2'
const MODULE_URL = `/crypto-wasm/kutup_crypto_wasm.js?runtime=${RUNTIME_CACHE_EPOCH}`
const WASM_URL = `/crypto-wasm/kutup_crypto_wasm_bg.wasm?runtime=${RUNTIME_CACHE_EPOCH}`

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
  deriveAccountProtectionKeys(
    password: string,
    saltBase64: string,
    suite: number,
    memoryKib: number,
    iterations: number,
    parallelism: number,
  ): { keyEncryptionKey: string; loginKey: string }
  deriveRecoveryAuthProof(recoveryEntropyBase64: string, loginEmail: string): string
  deriveAccountIdentityKeys(masterKeyBase64: string): {
    authorityPublicKey: string
    authorityKeyId: string
    incarnationId: string
    driveHpkePublicKey: string
    driveHpkePrivateKey: string
    driveSigningPublicKey: string
  }
  sealAccountEnvelope(
    plaintextBase64: string,
    keyBase64: string,
    purpose: number,
    loginEmail: string,
  ): string
  openAccountEnvelope(
    envelopeBase64: string,
    keyBase64: string,
    expectedPurpose: number,
    loginEmail: string,
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
    senderDeviceId: string,
    sequence: string,
  ): string
  collabFrameSigningBytes(frameBase64: string): string
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
    senderDeviceId: string
    sequence: string
    plaintext: string
  }
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
    senderAccount: string,
    senderIncarnationId: string,
    recipientAccount: string,
    recipientIncarnationId: string,
  ): string
  openNamedShareEnvelope(
    envelopeBase64: string,
    senderSigningPublicKeyBase64: string,
    recipientHpkePrivateKeyBase64: string,
    expectedCollectionId: string,
    expectedEpoch: number,
    expectedSenderAccount: string,
    expectedSenderIncarnationId: string,
    expectedRecipientAccount: string,
    expectedRecipientIncarnationId: string,
  ): string
  sealFileShareEnvelope(
    fileKeyBase64: string,
    senderMasterKeyBase64: string,
    recipientHpkePublicKeyBase64: string,
    fileId: string,
    generation: number,
    senderAccount: string,
    senderIncarnationId: string,
    recipientAccount: string,
    recipientIncarnationId: string,
  ): string
  openFileShareEnvelope(
    envelopeBase64: string,
    senderSigningPublicKeyBase64: string,
    recipientHpkePrivateKeyBase64: string,
    expectedFileId: string,
    expectedGeneration: number,
    expectedSenderAccount: string,
    expectedSenderIncarnationId: string,
    expectedRecipientAccount: string,
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
  ContentHasher: new () => { update(chunk: Uint8Array): void; finish(): string; free(): void }
  liveLocationOpen(keyBase64: string, streamIdHex: string, envelopeBase64: string): LiveLocationUpdate
  sealProfileKeyEnvelope(
    profileKeyBase64: string,
    senderMasterKeyBase64: string,
    recipientHpkePublicKeyBase64: string,
    senderAccount: string,
    senderIncarnationId: string,
    recipientAccount: string,
    recipientIncarnationId: string,
  ): string
  openProfileKeyEnvelope(
    envelopeBase64: string,
    senderSigningPublicKeyBase64: string,
    recipientHpkePrivateKeyBase64: string,
    expectedSenderAccount: string,
    expectedSenderIncarnationId: string,
    expectedRecipientAccount: string,
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

export async function getCryptoWasm(): Promise<CryptoWasmModule> {
  if (!modulePromise) {
    modulePromise = (async () => {
      const module = (await import(/* @vite-ignore */ MODULE_URL)) as CryptoWasmModule
      await module.default({ module_or_path: WASM_URL })
      return module
    })()
  }
  return modulePromise
}
