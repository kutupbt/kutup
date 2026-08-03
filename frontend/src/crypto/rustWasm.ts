// One loader for Kutup-owned browser cryptography. Feature adapters expose
// typed operations; this module owns only generated-module initialization.

const MODULE_URL = '/crypto-wasm/kutup_crypto_wasm.js'

export interface CryptoWasmModule {
  default(): Promise<unknown>
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
    collectionKeyBase64: string,
    fileId: string,
    collectionId: string,
    assetId: string,
    epoch: number,
  ): string
  openWhiteboardAsset(
    envelopeBase64: string,
    collectionKeyBase64: string,
    expectedFileId: string,
    expectedCollectionId: string,
    expectedAssetId: string,
    expectedEpoch: number,
  ): string
  prepareDriveFileBlob(
    fileKeyBase64: string,
    fileId: string,
    collectionId: string,
    epoch: number,
  ): { objectHeader: string; streamKey: string }
  openDriveFileBlobHeader(
    objectHeaderBase64: string,
    fileKeyBase64: string,
    expectedFileId: string,
    expectedCollectionId: string,
    expectedEpoch: number,
  ): string
  sealCollabFrame(
    plaintextBase64: string,
    collectionKeyBase64: string,
    kind: number,
    keyEpoch: number,
    docKeyId: number,
    fileId: string,
    collectionId: string,
    senderDeviceId: string,
    sequence: string,
  ): string
  collabFrameSigningBytes(frameBase64: string): string
  attachCollabFrameSignature(frameBase64: string, signatureBase64: string): string
  openCollabFrame(
    frameBase64: string,
    collectionKeyBase64: string,
    expectedFileId: string,
    expectedCollectionId: string,
    expectedKeyEpoch: number,
  ): {
    kind: number
    keyEpoch: number
    docKeyId: number
    senderDeviceId: string
    sequence: string
    plaintext: string
  }
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
}

let modulePromise: Promise<CryptoWasmModule> | null = null

export async function getCryptoWasm(): Promise<CryptoWasmModule> {
  if (!modulePromise) {
    modulePromise = (async () => {
      const module = (await import(/* @vite-ignore */ MODULE_URL)) as CryptoWasmModule
      await module.default()
      return module
    })()
  }
  return modulePromise
}
