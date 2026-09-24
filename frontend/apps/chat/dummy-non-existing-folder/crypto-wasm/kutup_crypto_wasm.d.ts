/* tslint:disable */
/* eslint-disable */

export function attachCollabFrameSignature(frame_base64: string, signature_base64: string): string;

export function chatAttachmentLedgerEnvelopeDigest(envelope_base64: string): string;

/**
 * The file-key generation a frame names in its public header, so a
 * client replaying older log frames can pick that generation's key.
 * Opening still checks it (`openCollabFrame` with the same generation).
 */
export function collabFrameKeyGeneration(frame_base64: string): number;

export function collabFrameSigningBytes(frame_base64: string): string;

export function createChatBackupSignerAuthorization(master_key_base64: string, backup_root_base64: string, backup_incarnation_id: string, created_at_unix: bigint): any;

export function createCollectionEpochStatement(master_key_base64: string, collection_key_base64: string, collection_id: string, owner_user_id: string, epoch: number, previous_statement_hash: string): string;

export function decodeChatAttachmentLedgerEntry(entry_base64: string): any;

/**
 * Authenticate canonical archive structure before any record reaches the
 * isolated display-history store.
 */
export function decodeChatBackupPlaintext(plaintext_base64: string, purpose: number): any;

/**
 * Derive the purpose-separated V1 account identity. The Drive private key is
 * returned only so the existing account-private wrap can be created during
 * the pre-tag format cutover; it is never sent in plaintext to the server.
 */
export function deriveAccountIdentityKeys(master_key_base64: string): any;

/**
 * Run the one expensive V1 Argon2id derivation and expand its two
 * purpose-separated account subkeys.
 */
export function deriveAccountProtectionKeys(password: string, salt_base64: string, suite: number, memory_kib: number, iterations: number, parallelism: number): any;

export function deriveChatAttachmentLedgerKey(master_key_base64: string): string;

/**
 * Derive the recovery authorization proof sent to the server. Raw recovery
 * entropy stays in the browser and continues to open only the recovery wrap.
 */
export function deriveRecoveryAuthProof(recovery_entropy_base64: string, login_email: string): string;

export function encodeChatAttachmentLedgerEntry(entry: any): string;

/**
 * Serialize archive plaintext through the canonical Rust protocol types.
 */
export function encodeChatBackupPlaintext(value: any, purpose: number): string;

/**
 * The file key of generation `wanted`, base64, from the current key of
 * `generation` and the file's history (`chain`: the listing's
 * `keyHistory`, generations 2 to `generation` in order).
 */
export function fileKeyAt(current_key_base64: string, file_id: string, generation: number, chain: any, wanted: number): string;

export function inspectChatAttachmentLedgerEnvelope(envelope_base64: string): any;

/**
 * Open one account secret only when its purpose and login-email binding match.
 */
export function openAccountEnvelope(envelope_base64: string, key_base64: string, expected_purpose: number, login_email: string): string;

export function openChatAttachmentLedger(envelope_base64: string, ledger_key_base64: string, expected_account_incarnation_id: string, expected_entity_id: string, expected_revision: bigint, expected_previous_envelope_digest: string): string;

export function openChatBackupMediaHeader(header_base64: string, backup_root_base64: string, expected_account_incarnation_id: string, expected_backup_incarnation_id: string, expected_media_id: string): any;

export function openChatBackupObject(object_base64: string, backup_root_base64: string, account_incarnation_id: string, backup_incarnation_id: string, purpose: number, object_id: string, source_device_id: number, device_sequence: bigint, previous_segment_digest: string): string;

export function openChatMediaObjectHeader(object_header_base64: string, attachment_key_base64: string, expected_attachment_id: string): string;

export function openCollabFrame(frame_base64: string, file_key_base64: string, expected_file_id: string, expected_key_generation: number): any;

export function openDriveEnvelope(envelope_base64: string, root_key_base64: string, expected_purpose: number, expected_epoch: number, expected_revision: bigint, expected_object_id: string, expected_parent_id: string): string;

export function openDriveFileBlobHeader(object_header_base64: string, file_key_base64: string, expected_file_id: string, expected_generation: number): string;

/**
 * Open an envelope sealed by `sealLocalState` (or the Rust equivalent);
 * fails closed on a wrong key, purpose or profile.
 */
export function openLocalState(envelope_base64: string, key_base64: string, purpose: number, profile: string): string;

export function openNamedShareEnvelope(envelope_base64: string, sender_signing_public_key_base64: string, recipient_hpke_private_key_base64: string, expected_collection_id: string, expected_epoch: number, expected_sender_account: string, expected_sender_incarnation_id: string, expected_recipient_account: string, expected_recipient_incarnation_id: string): string;

/**
 * Open a thumbnail of exactly this file, variant and key generation.
 */
export function openThumbnail(envelope_base64: string, variant: string, file_key_base64: string, expected_file_id: string, expected_generation: number): any;

export function openWhiteboardAsset(envelope_base64: string, file_key_base64: string, expected_file_id: string, expected_asset_id: string, expected_generation: number): string;

export function prepareChatBackupMedia(backup_root_base64: string, account_incarnation_id: string, backup_incarnation_id: string, stable_source_binding: string, source_ciphertext_bytes: bigint): any;

/**
 * Return the canonical Chat-media header and its purpose-derived stream key.
 * JS owns only bounded secretstream I/O, exactly as for Drive file blobs.
 */
export function prepareChatMediaObject(attachment_key_base64: string, attachment_id: string): any;

export function prepareDriveFileBlob(file_key_base64: string, file_id: string, generation: number): any;

/**
 * Seal one account secret into the canonical, suite-bearing V1 envelope.
 */
export function sealAccountEnvelope(plaintext_base64: string, key_base64: string, purpose: number, login_email: string): string;

export function sealChatAttachmentLedger(plaintext_base64: string, ledger_key_base64: string, account_incarnation_id: string, entity_id: string, revision: bigint, previous_envelope_digest: string): string;

export function sealChatBackupObject(plaintext_base64: string, backup_root_base64: string, account_incarnation_id: string, backup_incarnation_id: string, purpose: number, object_id: string, source_device_id: number, device_sequence: bigint, previous_segment_digest: string): string;

export function sealCollabFrame(plaintext_base64: string, file_key_base64: string, kind: number, key_generation: number, doc_key_id: number, file_id: string, sender_device_id: string, sequence: string): string;

export function sealDriveEnvelope(plaintext_base64: string, root_key_base64: string, purpose: number, epoch: number, revision: bigint, object_id: string, parent_id: string): string;

/**
 * Seal a session-fork payload (purpose 2) or a persisted web session (3).
 * Returns the canonical base64 envelope; the nonce is random.
 */
export function sealLocalState(plaintext_base64: string, key_base64: string, purpose: number, profile: string): string;

export function sealNamedShareEnvelope(collection_key_base64: string, sender_master_key_base64: string, recipient_hpke_public_key_base64: string, collection_id: string, epoch: number, sender_account: string, sender_incarnation_id: string, recipient_account: string, recipient_incarnation_id: string): string;

/**
 * The previous epoch's folder key sealed under this epoch's, for the
 * rotation record (docs/plans/drive-share-revocation.md).
 */
export function sealPreviousCollectionKey(previous_key_base64: string, key_base64: string, collection_id: string, owner_user_id: string, epoch: number): string;

/**
 * The file key of `generation − 1` sealed under that of `generation`, for a
 * re-key (docs/plans/drive-move.md).
 */
export function sealPreviousFileKey(previous_key_base64: string, key_base64: string, file_id: string, generation: number): string;

/**
 * Frame, pad and seal a thumbnail under the file key
 * (docs/plans/drive-thumbnails.md). `format`: 1 JPEG, 2 WebP, 3 PNG.
 */
export function sealThumbnail(image_base64: string, format: number, width: number, height: number, variant: string, file_key_base64: string, file_id: string, generation: number): string;

export function sealWhiteboardAsset(plaintext_base64: string, file_key_base64: string, file_id: string, asset_id: string, generation: number): string;

export function signChatBackupManifest(unsigned_manifest: any, backup_root_base64: string, account_incarnation_id: string, backup_incarnation_id: string): any;

/**
 * Every key of a folder, oldest first, as an array of base64 strings, from
 * its current key and complete signed history (`chain`: the
 * `GET /api/collections/{id}/epochs` array). Fails unless every statement
 * is the owner's, chained, and every key matches its commitment.
 */
export function unlockCollectionKeyring(current_key_base64: string, collection_id: string, owner_user_id: string, owner_authority_public_key_base64: string, chain: any): any;

/**
 * Verify the complete account-authority -> backup-signer -> manifest chain
 * against keys derived locally from the recovered account master key.
 */
export function verifyChatBackupMetadata(signer_authorization: any, manifest: any, master_key_base64: string, backup_root_base64: string, expected_backup_incarnation_id: string): any;

export function verifyCollectionEpochStatement(statement_base64: string, authority_public_key_base64: string, collection_key_base64: string, expected_collection_id: string, expected_owner_user_id: string, expected_epoch: number, expected_previous_statement_hash: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly attachCollabFrameSignature: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly chatAttachmentLedgerEnvelopeDigest: (a: number, b: number) => [number, number, number, number];
    readonly collabFrameKeyGeneration: (a: number, b: number) => [number, number, number];
    readonly collabFrameSigningBytes: (a: number, b: number) => [number, number, number, number];
    readonly createChatBackupSignerAuthorization: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint) => [number, number, number];
    readonly createCollectionEpochStatement: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number) => [number, number, number, number];
    readonly decodeChatAttachmentLedgerEntry: (a: number, b: number) => [number, number, number];
    readonly decodeChatBackupPlaintext: (a: number, b: number, c: number) => [number, number, number];
    readonly deriveAccountIdentityKeys: (a: number, b: number) => [number, number, number];
    readonly deriveAccountProtectionKeys: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly deriveChatAttachmentLedgerKey: (a: number, b: number) => [number, number, number, number];
    readonly deriveRecoveryAuthProof: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly encodeChatAttachmentLedgerEntry: (a: any) => [number, number, number, number];
    readonly encodeChatBackupPlaintext: (a: any, b: number) => [number, number, number, number];
    readonly fileKeyAt: (a: number, b: number, c: number, d: number, e: number, f: any, g: number) => [number, number, number, number];
    readonly inspectChatAttachmentLedgerEnvelope: (a: number, b: number) => [number, number, number];
    readonly openAccountEnvelope: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly openChatAttachmentLedger: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: bigint, j: number, k: number) => [number, number, number, number];
    readonly openChatBackupMediaHeader: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number];
    readonly openChatBackupObject: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: bigint, n: number, o: number) => [number, number, number, number];
    readonly openChatMediaObjectHeader: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly openCollabFrame: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number];
    readonly openDriveEnvelope: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: number, i: number, j: number, k: number) => [number, number, number, number];
    readonly openDriveFileBlobHeader: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly openLocalState: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly openNamedShareEnvelope: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number) => [number, number, number, number];
    readonly openThumbnail: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number, number];
    readonly openWhiteboardAsset: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number, number, number];
    readonly prepareChatBackupMedia: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: bigint) => [number, number, number];
    readonly prepareChatMediaObject: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly prepareDriveFileBlob: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly sealAccountEnvelope: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly sealChatAttachmentLedger: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: bigint, j: number, k: number) => [number, number, number, number];
    readonly sealChatBackupObject: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: bigint, n: number, o: number) => [number, number, number, number];
    readonly sealCollabFrame: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number) => [number, number, number, number];
    readonly sealDriveEnvelope: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: number, i: number, j: number, k: number) => [number, number, number, number];
    readonly sealLocalState: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly sealNamedShareEnvelope: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number) => [number, number, number, number];
    readonly sealPreviousCollectionKey: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number, number, number];
    readonly sealPreviousFileKey: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly sealThumbnail: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => [number, number, number, number];
    readonly sealWhiteboardAsset: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number, number, number];
    readonly signChatBackupManifest: (a: any, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number];
    readonly unlockCollectionKeyring: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: any) => [number, number, number];
    readonly verifyChatBackupMetadata: (a: any, b: any, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly verifyCollectionEpochStatement: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number) => [number, number, number, number];
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
