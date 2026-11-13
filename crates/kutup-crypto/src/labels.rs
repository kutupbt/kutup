//! Every label Kutup separates its keys, hashes, signatures and
//! associated data with (docs/plans/w6-key-hierarchy.md §3), in one place:
//! `kutup/<area>/<purpose>/v<N>\0`. An HKDF salt is always one of these (the
//! family), never none, empty or data; its info is the context (a purpose
//! label, the object's own header, or both). A unit test checks the grammar
//! and that no label repeats or is a prefix of another, and
//! `scripts/check-labels.sh` refuses a `"kutup/` or `"kutup-` literal
//! anywhere else in a crate's source unless `scripts/check-labels.allow`
//! names it as a non-label. Constructions a standard fixes (OHTTP, Web Push,
//! Signal's provisioning cipher) keep their own strings; wire tags a
//! standard's syntax carries are listed at the end, outside the grammar.
//! Labels the browser computes in TypeScript (marked so) are registered here
//! too, and the check refuses a `kutup/` literal in frontend sources that
//! isn't one of them, so no two languages pick the same label.

// --- 2fa-recovery-code -------------------------------------------------------

/// `kutup-server/src/two_factor.rs` (`MAC_LABEL`)
pub const TWO_FACTOR_RECOVERY_CODE_V1: &[u8] = b"kutup/2fa-recovery-code/v1\0";

// --- account-record ----------------------------------------------------------

/// `kutup-crypto/src/account_record.rs` (`COMMIT_INFO`): the key commitment
pub const ACCOUNT_RECORD_COMMIT_V1: &[u8] = b"kutup/account-record/commit/v1\0";
/// `kutup-crypto/src/account_record.rs` (`OBJECT_ID_INFO`): the key of hashed objects
pub const ACCOUNT_RECORD_OBJECT_ID_V1: &[u8] = b"kutup/account-record/object-id/v1\0";
/// `kutup-crypto/src/account_record.rs` (`KEY_INFO`)
pub const ACCOUNT_RECORD_KEY_V1: &[u8] = b"kutup/account-record/key/v1\0";
/// `kutup-crypto/src/account_record.rs` (`KEY_SALT`)
pub const ACCOUNT_RECORD_V1: &[u8] = b"kutup/account-record/v1\0";

// --- account-head ------------------------------------------------------------

/// `kutup-crypto/src/account_head.rs` (`ID_KEY_INFO`)
pub const ACCOUNT_HEAD_ID_KEY_V1: &[u8] = b"kutup/account-head/id-key/v1\0";
/// `kutup-crypto/src/account_head.rs` (`LOCAL_NAME_DOMAIN`)
pub const ACCOUNT_HEAD_LOCAL_NAME_V1: &[u8] = b"kutup/account-head/local-name/v1\0";
/// `kutup-crypto/src/account_head.rs` (`SCOPE_DOMAIN`)
pub const ACCOUNT_HEAD_SCOPE_V1: &[u8] = b"kutup/account-head/scope/v1\0";
/// `kutup-crypto/src/account_head.rs` (`SALT`)
pub const ACCOUNT_HEAD_V1: &[u8] = b"kutup/account-head/v1\0";
/// `kutup-crypto/src/account_head.rs` (`VALUE_ID_DOMAIN`)
pub const ACCOUNT_HEAD_VALUE_V1: &[u8] = b"kutup/account-head/value/v1\0";
/// `kutup-crypto/src/account_head.rs` (`WRITER_DOMAIN`)
pub const ACCOUNT_HEAD_WRITER_V1: &[u8] = b"kutup/account-head/writer/v1\0";

// --- account-identity --------------------------------------------------------

/// `kutup-chat-proto/src/account_identity.rs`
pub const ACCOUNT_IDENTITY_BINDING_V1: &[u8] = b"kutup/account-identity/binding/v1\0";
/// `kutup-crypto/src/identity.rs` (`DRIVE_HPKE_INFO`)
pub const ACCOUNT_IDENTITY_DRIVE_HPKE_XWING_V1: &[u8] =
    b"kutup/account-identity/drive-hpke-xwing/v1\0";
/// `kutup-crypto/src/identity.rs` (`DRIVE_SIGNING_INFO`)
pub const ACCOUNT_IDENTITY_DRIVE_SHARE_SIGNING_ED25519_V1: &[u8] =
    b"kutup/account-identity/drive-share-signing-ed25519/v1\0";
/// `kutup-crypto/src/identity.rs` (`SELF_AUTHORITY_INFO`)
pub const ACCOUNT_IDENTITY_SELF_AUTHORITY_V1: &[u8] = b"kutup/account-identity/self-authority/v1\0";
/// `kutup-crypto/src/identity.rs` (`ACCOUNT_IDENTITY_SALT`)
pub const ACCOUNT_IDENTITY_V1: &[u8] = b"kutup/account-identity/v1\0";

// --- account-recovery --------------------------------------------------------

/// `kutup-crypto/src/kdf.rs` (`RECOVERY_AUTH_SALT`)
pub const ACCOUNT_RECOVERY_AUTH_PROOF_V1: &[u8] = b"kutup/account-recovery/auth-proof/v1\0";

// --- account -----------------------------------------------------------------

/// `kutup-chat-proto/src/account_identity.rs`
pub const ACCOUNT_DEVICE_SESSION_V1: &[u8] = b"kutup/account/device-session/v1\0";
/// `kutup-server/src/account_ids.rs`
pub const ACCOUNT_ID_PROOF_V1: &[u8] = b"kutup/account/id-proof/v1\0";
/// `kutup-chat-proto/src/account_identity.rs`
pub const ACCOUNT_INCARNATION_V1: &[u8] = b"kutup/account/incarnation/v1\0";
/// `kutup-crypto/src/chat_group.rs`
pub const ACCOUNT_MANIFEST_V1: &[u8] = b"kutup/account/manifest/v1\0";
/// `kutup-chat-proto/src/account_identity.rs` (`DOMAIN`)
pub const ACCOUNT_MANIFEST_V3: &[u8] = b"kutup/account/manifest/v3\0";
/// `kutup-crypto/src/account_rename.rs` (`DOMAIN`)
pub const ACCOUNT_RENAME_V1: &[u8] = b"kutup/account/rename/v1\0";

// --- calls -------------------------------------------------------------------

/// `kutup-server/src/calls.rs` (`turn_credential`): keyed by the TURN secret,
/// the pseudonym a relay credential names instead of the account (was
/// `kutup-turn:` hashed with the secret)
pub const CALLS_TURN_PSEUDONYM_V1: &[u8] = b"kutup/calls/turn-pseudonym/v1\0";

// --- chat-attachment-ledger --------------------------------------------------

/// `frontend/packages/chat-core/src/attachment-ledger.ts` (`LOCAL_PIN_DOMAIN`, TypeScript)
pub const CHAT_ATTACHMENT_LEDGER_LOCAL_PIN_V1: &[u8] =
    b"kutup/chat-attachment-ledger/local-pin/v1\0";
/// `frontend/packages/chat-core/src/attachment-ledger.ts` (operation ids, TypeScript)
pub const CHAT_ATTACHMENT_LEDGER_OPERATION_V1: &[u8] =
    b"kutup/chat-attachment-ledger/operation/v1\0";

// --- chat-backup-media -------------------------------------------------------

/// `kutup-crypto/src/chat_backup_media_blocks.rs`
pub const CHAT_BACKUP_MEDIA_BLOCKS_BLOCK_KEY_V1: &[u8] =
    b"kutup/chat-backup-media/blocks/block-key/v1\0";
/// `kutup-crypto/src/chat_backup_media_blocks.rs`
pub const CHAT_BACKUP_MEDIA_BLOCKS_MANIFEST_KEY_V1: &[u8] =
    b"kutup/chat-backup-media/blocks/manifest-key/v1\0";
/// `kutup-crypto/src/chat_backup_media_blocks.rs`
pub const CHAT_BACKUP_MEDIA_BLOCKS_NONCE_KEY_V1: &[u8] =
    b"kutup/chat-backup-media/blocks/nonce-key/v1\0";

// --- chat-backup -------------------------------------------------------------

/// `kutup-crypto/src/chat_backup.rs` (`EVENT_SEGMENT_LABEL`)
pub const CHAT_BACKUP_EVENT_SEGMENT_KEY_V1: &[u8] = b"kutup/chat-backup/event-segment-key/v1\0";
/// `kutup-crypto/src/chat_backup.rs` (`MANIFEST_SIGNING_LABEL`)
pub const CHAT_BACKUP_MANIFEST_SIGNING_SEED_V1: &[u8] =
    b"kutup/chat-backup/manifest-signing-seed/v1\0";
/// `kutup-chat-proto/src/backup.rs` (`MANIFEST_DOMAIN`)
pub const CHAT_BACKUP_MANIFEST_V1: &[u8] = b"kutup/chat-backup/manifest/v1\0";
/// `kutup-crypto/src/chat_backup.rs` (`MEDIA_ENCRYPTION_LABEL`)
pub const CHAT_BACKUP_MEDIA_ENCRYPTION_ROOT_V1: &[u8] =
    b"kutup/chat-backup/media-encryption-root/v1\0";
/// `kutup-crypto/src/chat_backup.rs` (`MEDIA_ID_LABEL`)
pub const CHAT_BACKUP_MEDIA_ID_KEY_V1: &[u8] = b"kutup/chat-backup/media-id-key/v1\0";
/// `kutup-chat-proto/src/backup.rs`
pub const CHAT_BACKUP_MEDIA_REFERENCE_SET_V1: &[u8] = b"kutup/chat-backup/media-reference-set/v1\0";
/// `kutup-crypto/src/chat_backup.rs` (`MESSAGE_ARCHIVE_LABEL`)
pub const CHAT_BACKUP_MESSAGE_ARCHIVE_KEY_V1: &[u8] = b"kutup/chat-backup/message-archive-key/v1\0";
/// `kutup-chat-proto/src/backup.rs` (`SIGNER_AUTHORIZATION_DOMAIN`)
pub const CHAT_BACKUP_SIGNER_AUTHORIZATION_V1: &[u8] =
    b"kutup/chat-backup/signer-authorization/v1\0";
/// `kutup-crypto/src/chat_backup.rs` (`HKDF_SALT`)
pub const CHAT_BACKUP_V1: &[u8] = b"kutup/chat-backup/v1\0";

// --- chat-group-send ---------------------------------------------------------

/// `kutup-group-send/src/lib.rs` (`PARAMS_LABEL`): The label P0's master key is the hash of (§3.1).
pub const CHAT_GROUP_SEND_PARAMS_V1: &[u8] = b"kutup/chat-group-send/params/v1\0";
/// `kutup-group-send/src/lib.rs` (`SERVER_KEY_SEAL_DOMAIN`): The domain a stored server key is sealed under.
pub const CHAT_GROUP_SEND_SERVER_KEY_V1: &[u8] = b"kutup/chat-group-send/server-key/v1\0";

// --- chat-group --------------------------------------------------------------

/// `kutup-crypto/src/chat_group.rs` (`AVATAR_AAD`)
pub const CHAT_GROUP_AVATAR_V1: &[u8] = b"kutup/chat-group/avatar/v1\0";
/// `kutup-crypto/src/chat_group.rs` (`BINDING_DOMAIN`)
pub const CHAT_GROUP_BINDING_V1: &[u8] = b"kutup/chat-group/binding/v1\0";
/// `kutup-crypto/src/chat_group.rs` (`CHANGE_HASH_DOMAIN`)
pub const CHAT_GROUP_CHANGE_HASH_V1: &[u8] = b"kutup/chat-group/change-hash/v1\0";
/// `kutup-crypto/src/chat_group.rs` (`CHANGE_SIGNATURE_DOMAIN`)
pub const CHAT_GROUP_CHANGE_V1: &[u8] = b"kutup/chat-group/change/v1\0";
/// `kutup-crypto/src/chat_group.rs` (`CLAIM_DOMAIN`)
pub const CHAT_GROUP_CLAIM_V1: &[u8] = b"kutup/chat-group/claim/v1\0";
/// `kutup-chat-proto/src/group_route.rs` (`KEY_CONFIG_HASH_DOMAIN`)
pub const CHAT_GROUP_GATEWAY_KEY_CONFIG_HASH_V1: &[u8] =
    b"kutup/chat-group/gateway-key-config-hash/v1\0";
/// `kutup-chat-proto/src/group_route.rs` (`KEY_CONFIG_DOMAIN`)
pub const CHAT_GROUP_GATEWAY_KEY_CONFIG_V1: &[u8] = b"kutup/chat-group/gateway-key-config/v1\0";
/// `kutup-server/src/chat_groups/keys.rs` (`KEY_INFO`): The KEM is in the label:
pub const CHAT_GROUP_GATEWAY_KEY_XWING_V2: &[u8] = b"kutup/chat-group/gateway-key-xwing/v2\0";
/// `kutup-crypto/src/chat_group.rs` (`HOME_DOMAIN`)
pub const CHAT_GROUP_HOME_V1: &[u8] = b"kutup/chat-group/home/v1\0";
/// `kutup-crypto/src/chat_group.rs` (`ID_INFO`): v2:
pub const CHAT_GROUP_ID_V2: &[u8] = b"kutup/chat-group/id/v2\0";
/// `kutup-chat-proto/src/group_route.rs` (`LINK_PROOF_DOMAIN`)
pub const CHAT_GROUP_LINK_REQUEST_V1: &[u8] = b"kutup/chat-group/link-request/v1\0";
/// `kutup-chat-proto/src/group_route.rs` (`NOTARY_DOMAIN`)
pub const CHAT_GROUP_NOTARY_V1: &[u8] = b"kutup/chat-group/notary/v1\0";
/// `kutup-crypto/src/chat_group.rs` (`PSEUDONYM_SALT`)
pub const CHAT_GROUP_PSEUDONYM_V1: &[u8] = b"kutup/chat-group/pseudonym/v1\0";
/// `kutup-chat-proto/src/group_route.rs` (`BODY_HASH_DOMAIN`)
pub const CHAT_GROUP_REQUEST_BODY_V1: &[u8] = b"kutup/chat-group/request-body/v1\0";
/// `kutup-chat-proto/src/group_route.rs` (`REQUEST_DOMAIN`)
pub const CHAT_GROUP_REQUEST_V1: &[u8] = b"kutup/chat-group/request/v1\0";
/// `kutup-crypto/src/chat_group.rs` (`SEAL_DOMAIN`)
pub const CHAT_GROUP_SEALED_FIELD_V1: &[u8] = b"kutup/chat-group/sealed-field/v1\0";
/// `kutup-server/src/chat_groups/gateway.rs` (`SEEN_PSEUDONYM_DOMAIN`)
pub const CHAT_GROUP_SEEN_PSEUDONYM_V1: &[u8] = b"kutup/chat-group/seen-pseudonym/v1\0";
/// `kutup-crypto/src/chat_group.rs` (`STATE_HASH_DOMAIN`)
pub const CHAT_GROUP_STATE_HASH_V1: &[u8] = b"kutup/chat-group/state-hash/v1\0";
/// `kutup-crypto/src/chat_group.rs` (`STATE_KEY_INFO`): v2:
pub const CHAT_GROUP_STATE_KEY_V2: &[u8] = b"kutup/chat-group/state-key/v2\0";
/// `kutup-crypto/src/chat_group.rs` (`KDF_SALT`)
pub const CHAT_GROUP_V1: &[u8] = b"kutup/chat-group/v1\0";

// --- chat-media --------------------------------------------------------------

/// `kutup-crypto/src/chat_media_blocks.rs`
pub const CHAT_MEDIA_BLOCKS_BLOCK_KEY_V1: &[u8] = b"kutup/chat-media/blocks/block-key/v1\0";
/// `kutup-crypto/src/chat_media_blocks.rs`
pub const CHAT_MEDIA_BLOCKS_MANIFEST_KEY_V1: &[u8] = b"kutup/chat-media/blocks/manifest-key/v1\0";
/// `kutup-crypto/src/chat_media_blocks.rs`
pub const CHAT_MEDIA_BLOCKS_NONCE_KEY_V1: &[u8] = b"kutup/chat-media/blocks/nonce-key/v1\0";
/// `kutup-server/src/handlers/chat_media.rs`
pub const CHAT_MEDIA_DELIVERY_OFFER_DIGEST_V1: &[u8] =
    b"kutup/chat-media/delivery-offer-digest/v1\0";
/// `frontend/packages/chat-core/src/media.ts` (delivery operation ids, TypeScript)
pub const CHAT_MEDIA_DELIVERY_OPERATION_V1: &[u8] = b"kutup/chat-media/delivery-operation/v1\0";
/// `kutup-server/src/chat_media_federation.rs`
pub const CHAT_MEDIA_FEDERATION_ORIGIN_RATE_V1: &[u8] =
    b"kutup/chat-media/federation-origin-rate/v1\0";
/// `kutup-crypto/src/chat_media.rs` (`OBJECT_KEY_SALT`)
pub const CHAT_MEDIA_OBJECT_KEY_V1: &[u8] = b"kutup/chat-media/object-key/v1\0";
/// `kutup-server/src/handlers/chat_media.rs`
pub const CHAT_MEDIA_RECIPIENT_RATE_V1: &[u8] = b"kutup/chat-media/recipient-rate/v1\0";

// --- chat-store --------------------------------------------------------------

/// `kutup-crypto/src/chat_store.rs`: the family (HKDF salt) of the local store's keys
pub const CHAT_STORE_V1: &[u8] = b"kutup/chat-store/v1\0";
/// `kutup-crypto/src/chat_store.rs` (`INDEX_INFO`)
pub const CHAT_STORE_INDEX_V1: &[u8] = b"kutup/chat-store/index/v1\0";
/// `kutup-crypto/src/chat_store.rs` (`RECORD_AAD`)
pub const CHAT_STORE_RECORD_V1: &[u8] = b"kutup/chat-store/record/v1\0";
/// `kutup-crypto/src/chat_store.rs` (`VALUE_INFO`)
pub const CHAT_STORE_VALUE_V1: &[u8] = b"kutup/chat-store/value/v1\0";
/// `kutup-crypto/src/chat_store.rs` (`WRAP_INFO`)
pub const CHAT_STORE_WRAP_V1: &[u8] = b"kutup/chat-store/wrap/v1\0";

// --- chat --------------------------------------------------------------------

/// `kutup-crypto/src/chat_call_link.rs` (`SALT`)
pub const CHAT_CALL_LINK_V1: &[u8] = b"kutup/chat/call-link/v1\0";
/// `kutup-server/src/handlers/chat_identity.rs` (`CREDENTIAL_DOMAIN`)
pub const CHAT_DEVICE_CREDENTIAL_V1: &[u8] = b"kutup/chat/device-credential/v1\0";
/// `kutup-chat-proto/src/account_identity.rs`
pub const CHAT_KEYS_CHECK_V1: &[u8] = b"kutup/chat/keys-check/v1\0";
/// `kutup-crypto/src/chat_store.rs` (`LOCAL_INFO`)
pub const CHAT_LOCAL_V1: &[u8] = b"kutup/chat/local/v1\0";

// --- collab ------------------------------------------------------------------

/// `kutup-crypto/src/envelope.rs` (`KEY_DERIVATION_SALT`)
pub const COLLAB_FRAME_KEY_V1: &[u8] = b"kutup/collab/frame-key/v1\0";
/// `kutup-crypto/src/envelope.rs` (`SIGNATURE_DOMAIN`)
pub const COLLAB_FRAME_V3: &[u8] = b"kutup/collab/frame/v3\0";

// --- contact-control ---------------------------------------------------------

/// `kutup-chat-core/src/session.rs`
pub const CONTACT_CONTROL_V1: &[u8] = b"kutup/contact-control/v1\0";

// --- contact-summary ---------------------------------------------------------

/// `kutup-crypto/src/chat_group.rs`
pub const CONTACT_SUMMARY_V2: &[u8] = b"kutup/contact-summary/v2\0";

// --- device-registration -----------------------------------------------------

/// `kutup-crypto/src/chat_group.rs`
pub const DEVICE_REGISTRATION_V1: &[u8] = b"kutup/device-registration/v1\0";

// --- device-revocation -------------------------------------------------------

/// `kutup-crypto/src/chat_group.rs`
pub const DEVICE_REVOCATION_V1: &[u8] = b"kutup/device-revocation/v1\0";

// --- dkim-key ----------------------------------------------------------------

/// `kutup-crypto/src/dkim_key.rs` (`SEAL_DOMAIN`)
pub const DKIM_KEY_V1: &[u8] = b"kutup/dkim-key/v1\0";

// --- drive-envelope ----------------------------------------------------------

/// `kutup-crypto/src/drive_envelope.rs` (`KEY_DERIVATION_SALT`)
pub const DRIVE_ENVELOPE_KEY_V1: &[u8] = b"kutup/drive-envelope/key/v1\0";
/// `kutup-crypto/src/drive_envelope.rs` (`THUMBNAIL_BINDING_LABEL`)
pub const DRIVE_ENVELOPE_THUMBNAIL_V1: &[u8] = b"kutup/drive-envelope/thumbnail/v1\0";
/// `kutup-crypto/src/drive_envelope.rs` (`THUMBNAIL_REVISION_BINDING_LABEL`)
pub const DRIVE_ENVELOPE_THUMBNAIL_V2: &[u8] = b"kutup/drive-envelope/thumbnail/v2\0";
/// `kutup-crypto/src/drive_envelope.rs` (`WHITEBOARD_ASSET_BINDING_LABEL`)
pub const DRIVE_ENVELOPE_WHITEBOARD_ASSET_V2: &[u8] = b"kutup/drive-envelope/whiteboard-asset/v2\0";

// --- drive-object ------------------------------------------------------------

/// `kutup-crypto/src/drive_blocks.rs`
pub const DRIVE_OBJECT_BLOCKS_BLOCK_KEY_V1: &[u8] = b"kutup/drive-object/blocks/block-key/v1\0";
/// `kutup-crypto/src/drive_blocks.rs`
pub const DRIVE_OBJECT_BLOCKS_MANIFEST_KEY_V1: &[u8] =
    b"kutup/drive-object/blocks/manifest-key/v1\0";
/// `kutup-crypto/src/drive_blocks.rs`
pub const DRIVE_OBJECT_BLOCKS_NONCE_KEY_V1: &[u8] = b"kutup/drive-object/blocks/nonce-key/v1\0";
/// `kutup-crypto/src/drive_object.rs` (`FILE_BLOB_KEY_SALT`)
pub const DRIVE_OBJECT_FILE_BLOB_KEY_V1: &[u8] = b"kutup/drive-object/file-blob-key/v1\0";

// --- drive -------------------------------------------------------------------

/// `kutup-crypto/src/drive_names.rs`: the family (HKDF salt) of the name hash keys
pub const DRIVE_NAMES_V1: &[u8] = b"kutup/drive/names/v1\0";
/// `kutup-crypto/src/drive_blocks.rs`
pub const DRIVE_BLOCK_MANIFEST_V1: &[u8] = b"kutup/drive/block-manifest/v1\0";
/// `kutup-crypto/src/collection_epoch.rs` (`RECORD_HASH_DOMAIN`)
pub const DRIVE_COLLECTION_EPOCH_RECORD_HASH_V1: &[u8] =
    b"kutup/drive/collection-epoch-record-hash/v1\0";
/// `kutup-crypto/src/chat_group.rs`
pub const DRIVE_COLLECTION_KEY_COMMITMENT_V1: &[u8] = b"kutup/drive/collection-key-commitment/v1\0";
/// `kutup-crypto/src/named_share.rs` (`FILE_HPKE_INFO`)
pub const DRIVE_FILE_SHARE_HPKE_V1: &[u8] = b"kutup/drive/file-share-hpke/v1\0";
/// `kutup-crypto/src/drive_names.rs` (`HASH_KEY_INFO`)
pub const DRIVE_FOLDER_HASH_KEY_V1: &[u8] = b"kutup/drive/folder-hash-key/v1\0";
/// `kutup-crypto/src/chat_group.rs`
pub const DRIVE_KEY_BINDING_V2: &[u8] = b"kutup/drive/key-binding/v2\0";
/// `kutup-crypto/src/named_share.rs` (`HPKE_INFO`)
pub const DRIVE_NAMED_SHARE_HPKE_V1: &[u8] = b"kutup/drive/named-share-hpke/v1\0";
/// `kutup-crypto/src/profile_key_share.rs` (`HPKE_INFO`)
pub const DRIVE_PROFILE_KEY_HPKE_V1: &[u8] = b"kutup/drive/profile-key-hpke/v1\0";
/// `kutup-crypto/src/drive_names.rs` (`TOP_LEVEL_INFO`)
pub const DRIVE_TOP_LEVEL_NAMES_V1: &[u8] = b"kutup/drive/top-level-names/v1\0";

// --- fake-account ------------------------------------------------------------

/// `kutup-server/src/handlers/auth.rs`
pub const FAKE_ACCOUNT_V1: &[u8] = b"kutup/fake-account/v1\0";

// --- group-endorsement-upload ------------------------------------------------

/// `kutup-server/src/chat_groups/gateway.rs`
pub const GROUP_ENDORSEMENT_UPLOAD_V1: &[u8] = b"kutup/group-endorsement-upload/v1\0";

// --- group-send-issue --------------------------------------------------------

/// `kutup-server/src/chat_group_send.rs`
pub const GROUP_SEND_ISSUE_V1: &[u8] = b"kutup/group-send-issue/v1\0";

// --- known-client ------------------------------------------------------------

/// `kutup-server/src/auth_check.rs`
pub const KNOWN_CLIENT_V1: &[u8] = b"kutup/known-client/v1\0";

// --- mail-address-key --------------------------------------------------------

/// `kutup-crypto/src/mail_key.rs` (`PRIVATE_KEY_DOMAIN`)
pub const MAIL_ADDRESS_KEY_V1: &[u8] = b"kutup/mail-address-key/v1\0";

// --- mail-forwarding ---------------------------------------------------------

/// `kutup-server/src/mail/forwarding.rs` (`MARKER_DOMAIN`)
pub const MAIL_FORWARDING_MARKER_V1: &[u8] = b"kutup/mail-forwarding/marker/v1\0";
/// `kutup-server/src/mail/forwarding_code.rs` (`code_key`; was `kutup mail forwarding code v1`)
pub const MAIL_FORWARDING_CODE_KEY_V1: &[u8] = b"kutup/mail-forwarding/code-key/v1\0";
/// `kutup-server/src/mail/forwarding_code.rs` (`stop_token`; was `kutup mail forwarding stop v1`)
pub const MAIL_FORWARDING_STOP_V1: &[u8] = b"kutup/mail-forwarding/stop/v1\0";
/// `kutup-crypto/src/mail_forwarding.rs` (`SEAL_DOMAIN`)
pub const MAIL_FORWARDING_PROXY_PARAMETER_V1: &[u8] = b"kutup/mail-forwarding/proxy-parameter/v1\0";
/// `kutup-server/src/mail/forwarding.rs` (`RETURN_PATH_DOMAIN`)
pub const MAIL_FORWARDING_RETURN_PATH_V1: &[u8] = b"kutup/mail-forwarding/return-path/v1\0";

// --- mail-group-key-share ----------------------------------------------------

/// `kutup-crypto/src/chat_group.rs`
pub const MAIL_GROUP_KEY_SHARE_V2: &[u8] = b"kutup/mail-group-key-share/v2\0";

// --- mail-group-signer-handover ----------------------------------------------

/// `kutup-crypto/src/mail_group.rs` (`HANDOVER_DOMAIN`)
pub const MAIL_GROUP_SIGNER_HANDOVER_V1: &[u8] = b"kutup/mail-group-signer-handover/v1\0";

// --- mail-group-signing-share ------------------------------------------------

/// `kutup-crypto/src/mail_group.rs` (`SIGNING_SHARE_DOMAIN`)
pub const MAIL_GROUP_SIGNING_SHARE_V2: &[u8] = b"kutup/mail-group-signing-share/v2\0";

// --- mail-key-list -----------------------------------------------------------

/// `kutup-crypto/src/chat_group.rs`
pub const MAIL_KEY_LIST_V1: &[u8] = b"kutup/mail-key-list/v1\0";

// --- mail-search -------------------------------------------------------------

/// `kutup-crypto/src/mail_search.rs` (`LOCATOR_KEY_INFO`)
pub const MAIL_SEARCH_LOCATOR_KEY_V1: &[u8] = b"kutup/mail-search/locator-key/v1\0";
/// `kutup-crypto/src/mail_search.rs` (`NAME_KEY_INFO`)
pub const MAIL_SEARCH_NAME_KEY_V1: &[u8] = b"kutup/mail-search/name-key/v1\0";
/// `kutup-crypto/src/mail_search.rs` (`RECORD_KEY_INFO`)
pub const MAIL_SEARCH_RECORD_KEY_V1: &[u8] = b"kutup/mail-search/record-key/v1\0";
/// `kutup-crypto/src/mail_search.rs` (`AAD_DOMAIN`)
pub const MAIL_SEARCH_RECORD_V1: &[u8] = b"kutup/mail-search/record/v1\0";
/// `kutup-crypto/src/mail_search.rs` (`STORE_SALT`)
pub const MAIL_SEARCH_V1: &[u8] = b"kutup/mail-search/v1\0";
/// `kutup-crypto/src/mail_search.rs` (`ACCOUNT_SALT`)
pub const MAIL_SEARCH_WRAP_V1: &[u8] = b"kutup/mail-search/wrap/v1\0";

// --- manifest-pins -----------------------------------------------------------

/// `kutup-crypto/src/local_state.rs` (`manifest_pins_key`, the HKDF info)
pub const MANIFEST_PINS_KEY_V1: &[u8] = b"kutup/manifest-pins/key/v1\0";
/// `kutup-crypto/src/local_state.rs` (`manifest_pins_key`, the HKDF salt)
pub const MANIFEST_PINS_V1: &[u8] = b"kutup/manifest-pins/v1\0";

// --- multi-ip-bytes ----------------------------------------------------------

/// `kutup-server/src/handlers/chat.rs`
pub const MULTI_IP_BYTES_V1: &[u8] = b"kutup/multi-ip-bytes/v1\0";

// --- multi-origin ------------------------------------------------------------

/// `kutup-server/src/handlers/chat_multi.rs`
pub const MULTI_ORIGIN_V1: &[u8] = b"kutup/multi-origin/v1\0";

// --- multi-recipient ---------------------------------------------------------

/// `kutup-server/src/handlers/chat_multi.rs`
pub const MULTI_RECIPIENT_V1: &[u8] = b"kutup/multi-recipient/v1\0";

// --- multi-token -------------------------------------------------------------

/// `kutup-server/src/handlers/chat_multi.rs`
pub const MULTI_TOKEN_V1: &[u8] = b"kutup/multi-token/v1\0";

// --- opaque ------------------------------------------------------------------

/// `kutup-crypto/src/opaque.rs` (`CREDENTIAL_PREFIX`)
pub const OPAQUE_CREDENTIAL_V1: &[u8] = b"kutup/opaque/credential/v1\0";
/// `kutup-crypto/src/opaque.rs` (`EXPORT_SALT`)
pub const OPAQUE_EXPORT_V1: &[u8] = b"kutup/opaque/export/v1\0";
/// `kutup-crypto/src/opaque_login_state.rs` (`LABEL`)
pub const OPAQUE_LOGIN_STATE_V1: &[u8] = b"kutup/opaque/login-state/v1\0";
/// `kutup-crypto/src/opaque.rs` (`MASTER_KEY_KEK_INFO`)
pub const OPAQUE_MASTER_KEY_KEK_V1: &[u8] = b"kutup/opaque/master-key-kek/v1\0";
/// `kutup-crypto/src/opaque.rs` (`SETUP_AAD`)
pub const OPAQUE_SETUP_V1: &[u8] = b"kutup/opaque/setup/v1\0";
/// `kutup-crypto/src/opaque.rs` (`CONTEXT`): Bound into every sign-in's transcript.
pub const OPAQUE_V1: &[u8] = b"kutup/opaque/v1\0";

// --- org -----------------------------------------------------------------------

/// `kutup-crypto/src/organization.rs` (`access_request`, signature context)
pub const ORG_ACCESS_REQUEST_V1: &[u8] = b"kutup/org/access-request/v1\0";
/// `kutup-crypto/src/organization.rs` (`KeyCertificateV1`, signature context)
pub const ORG_KEY_CERTIFICATE_V1: &[u8] = b"kutup/org/key-certificate/v1\0";
/// `kutup-crypto/src/organization.rs` (`key_id`, hash domain)
pub const ORG_KEY_ID_V1: &[u8] = b"kutup/org/key-id/v1\0";
/// `kutup-crypto/src/organization.rs` (`KeyShareV1`, signature context)
pub const ORG_KEY_SHARE_SIGNATURE_V1: &[u8] = b"kutup/org/key-share-signature/v1\0";
/// `kutup-crypto/src/organization.rs` (`KeyShareV1`, HPKE info: the seed to
/// an admin's Drive X-Wing key, apart from Drive's share labels)
pub const ORG_KEY_SHARE_V1: &[u8] = b"kutup/org/key-share/v1\0";
/// `kutup-crypto/src/organization.rs` (`EscrowV1`, HPKE info)
pub const ORG_MEMBER_ESCROW_V1: &[u8] = b"kutup/org/member-escrow/v1\0";

// --- pass-vault-secret -------------------------------------------------------

/// `kutup-crypto/src/pass_vault.rs`
pub const PASS_VAULT_SECRET_V1: &[u8] = b"kutup/pass-vault-secret/v1\0";
/// `kutup-crypto/src/pass_vault.rs` (`DOMAIN`)
pub const PASS_VAULT_SECRET_V2: &[u8] = b"kutup/pass-vault-secret/v2\0";

// --- photos-library ----------------------------------------------------------

// --- private-ciphertext-cache ------------------------------------------------

/// `frontend/packages/files/src/mediaCache/types.ts` (account scope, TypeScript)
pub const PRIVATE_CIPHERTEXT_CACHE_ACCOUNT_V1: &[u8] =
    b"kutup/private-ciphertext-cache/account/v1\0";
/// `frontend/packages/files/src/mediaCache/types.ts` (binding key, TypeScript)
pub const PRIVATE_CIPHERTEXT_CACHE_BINDING_V1: &[u8] =
    b"kutup/private-ciphertext-cache/binding/v1\0";

// --- profile-envelope --------------------------------------------------------

/// `kutup-crypto/src/chat_profile.rs` (`ENVELOPE_KEY_SALT`)
pub const PROFILE_ENVELOPE_KEY_V1: &[u8] = b"kutup/profile-envelope/key/v1\0";

// --- registration-code -------------------------------------------------------

/// `kutup-server/src/registration.rs`
pub const REGISTRATION_CODE_V1: &[u8] = b"kutup/registration-code/v1\0";

// --- sealed-delivery-capability ----------------------------------------------

/// `kutup-crypto/src/chat_profile.rs` (`DELIVERY_CAPABILITY_CONTEXT`)
pub const SEALED_DELIVERY_CAPABILITY_V1: &[u8] = b"kutup/sealed-delivery-capability/v1\0";

// --- sealed-origin-rate ------------------------------------------------------

/// `kutup-server/src/chat_federation.rs`
pub const SEALED_ORIGIN_RATE_V1: &[u8] = b"kutup/sealed-origin-rate/v1\0";

// --- sealed-recipient-rate ---------------------------------------------------

/// `kutup-server/src/handlers/chat.rs`
pub const SEALED_RECIPIENT_RATE_V1: &[u8] = b"kutup/sealed-recipient-rate/v1\0";

// --- server ------------------------------------------------------------------

/// `kutup-server/src/audit_log.rs` (`CHAIN_DOMAIN`)
pub const SERVER_ADMIN_AUDIT_CHAIN_V1: &[u8] = b"kutup/server/admin-audit-chain/v1\0";
/// `kutup-crypto/src/server_data.rs` (`SALT`)
pub const SERVER_DATA_V1: &[u8] = b"kutup/server/data/v1\0";
/// `kutup-crypto/src/server_data.rs` (`KEK_INFO`)
pub const SERVER_DATA_KEK_V1: &[u8] = b"kutup/server/data-kek/v1\0";
/// `kutup-crypto/src/server_data.rs` (`WRAP_AAD`)
pub const SERVER_DATA_KEY_WRAP_V1: &[u8] = b"kutup/server/data-key-wrap/v1\0";
/// `kutup-crypto/src/server_data.rs` (`FIELD_KEY_INFO`)
pub const SERVER_DATA_FIELD_KEY_V1: &[u8] = b"kutup/server/data-field-key/v1\0";
/// `kutup-crypto/src/server_data.rs` (`FIELD_AAD`)
pub const SERVER_DATA_FIELD_V1: &[u8] = b"kutup/server/data-field/v1\0";
/// `kutup-crypto/src/server_data.rs` (`SUBJECT_INFO`)
pub const SERVER_DESTRUCTION_SUBJECT_V1: &[u8] = b"kutup/server/destruction-subject/v1\0";

// --- session-version ---------------------------------------------------------

/// `kutup-server/src/middleware.rs`
pub const SESSION_VERSION_V1: &[u8] = b"kutup/session-version/v1\0";

// --- yjs-seed ----------------------------------------------------------------

/// `kutup-crypto/src/yjs_seed.rs` (`LABEL`)
pub const YJS_SEED_V1: &[u8] = b"kutup/yjs-seed/v1\0";

// --- chat-profile ------------------------------------------------------------

/// `kutup-crypto/src/chat_profile.rs`: the family (HKDF salt) of the profile keys
pub const CHAT_PROFILE_V1: &[u8] = b"kutup/chat-profile/v1\0";
/// `kutup-crypto/src/chat_profile.rs` (was `kutup-chat-profile-access-v1`)
pub const CHAT_PROFILE_ACCESS_V1: &[u8] = b"kutup/chat-profile/access/v1\0";
/// `kutup-chat-core/src/engine.rs` (was `kutup-profile-key-update-v1`)
pub const CHAT_PROFILE_KEY_UPDATE_V1: &[u8] = b"kutup/chat-profile/key-update/v1\0";
/// `kutup-crypto/src/chat_profile.rs` (was `kutup-chat-profile-version-v1`)
pub const CHAT_PROFILE_VERSION_V1: &[u8] = b"kutup/chat-profile/version/v1\0";

// --- drive-federation --------------------------------------------------------

/// `kutup-server/src/drive_federation.rs` (was `kutup-drive-federation-operation-v1`)
pub const DRIVE_FEDERATION_OPERATION_V1: &[u8] = b"kutup/drive-federation/operation/v1\0";

// --- federation --------------------------------------------------------------

/// `kutup-federation-proto/src/discovery.rs` (was `kutup-federation-discovery-v2`)
pub const FEDERATION_DISCOVERY_V2: &[u8] = b"kutup/federation/discovery/v2\0";
/// `kutup-federation-proto/src/policy.rs` (was `kutup-federated-feature-policy-envelope-hash-v1`)
pub const FEDERATION_FEATURE_POLICY_ENVELOPE_HASH_V1: &[u8] =
    b"kutup/federation/feature-policy-envelope-hash/v1\0";
/// `kutup-federation-proto/src/policy.rs` (was `kutup-federated-feature-policy-envelope-v1`)
pub const FEDERATION_FEATURE_POLICY_ENVELOPE_V1: &[u8] =
    b"kutup/federation/feature-policy-envelope/v1\0";
/// `kutup-federation-proto/src/identity.rs` (was `kutup-federation-identity-document-hash-v1`)
pub const FEDERATION_IDENTITY_DOCUMENT_HASH_V1: &[u8] =
    b"kutup/federation/identity-document-hash/v1\0";
/// `kutup-federation-proto/src/identity.rs` (was `kutup-federation-identity-document-v1`)
pub const FEDERATION_IDENTITY_DOCUMENT_V1: &[u8] = b"kutup/federation/identity-document/v1\0";
/// `kutup-server/src/federation/replay.rs` (was `kutup-federation-replay-v1`)
pub const FEDERATION_REPLAY_V1: &[u8] = b"kutup/federation/replay/v1\0";
/// `kutup-federation-proto/src/http_signatures.rs` (was `kutup-federation-request-replay-hash-v1`)
pub const FEDERATION_REQUEST_REPLAY_HASH_V1: &[u8] = b"kutup/federation/request-replay-hash/v1\0";
// --- wire tags -----------------------------------------------------------------
//
// Not labels in the grammar: a standard's syntax carries them, so they hold
// no NUL. Listed here so the registry stays the one index.

/// `kutup-federation-proto` (`FEDERATION_SIGNATURE_TAG`): the RFC 9421
/// `tag` parameter of every federation signature
pub const FEDERATION_SIGNATURE_TAG: &str = "kutup-federation-v2";

/// Every label, for the registry's own checks.
pub const ALL: [&[u8]; 170] = [
    ORG_ACCESS_REQUEST_V1,
    ORG_KEY_CERTIFICATE_V1,
    ORG_KEY_ID_V1,
    ORG_KEY_SHARE_SIGNATURE_V1,
    ORG_KEY_SHARE_V1,
    ORG_MEMBER_ESCROW_V1,
    MANIFEST_PINS_KEY_V1,
    MANIFEST_PINS_V1,
    MAIL_FORWARDING_CODE_KEY_V1,
    MAIL_FORWARDING_STOP_V1,
    CALLS_TURN_PSEUDONYM_V1,
    CHAT_ATTACHMENT_LEDGER_LOCAL_PIN_V1,
    CHAT_ATTACHMENT_LEDGER_OPERATION_V1,
    CHAT_MEDIA_DELIVERY_OPERATION_V1,
    PRIVATE_CIPHERTEXT_CACHE_ACCOUNT_V1,
    PRIVATE_CIPHERTEXT_CACHE_BINDING_V1,
    TWO_FACTOR_RECOVERY_CODE_V1,
    ACCOUNT_RECORD_COMMIT_V1,
    ACCOUNT_RECORD_KEY_V1,
    ACCOUNT_RECORD_OBJECT_ID_V1,
    ACCOUNT_RECORD_V1,
    ACCOUNT_HEAD_ID_KEY_V1,
    ACCOUNT_HEAD_LOCAL_NAME_V1,
    ACCOUNT_HEAD_SCOPE_V1,
    ACCOUNT_HEAD_V1,
    ACCOUNT_HEAD_VALUE_V1,
    ACCOUNT_HEAD_WRITER_V1,
    ACCOUNT_IDENTITY_BINDING_V1,
    ACCOUNT_IDENTITY_DRIVE_HPKE_XWING_V1,
    ACCOUNT_IDENTITY_DRIVE_SHARE_SIGNING_ED25519_V1,
    ACCOUNT_IDENTITY_SELF_AUTHORITY_V1,
    ACCOUNT_IDENTITY_V1,
    ACCOUNT_RECOVERY_AUTH_PROOF_V1,
    ACCOUNT_DEVICE_SESSION_V1,
    ACCOUNT_ID_PROOF_V1,
    ACCOUNT_INCARNATION_V1,
    ACCOUNT_MANIFEST_V1,
    ACCOUNT_MANIFEST_V3,
    ACCOUNT_RENAME_V1,
    CHAT_BACKUP_MEDIA_BLOCKS_BLOCK_KEY_V1,
    CHAT_BACKUP_MEDIA_BLOCKS_MANIFEST_KEY_V1,
    CHAT_BACKUP_MEDIA_BLOCKS_NONCE_KEY_V1,
    CHAT_BACKUP_EVENT_SEGMENT_KEY_V1,
    CHAT_BACKUP_MANIFEST_SIGNING_SEED_V1,
    CHAT_BACKUP_MANIFEST_V1,
    CHAT_BACKUP_MEDIA_ENCRYPTION_ROOT_V1,
    CHAT_BACKUP_MEDIA_ID_KEY_V1,
    CHAT_BACKUP_MEDIA_REFERENCE_SET_V1,
    CHAT_BACKUP_MESSAGE_ARCHIVE_KEY_V1,
    CHAT_BACKUP_SIGNER_AUTHORIZATION_V1,
    CHAT_BACKUP_V1,
    CHAT_GROUP_SEND_PARAMS_V1,
    CHAT_GROUP_SEND_SERVER_KEY_V1,
    CHAT_GROUP_AVATAR_V1,
    CHAT_GROUP_BINDING_V1,
    CHAT_GROUP_CHANGE_HASH_V1,
    CHAT_GROUP_CHANGE_V1,
    CHAT_GROUP_CLAIM_V1,
    CHAT_GROUP_GATEWAY_KEY_CONFIG_HASH_V1,
    CHAT_GROUP_GATEWAY_KEY_CONFIG_V1,
    CHAT_GROUP_GATEWAY_KEY_XWING_V2,
    CHAT_GROUP_HOME_V1,
    CHAT_GROUP_ID_V2,
    CHAT_GROUP_LINK_REQUEST_V1,
    CHAT_GROUP_NOTARY_V1,
    CHAT_GROUP_PSEUDONYM_V1,
    CHAT_GROUP_REQUEST_BODY_V1,
    CHAT_GROUP_REQUEST_V1,
    CHAT_GROUP_SEALED_FIELD_V1,
    CHAT_GROUP_SEEN_PSEUDONYM_V1,
    CHAT_GROUP_STATE_HASH_V1,
    CHAT_GROUP_STATE_KEY_V2,
    CHAT_GROUP_V1,
    CHAT_MEDIA_BLOCKS_BLOCK_KEY_V1,
    CHAT_MEDIA_BLOCKS_MANIFEST_KEY_V1,
    CHAT_MEDIA_BLOCKS_NONCE_KEY_V1,
    CHAT_MEDIA_DELIVERY_OFFER_DIGEST_V1,
    CHAT_MEDIA_FEDERATION_ORIGIN_RATE_V1,
    CHAT_MEDIA_OBJECT_KEY_V1,
    CHAT_MEDIA_RECIPIENT_RATE_V1,
    CHAT_STORE_INDEX_V1,
    CHAT_STORE_RECORD_V1,
    CHAT_STORE_VALUE_V1,
    CHAT_STORE_WRAP_V1,
    CHAT_CALL_LINK_V1,
    CHAT_DEVICE_CREDENTIAL_V1,
    CHAT_KEYS_CHECK_V1,
    CHAT_LOCAL_V1,
    COLLAB_FRAME_KEY_V1,
    COLLAB_FRAME_V3,
    CONTACT_CONTROL_V1,
    CONTACT_SUMMARY_V2,
    DEVICE_REGISTRATION_V1,
    DEVICE_REVOCATION_V1,
    DKIM_KEY_V1,
    DRIVE_ENVELOPE_KEY_V1,
    DRIVE_ENVELOPE_THUMBNAIL_V1,
    DRIVE_ENVELOPE_THUMBNAIL_V2,
    DRIVE_ENVELOPE_WHITEBOARD_ASSET_V2,
    DRIVE_OBJECT_BLOCKS_BLOCK_KEY_V1,
    DRIVE_OBJECT_BLOCKS_MANIFEST_KEY_V1,
    DRIVE_OBJECT_BLOCKS_NONCE_KEY_V1,
    DRIVE_OBJECT_FILE_BLOB_KEY_V1,
    DRIVE_BLOCK_MANIFEST_V1,
    DRIVE_COLLECTION_EPOCH_RECORD_HASH_V1,
    DRIVE_COLLECTION_KEY_COMMITMENT_V1,
    DRIVE_FILE_SHARE_HPKE_V1,
    DRIVE_FOLDER_HASH_KEY_V1,
    DRIVE_KEY_BINDING_V2,
    DRIVE_NAMED_SHARE_HPKE_V1,
    DRIVE_PROFILE_KEY_HPKE_V1,
    DRIVE_TOP_LEVEL_NAMES_V1,
    FAKE_ACCOUNT_V1,
    GROUP_ENDORSEMENT_UPLOAD_V1,
    GROUP_SEND_ISSUE_V1,
    KNOWN_CLIENT_V1,
    MAIL_ADDRESS_KEY_V1,
    MAIL_FORWARDING_MARKER_V1,
    MAIL_FORWARDING_PROXY_PARAMETER_V1,
    MAIL_FORWARDING_RETURN_PATH_V1,
    MAIL_GROUP_KEY_SHARE_V2,
    MAIL_GROUP_SIGNER_HANDOVER_V1,
    MAIL_GROUP_SIGNING_SHARE_V2,
    MAIL_KEY_LIST_V1,
    MAIL_SEARCH_LOCATOR_KEY_V1,
    MAIL_SEARCH_NAME_KEY_V1,
    MAIL_SEARCH_RECORD_KEY_V1,
    MAIL_SEARCH_RECORD_V1,
    MAIL_SEARCH_V1,
    MAIL_SEARCH_WRAP_V1,
    MULTI_IP_BYTES_V1,
    MULTI_ORIGIN_V1,
    MULTI_RECIPIENT_V1,
    MULTI_TOKEN_V1,
    OPAQUE_CREDENTIAL_V1,
    OPAQUE_EXPORT_V1,
    OPAQUE_LOGIN_STATE_V1,
    OPAQUE_MASTER_KEY_KEK_V1,
    OPAQUE_SETUP_V1,
    OPAQUE_V1,
    PASS_VAULT_SECRET_V1,
    PASS_VAULT_SECRET_V2,
    PROFILE_ENVELOPE_KEY_V1,
    REGISTRATION_CODE_V1,
    SEALED_DELIVERY_CAPABILITY_V1,
    SEALED_ORIGIN_RATE_V1,
    SEALED_RECIPIENT_RATE_V1,
    SERVER_ADMIN_AUDIT_CHAIN_V1,
    SERVER_DATA_V1,
    SERVER_DATA_KEK_V1,
    SERVER_DATA_KEY_WRAP_V1,
    SERVER_DATA_FIELD_KEY_V1,
    SERVER_DATA_FIELD_V1,
    SERVER_DESTRUCTION_SUBJECT_V1,
    SESSION_VERSION_V1,
    YJS_SEED_V1,
    CHAT_PROFILE_ACCESS_V1,
    CHAT_PROFILE_VERSION_V1,
    CHAT_PROFILE_KEY_UPDATE_V1,
    DRIVE_FEDERATION_OPERATION_V1,
    FEDERATION_FEATURE_POLICY_ENVELOPE_HASH_V1,
    FEDERATION_FEATURE_POLICY_ENVELOPE_V1,
    FEDERATION_DISCOVERY_V2,
    FEDERATION_IDENTITY_DOCUMENT_HASH_V1,
    FEDERATION_IDENTITY_DOCUMENT_V1,
    FEDERATION_REPLAY_V1,
    FEDERATION_REQUEST_REPLAY_HASH_V1,
    CHAT_STORE_V1,
    CHAT_PROFILE_V1,
    DRIVE_NAMES_V1,
];

#[cfg(test)]
mod tests {
    use super::ALL;

    #[test]
    fn every_label_follows_the_grammar_once_and_prefixes_no_other() {
        for (i, label) in ALL.iter().enumerate() {
            let text = std::str::from_utf8(label).expect("UTF-8");
            let body = text
                .strip_prefix("kutup/")
                .and_then(|rest| rest.strip_suffix('\0'))
                .unwrap_or_else(|| panic!("{text:?}: kutup/…\\0"));
            let segments: Vec<&str> = body.split('/').collect();
            assert!(segments.len() >= 2, "{text:?}: an area and a version");
            let (version, path) = segments.split_last().unwrap();
            assert!(
                version.len() > 1
                    && version.starts_with('v')
                    && version[1..].bytes().all(|b| b.is_ascii_digit()),
                "{text:?}: ends in v<N>"
            );
            for segment in path {
                assert!(
                    !segment.is_empty()
                        && !segment.starts_with('-')
                        && !segment.ends_with('-')
                        && !segment.contains("--")
                        && segment
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                    "{text:?}: lowercase a-z 0-9 - segments"
                );
            }
            for other in &ALL[i + 1..] {
                assert_ne!(label, other, "{text:?} repeats");
                assert!(
                    !label.starts_with(other) && !other.starts_with(label),
                    "{text:?} and {:?}: one is a prefix of the other",
                    std::str::from_utf8(other).unwrap()
                );
            }
        }
    }
}
