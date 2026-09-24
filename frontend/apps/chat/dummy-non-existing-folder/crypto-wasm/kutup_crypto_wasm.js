/* @ts-self-types="./kutup_crypto_wasm.d.ts" */

/**
 * @param {string} frame_base64
 * @param {string} signature_base64
 * @returns {string}
 */
export function attachCollabFrameSignature(frame_base64, signature_base64) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(frame_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(signature_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.attachCollabFrameSignature(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * @param {string} envelope_base64
 * @returns {string}
 */
export function chatAttachmentLedgerEnvelopeDigest(envelope_base64) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(envelope_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.chatAttachmentLedgerEnvelopeDigest(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * The file-key generation a frame names in its public header, so a
 * client replaying older log frames can pick that generation's key.
 * Opening still checks it (`openCollabFrame` with the same generation).
 * @param {string} frame_base64
 * @returns {number}
 */
export function collabFrameKeyGeneration(frame_base64) {
    const ptr0 = passStringToWasm0(frame_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.collabFrameKeyGeneration(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return ret[0] >>> 0;
}

/**
 * @param {string} frame_base64
 * @returns {string}
 */
export function collabFrameSigningBytes(frame_base64) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(frame_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.collabFrameSigningBytes(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * @param {string} master_key_base64
 * @param {string} backup_root_base64
 * @param {string} backup_incarnation_id
 * @param {bigint} created_at_unix
 * @returns {any}
 */
export function createChatBackupSignerAuthorization(master_key_base64, backup_root_base64, backup_incarnation_id, created_at_unix) {
    const ptr0 = passStringToWasm0(master_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(backup_root_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(backup_incarnation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.createChatBackupSignerAuthorization(ptr0, len0, ptr1, len1, ptr2, len2, created_at_unix);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * @param {string} master_key_base64
 * @param {string} collection_key_base64
 * @param {string} collection_id
 * @param {string} owner_user_id
 * @param {number} epoch
 * @param {string} previous_statement_hash
 * @returns {string}
 */
export function createCollectionEpochStatement(master_key_base64, collection_key_base64, collection_id, owner_user_id, epoch, previous_statement_hash) {
    let deferred7_0;
    let deferred7_1;
    try {
        const ptr0 = passStringToWasm0(master_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(collection_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(collection_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(owner_user_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(previous_statement_hash, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ret = wasm.createCollectionEpochStatement(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, epoch, ptr4, len4);
        var ptr6 = ret[0];
        var len6 = ret[1];
        if (ret[3]) {
            ptr6 = 0; len6 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred7_0 = ptr6;
        deferred7_1 = len6;
        return getStringFromWasm0(ptr6, len6);
    } finally {
        wasm.__wbindgen_free(deferred7_0, deferred7_1, 1);
    }
}

/**
 * @param {string} entry_base64
 * @returns {any}
 */
export function decodeChatAttachmentLedgerEntry(entry_base64) {
    const ptr0 = passStringToWasm0(entry_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.decodeChatAttachmentLedgerEntry(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * Authenticate canonical archive structure before any record reaches the
 * isolated display-history store.
 * @param {string} plaintext_base64
 * @param {number} purpose
 * @returns {any}
 */
export function decodeChatBackupPlaintext(plaintext_base64, purpose) {
    const ptr0 = passStringToWasm0(plaintext_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.decodeChatBackupPlaintext(ptr0, len0, purpose);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * Derive the purpose-separated V1 account identity. The Drive private key is
 * returned only so the existing account-private wrap can be created during
 * the pre-tag format cutover; it is never sent in plaintext to the server.
 * @param {string} master_key_base64
 * @returns {any}
 */
export function deriveAccountIdentityKeys(master_key_base64) {
    const ptr0 = passStringToWasm0(master_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.deriveAccountIdentityKeys(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * Run the one expensive V1 Argon2id derivation and expand its two
 * purpose-separated account subkeys.
 * @param {string} password
 * @param {string} salt_base64
 * @param {number} suite
 * @param {number} memory_kib
 * @param {number} iterations
 * @param {number} parallelism
 * @returns {any}
 */
export function deriveAccountProtectionKeys(password, salt_base64, suite, memory_kib, iterations, parallelism) {
    const ptr0 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(salt_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.deriveAccountProtectionKeys(ptr0, len0, ptr1, len1, suite, memory_kib, iterations, parallelism);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * @param {string} master_key_base64
 * @returns {string}
 */
export function deriveChatAttachmentLedgerKey(master_key_base64) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(master_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.deriveChatAttachmentLedgerKey(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Derive the recovery authorization proof sent to the server. Raw recovery
 * entropy stays in the browser and continues to open only the recovery wrap.
 * @param {string} recovery_entropy_base64
 * @param {string} login_email
 * @returns {string}
 */
export function deriveRecoveryAuthProof(recovery_entropy_base64, login_email) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(recovery_entropy_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(login_email, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.deriveRecoveryAuthProof(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * @param {any} entry
 * @returns {string}
 */
export function encodeChatAttachmentLedgerEntry(entry) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ret = wasm.encodeChatAttachmentLedgerEntry(entry);
        var ptr1 = ret[0];
        var len1 = ret[1];
        if (ret[3]) {
            ptr1 = 0; len1 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred2_0 = ptr1;
        deferred2_1 = len1;
        return getStringFromWasm0(ptr1, len1);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Serialize archive plaintext through the canonical Rust protocol types.
 * @param {any} value
 * @param {number} purpose
 * @returns {string}
 */
export function encodeChatBackupPlaintext(value, purpose) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ret = wasm.encodeChatBackupPlaintext(value, purpose);
        var ptr1 = ret[0];
        var len1 = ret[1];
        if (ret[3]) {
            ptr1 = 0; len1 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred2_0 = ptr1;
        deferred2_1 = len1;
        return getStringFromWasm0(ptr1, len1);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * The file key of generation `wanted`, base64, from the current key of
 * `generation` and the file's history (`chain`: the listing's
 * `keyHistory`, generations 2 to `generation` in order).
 * @param {string} current_key_base64
 * @param {string} file_id
 * @param {number} generation
 * @param {any} chain
 * @param {number} wanted
 * @returns {string}
 */
export function fileKeyAt(current_key_base64, file_id, generation, chain, wanted) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(current_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(file_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.fileKeyAt(ptr0, len0, ptr1, len1, generation, chain, wanted);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * @param {string} envelope_base64
 * @returns {any}
 */
export function inspectChatAttachmentLedgerEnvelope(envelope_base64) {
    const ptr0 = passStringToWasm0(envelope_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.inspectChatAttachmentLedgerEnvelope(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * Open one account secret only when its purpose and login-email binding match.
 * @param {string} envelope_base64
 * @param {string} key_base64
 * @param {number} expected_purpose
 * @param {string} login_email
 * @returns {string}
 */
export function openAccountEnvelope(envelope_base64, key_base64, expected_purpose, login_email) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(envelope_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(login_email, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.openAccountEnvelope(ptr0, len0, ptr1, len1, expected_purpose, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * @param {string} envelope_base64
 * @param {string} ledger_key_base64
 * @param {string} expected_account_incarnation_id
 * @param {string} expected_entity_id
 * @param {bigint} expected_revision
 * @param {string} expected_previous_envelope_digest
 * @returns {string}
 */
export function openChatAttachmentLedger(envelope_base64, ledger_key_base64, expected_account_incarnation_id, expected_entity_id, expected_revision, expected_previous_envelope_digest) {
    let deferred7_0;
    let deferred7_1;
    try {
        const ptr0 = passStringToWasm0(envelope_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(ledger_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(expected_account_incarnation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(expected_entity_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(expected_previous_envelope_digest, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ret = wasm.openChatAttachmentLedger(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, expected_revision, ptr4, len4);
        var ptr6 = ret[0];
        var len6 = ret[1];
        if (ret[3]) {
            ptr6 = 0; len6 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred7_0 = ptr6;
        deferred7_1 = len6;
        return getStringFromWasm0(ptr6, len6);
    } finally {
        wasm.__wbindgen_free(deferred7_0, deferred7_1, 1);
    }
}

/**
 * @param {string} header_base64
 * @param {string} backup_root_base64
 * @param {string} expected_account_incarnation_id
 * @param {string} expected_backup_incarnation_id
 * @param {string} expected_media_id
 * @returns {any}
 */
export function openChatBackupMediaHeader(header_base64, backup_root_base64, expected_account_incarnation_id, expected_backup_incarnation_id, expected_media_id) {
    const ptr0 = passStringToWasm0(header_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(backup_root_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(expected_account_incarnation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(expected_backup_incarnation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(expected_media_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ret = wasm.openChatBackupMediaHeader(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * @param {string} object_base64
 * @param {string} backup_root_base64
 * @param {string} account_incarnation_id
 * @param {string} backup_incarnation_id
 * @param {number} purpose
 * @param {string} object_id
 * @param {number} source_device_id
 * @param {bigint} device_sequence
 * @param {string} previous_segment_digest
 * @returns {string}
 */
export function openChatBackupObject(object_base64, backup_root_base64, account_incarnation_id, backup_incarnation_id, purpose, object_id, source_device_id, device_sequence, previous_segment_digest) {
    let deferred8_0;
    let deferred8_1;
    try {
        const ptr0 = passStringToWasm0(object_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(backup_root_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(account_incarnation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(backup_incarnation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(object_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(previous_segment_digest, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len5 = WASM_VECTOR_LEN;
        const ret = wasm.openChatBackupObject(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, purpose, ptr4, len4, source_device_id, device_sequence, ptr5, len5);
        var ptr7 = ret[0];
        var len7 = ret[1];
        if (ret[3]) {
            ptr7 = 0; len7 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred8_0 = ptr7;
        deferred8_1 = len7;
        return getStringFromWasm0(ptr7, len7);
    } finally {
        wasm.__wbindgen_free(deferred8_0, deferred8_1, 1);
    }
}

/**
 * @param {string} object_header_base64
 * @param {string} attachment_key_base64
 * @param {string} expected_attachment_id
 * @returns {string}
 */
export function openChatMediaObjectHeader(object_header_base64, attachment_key_base64, expected_attachment_id) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(object_header_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(attachment_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(expected_attachment_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.openChatMediaObjectHeader(ptr0, len0, ptr1, len1, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * @param {string} frame_base64
 * @param {string} file_key_base64
 * @param {string} expected_file_id
 * @param {number} expected_key_generation
 * @returns {any}
 */
export function openCollabFrame(frame_base64, file_key_base64, expected_file_id, expected_key_generation) {
    const ptr0 = passStringToWasm0(frame_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(file_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(expected_file_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.openCollabFrame(ptr0, len0, ptr1, len1, ptr2, len2, expected_key_generation);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * @param {string} envelope_base64
 * @param {string} root_key_base64
 * @param {number} expected_purpose
 * @param {number} expected_epoch
 * @param {bigint} expected_revision
 * @param {string} expected_object_id
 * @param {string} expected_parent_id
 * @returns {string}
 */
export function openDriveEnvelope(envelope_base64, root_key_base64, expected_purpose, expected_epoch, expected_revision, expected_object_id, expected_parent_id) {
    let deferred6_0;
    let deferred6_1;
    try {
        const ptr0 = passStringToWasm0(envelope_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(root_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(expected_object_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(expected_parent_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.openDriveEnvelope(ptr0, len0, ptr1, len1, expected_purpose, expected_epoch, expected_revision, ptr2, len2, ptr3, len3);
        var ptr5 = ret[0];
        var len5 = ret[1];
        if (ret[3]) {
            ptr5 = 0; len5 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred6_0 = ptr5;
        deferred6_1 = len5;
        return getStringFromWasm0(ptr5, len5);
    } finally {
        wasm.__wbindgen_free(deferred6_0, deferred6_1, 1);
    }
}

/**
 * @param {string} object_header_base64
 * @param {string} file_key_base64
 * @param {string} expected_file_id
 * @param {number} expected_generation
 * @returns {string}
 */
export function openDriveFileBlobHeader(object_header_base64, file_key_base64, expected_file_id, expected_generation) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(object_header_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(file_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(expected_file_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.openDriveFileBlobHeader(ptr0, len0, ptr1, len1, ptr2, len2, expected_generation);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * Open an envelope sealed by `sealLocalState` (or the Rust equivalent);
 * fails closed on a wrong key, purpose or profile.
 * @param {string} envelope_base64
 * @param {string} key_base64
 * @param {number} purpose
 * @param {string} profile
 * @returns {string}
 */
export function openLocalState(envelope_base64, key_base64, purpose, profile) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(envelope_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(profile, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.openLocalState(ptr0, len0, ptr1, len1, purpose, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * @param {string} envelope_base64
 * @param {string} sender_signing_public_key_base64
 * @param {string} recipient_hpke_private_key_base64
 * @param {string} expected_collection_id
 * @param {number} expected_epoch
 * @param {string} expected_sender_account
 * @param {string} expected_sender_incarnation_id
 * @param {string} expected_recipient_account
 * @param {string} expected_recipient_incarnation_id
 * @returns {string}
 */
export function openNamedShareEnvelope(envelope_base64, sender_signing_public_key_base64, recipient_hpke_private_key_base64, expected_collection_id, expected_epoch, expected_sender_account, expected_sender_incarnation_id, expected_recipient_account, expected_recipient_incarnation_id) {
    let deferred10_0;
    let deferred10_1;
    try {
        const ptr0 = passStringToWasm0(envelope_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(sender_signing_public_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(recipient_hpke_private_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(expected_collection_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(expected_sender_account, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(expected_sender_incarnation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len5 = WASM_VECTOR_LEN;
        const ptr6 = passStringToWasm0(expected_recipient_account, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len6 = WASM_VECTOR_LEN;
        const ptr7 = passStringToWasm0(expected_recipient_incarnation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len7 = WASM_VECTOR_LEN;
        const ret = wasm.openNamedShareEnvelope(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, expected_epoch, ptr4, len4, ptr5, len5, ptr6, len6, ptr7, len7);
        var ptr9 = ret[0];
        var len9 = ret[1];
        if (ret[3]) {
            ptr9 = 0; len9 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred10_0 = ptr9;
        deferred10_1 = len9;
        return getStringFromWasm0(ptr9, len9);
    } finally {
        wasm.__wbindgen_free(deferred10_0, deferred10_1, 1);
    }
}

/**
 * Open a thumbnail of exactly this file, variant and key generation.
 * @param {string} envelope_base64
 * @param {string} variant
 * @param {string} file_key_base64
 * @param {string} expected_file_id
 * @param {number} expected_generation
 * @returns {any}
 */
export function openThumbnail(envelope_base64, variant, file_key_base64, expected_file_id, expected_generation) {
    const ptr0 = passStringToWasm0(envelope_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(variant, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(file_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(expected_file_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.openThumbnail(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, expected_generation);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * @param {string} envelope_base64
 * @param {string} file_key_base64
 * @param {string} expected_file_id
 * @param {string} expected_asset_id
 * @param {number} expected_generation
 * @returns {string}
 */
export function openWhiteboardAsset(envelope_base64, file_key_base64, expected_file_id, expected_asset_id, expected_generation) {
    let deferred6_0;
    let deferred6_1;
    try {
        const ptr0 = passStringToWasm0(envelope_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(file_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(expected_file_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(expected_asset_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.openWhiteboardAsset(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, expected_generation);
        var ptr5 = ret[0];
        var len5 = ret[1];
        if (ret[3]) {
            ptr5 = 0; len5 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred6_0 = ptr5;
        deferred6_1 = len5;
        return getStringFromWasm0(ptr5, len5);
    } finally {
        wasm.__wbindgen_free(deferred6_0, deferred6_1, 1);
    }
}

/**
 * @param {string} backup_root_base64
 * @param {string} account_incarnation_id
 * @param {string} backup_incarnation_id
 * @param {string} stable_source_binding
 * @param {bigint} source_ciphertext_bytes
 * @returns {any}
 */
export function prepareChatBackupMedia(backup_root_base64, account_incarnation_id, backup_incarnation_id, stable_source_binding, source_ciphertext_bytes) {
    const ptr0 = passStringToWasm0(backup_root_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(account_incarnation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(backup_incarnation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(stable_source_binding, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.prepareChatBackupMedia(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, source_ciphertext_bytes);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * Return the canonical Chat-media header and its purpose-derived stream key.
 * JS owns only bounded secretstream I/O, exactly as for Drive file blobs.
 * @param {string} attachment_key_base64
 * @param {string} attachment_id
 * @returns {any}
 */
export function prepareChatMediaObject(attachment_key_base64, attachment_id) {
    const ptr0 = passStringToWasm0(attachment_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(attachment_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.prepareChatMediaObject(ptr0, len0, ptr1, len1);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * @param {string} file_key_base64
 * @param {string} file_id
 * @param {number} generation
 * @returns {any}
 */
export function prepareDriveFileBlob(file_key_base64, file_id, generation) {
    const ptr0 = passStringToWasm0(file_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(file_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.prepareDriveFileBlob(ptr0, len0, ptr1, len1, generation);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * Seal one account secret into the canonical, suite-bearing V1 envelope.
 * @param {string} plaintext_base64
 * @param {string} key_base64
 * @param {number} purpose
 * @param {string} login_email
 * @returns {string}
 */
export function sealAccountEnvelope(plaintext_base64, key_base64, purpose, login_email) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(plaintext_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(login_email, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.sealAccountEnvelope(ptr0, len0, ptr1, len1, purpose, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * @param {string} plaintext_base64
 * @param {string} ledger_key_base64
 * @param {string} account_incarnation_id
 * @param {string} entity_id
 * @param {bigint} revision
 * @param {string} previous_envelope_digest
 * @returns {string}
 */
export function sealChatAttachmentLedger(plaintext_base64, ledger_key_base64, account_incarnation_id, entity_id, revision, previous_envelope_digest) {
    let deferred7_0;
    let deferred7_1;
    try {
        const ptr0 = passStringToWasm0(plaintext_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(ledger_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(account_incarnation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(entity_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(previous_envelope_digest, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ret = wasm.sealChatAttachmentLedger(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, revision, ptr4, len4);
        var ptr6 = ret[0];
        var len6 = ret[1];
        if (ret[3]) {
            ptr6 = 0; len6 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred7_0 = ptr6;
        deferred7_1 = len6;
        return getStringFromWasm0(ptr6, len6);
    } finally {
        wasm.__wbindgen_free(deferred7_0, deferred7_1, 1);
    }
}

/**
 * @param {string} plaintext_base64
 * @param {string} backup_root_base64
 * @param {string} account_incarnation_id
 * @param {string} backup_incarnation_id
 * @param {number} purpose
 * @param {string} object_id
 * @param {number} source_device_id
 * @param {bigint} device_sequence
 * @param {string} previous_segment_digest
 * @returns {string}
 */
export function sealChatBackupObject(plaintext_base64, backup_root_base64, account_incarnation_id, backup_incarnation_id, purpose, object_id, source_device_id, device_sequence, previous_segment_digest) {
    let deferred8_0;
    let deferred8_1;
    try {
        const ptr0 = passStringToWasm0(plaintext_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(backup_root_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(account_incarnation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(backup_incarnation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(object_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(previous_segment_digest, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len5 = WASM_VECTOR_LEN;
        const ret = wasm.sealChatBackupObject(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, purpose, ptr4, len4, source_device_id, device_sequence, ptr5, len5);
        var ptr7 = ret[0];
        var len7 = ret[1];
        if (ret[3]) {
            ptr7 = 0; len7 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred8_0 = ptr7;
        deferred8_1 = len7;
        return getStringFromWasm0(ptr7, len7);
    } finally {
        wasm.__wbindgen_free(deferred8_0, deferred8_1, 1);
    }
}

/**
 * @param {string} plaintext_base64
 * @param {string} file_key_base64
 * @param {number} kind
 * @param {number} key_generation
 * @param {number} doc_key_id
 * @param {string} file_id
 * @param {string} sender_device_id
 * @param {string} sequence
 * @returns {string}
 */
export function sealCollabFrame(plaintext_base64, file_key_base64, kind, key_generation, doc_key_id, file_id, sender_device_id, sequence) {
    let deferred7_0;
    let deferred7_1;
    try {
        const ptr0 = passStringToWasm0(plaintext_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(file_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(file_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(sender_device_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(sequence, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ret = wasm.sealCollabFrame(ptr0, len0, ptr1, len1, kind, key_generation, doc_key_id, ptr2, len2, ptr3, len3, ptr4, len4);
        var ptr6 = ret[0];
        var len6 = ret[1];
        if (ret[3]) {
            ptr6 = 0; len6 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred7_0 = ptr6;
        deferred7_1 = len6;
        return getStringFromWasm0(ptr6, len6);
    } finally {
        wasm.__wbindgen_free(deferred7_0, deferred7_1, 1);
    }
}

/**
 * @param {string} plaintext_base64
 * @param {string} root_key_base64
 * @param {number} purpose
 * @param {number} epoch
 * @param {bigint} revision
 * @param {string} object_id
 * @param {string} parent_id
 * @returns {string}
 */
export function sealDriveEnvelope(plaintext_base64, root_key_base64, purpose, epoch, revision, object_id, parent_id) {
    let deferred6_0;
    let deferred6_1;
    try {
        const ptr0 = passStringToWasm0(plaintext_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(root_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(object_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(parent_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.sealDriveEnvelope(ptr0, len0, ptr1, len1, purpose, epoch, revision, ptr2, len2, ptr3, len3);
        var ptr5 = ret[0];
        var len5 = ret[1];
        if (ret[3]) {
            ptr5 = 0; len5 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred6_0 = ptr5;
        deferred6_1 = len5;
        return getStringFromWasm0(ptr5, len5);
    } finally {
        wasm.__wbindgen_free(deferred6_0, deferred6_1, 1);
    }
}

/**
 * Seal a session-fork payload (purpose 2) or a persisted web session (3).
 * Returns the canonical base64 envelope; the nonce is random.
 * @param {string} plaintext_base64
 * @param {string} key_base64
 * @param {number} purpose
 * @param {string} profile
 * @returns {string}
 */
export function sealLocalState(plaintext_base64, key_base64, purpose, profile) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(plaintext_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(profile, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.sealLocalState(ptr0, len0, ptr1, len1, purpose, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * @param {string} collection_key_base64
 * @param {string} sender_master_key_base64
 * @param {string} recipient_hpke_public_key_base64
 * @param {string} collection_id
 * @param {number} epoch
 * @param {string} sender_account
 * @param {string} sender_incarnation_id
 * @param {string} recipient_account
 * @param {string} recipient_incarnation_id
 * @returns {string}
 */
export function sealNamedShareEnvelope(collection_key_base64, sender_master_key_base64, recipient_hpke_public_key_base64, collection_id, epoch, sender_account, sender_incarnation_id, recipient_account, recipient_incarnation_id) {
    let deferred10_0;
    let deferred10_1;
    try {
        const ptr0 = passStringToWasm0(collection_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(sender_master_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(recipient_hpke_public_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(collection_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(sender_account, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(sender_incarnation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len5 = WASM_VECTOR_LEN;
        const ptr6 = passStringToWasm0(recipient_account, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len6 = WASM_VECTOR_LEN;
        const ptr7 = passStringToWasm0(recipient_incarnation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len7 = WASM_VECTOR_LEN;
        const ret = wasm.sealNamedShareEnvelope(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, epoch, ptr4, len4, ptr5, len5, ptr6, len6, ptr7, len7);
        var ptr9 = ret[0];
        var len9 = ret[1];
        if (ret[3]) {
            ptr9 = 0; len9 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred10_0 = ptr9;
        deferred10_1 = len9;
        return getStringFromWasm0(ptr9, len9);
    } finally {
        wasm.__wbindgen_free(deferred10_0, deferred10_1, 1);
    }
}

/**
 * The previous epoch's folder key sealed under this epoch's, for the
 * rotation record (docs/plans/drive-share-revocation.md).
 * @param {string} previous_key_base64
 * @param {string} key_base64
 * @param {string} collection_id
 * @param {string} owner_user_id
 * @param {number} epoch
 * @returns {string}
 */
export function sealPreviousCollectionKey(previous_key_base64, key_base64, collection_id, owner_user_id, epoch) {
    let deferred6_0;
    let deferred6_1;
    try {
        const ptr0 = passStringToWasm0(previous_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(collection_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(owner_user_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.sealPreviousCollectionKey(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, epoch);
        var ptr5 = ret[0];
        var len5 = ret[1];
        if (ret[3]) {
            ptr5 = 0; len5 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred6_0 = ptr5;
        deferred6_1 = len5;
        return getStringFromWasm0(ptr5, len5);
    } finally {
        wasm.__wbindgen_free(deferred6_0, deferred6_1, 1);
    }
}

/**
 * The file key of `generation − 1` sealed under that of `generation`, for a
 * re-key (docs/plans/drive-move.md).
 * @param {string} previous_key_base64
 * @param {string} key_base64
 * @param {string} file_id
 * @param {number} generation
 * @returns {string}
 */
export function sealPreviousFileKey(previous_key_base64, key_base64, file_id, generation) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(previous_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(file_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.sealPreviousFileKey(ptr0, len0, ptr1, len1, ptr2, len2, generation);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * Frame, pad and seal a thumbnail under the file key
 * (docs/plans/drive-thumbnails.md). `format`: 1 JPEG, 2 WebP, 3 PNG.
 * @param {string} image_base64
 * @param {number} format
 * @param {number} width
 * @param {number} height
 * @param {string} variant
 * @param {string} file_key_base64
 * @param {string} file_id
 * @param {number} generation
 * @returns {string}
 */
export function sealThumbnail(image_base64, format, width, height, variant, file_key_base64, file_id, generation) {
    let deferred6_0;
    let deferred6_1;
    try {
        const ptr0 = passStringToWasm0(image_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(variant, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(file_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(file_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.sealThumbnail(ptr0, len0, format, width, height, ptr1, len1, ptr2, len2, ptr3, len3, generation);
        var ptr5 = ret[0];
        var len5 = ret[1];
        if (ret[3]) {
            ptr5 = 0; len5 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred6_0 = ptr5;
        deferred6_1 = len5;
        return getStringFromWasm0(ptr5, len5);
    } finally {
        wasm.__wbindgen_free(deferred6_0, deferred6_1, 1);
    }
}

/**
 * @param {string} plaintext_base64
 * @param {string} file_key_base64
 * @param {string} file_id
 * @param {string} asset_id
 * @param {number} generation
 * @returns {string}
 */
export function sealWhiteboardAsset(plaintext_base64, file_key_base64, file_id, asset_id, generation) {
    let deferred6_0;
    let deferred6_1;
    try {
        const ptr0 = passStringToWasm0(plaintext_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(file_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(file_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(asset_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.sealWhiteboardAsset(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, generation);
        var ptr5 = ret[0];
        var len5 = ret[1];
        if (ret[3]) {
            ptr5 = 0; len5 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred6_0 = ptr5;
        deferred6_1 = len5;
        return getStringFromWasm0(ptr5, len5);
    } finally {
        wasm.__wbindgen_free(deferred6_0, deferred6_1, 1);
    }
}

/**
 * @param {any} unsigned_manifest
 * @param {string} backup_root_base64
 * @param {string} account_incarnation_id
 * @param {string} backup_incarnation_id
 * @returns {any}
 */
export function signChatBackupManifest(unsigned_manifest, backup_root_base64, account_incarnation_id, backup_incarnation_id) {
    const ptr0 = passStringToWasm0(backup_root_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(account_incarnation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(backup_incarnation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.signChatBackupManifest(unsigned_manifest, ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * Every key of a folder, oldest first, as an array of base64 strings, from
 * its current key and complete signed history (`chain`: the
 * `GET /api/collections/{id}/epochs` array). Fails unless every statement
 * is the owner's, chained, and every key matches its commitment.
 * @param {string} current_key_base64
 * @param {string} collection_id
 * @param {string} owner_user_id
 * @param {string} owner_authority_public_key_base64
 * @param {any} chain
 * @returns {any}
 */
export function unlockCollectionKeyring(current_key_base64, collection_id, owner_user_id, owner_authority_public_key_base64, chain) {
    const ptr0 = passStringToWasm0(current_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(collection_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(owner_user_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(owner_authority_public_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.unlockCollectionKeyring(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, chain);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * Verify the complete account-authority -> backup-signer -> manifest chain
 * against keys derived locally from the recovered account master key.
 * @param {any} signer_authorization
 * @param {any} manifest
 * @param {string} master_key_base64
 * @param {string} backup_root_base64
 * @param {string} expected_backup_incarnation_id
 * @returns {any}
 */
export function verifyChatBackupMetadata(signer_authorization, manifest, master_key_base64, backup_root_base64, expected_backup_incarnation_id) {
    const ptr0 = passStringToWasm0(master_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(backup_root_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(expected_backup_incarnation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.verifyChatBackupMetadata(signer_authorization, manifest, ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * @param {string} statement_base64
 * @param {string} authority_public_key_base64
 * @param {string} collection_key_base64
 * @param {string} expected_collection_id
 * @param {string} expected_owner_user_id
 * @param {number} expected_epoch
 * @param {string} expected_previous_statement_hash
 * @returns {string}
 */
export function verifyCollectionEpochStatement(statement_base64, authority_public_key_base64, collection_key_base64, expected_collection_id, expected_owner_user_id, expected_epoch, expected_previous_statement_hash) {
    let deferred8_0;
    let deferred8_1;
    try {
        const ptr0 = passStringToWasm0(statement_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(authority_public_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(collection_key_base64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(expected_collection_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(expected_owner_user_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(expected_previous_statement_hash, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len5 = WASM_VECTOR_LEN;
        const ret = wasm.verifyCollectionEpochStatement(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, expected_epoch, ptr5, len5);
        var ptr7 = ret[0];
        var len7 = ret[1];
        if (ret[3]) {
            ptr7 = 0; len7 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred8_0 = ptr7;
        deferred8_1 = len7;
        return getStringFromWasm0(ptr7, len7);
    } finally {
        wasm.__wbindgen_free(deferred8_0, deferred8_1, 1);
    }
}
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg_Error_ef53bc310eb298a0: function(arg0, arg1) {
            const ret = Error(getStringFromWasm0(arg0, arg1));
            return ret;
        },
        __wbg_Number_6b506e6536831eaa: function(arg0) {
            const ret = Number(arg0);
            return ret;
        },
        __wbg_String_8564e559799eccda: function(arg0, arg1) {
            const ret = String(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_bigint_get_as_i64_38130e98eecd467d: function(arg0, arg1) {
            const v = arg1;
            const ret = typeof(v) === 'bigint' ? v : undefined;
            getDataViewMemory0().setBigInt64(arg0 + 8 * 1, isLikeNone(ret) ? BigInt(0) : ret, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, !isLikeNone(ret), true);
        },
        __wbg___wbindgen_boolean_get_1a45e2c38d4d41b9: function(arg0) {
            const v = arg0;
            const ret = typeof(v) === 'boolean' ? v : undefined;
            return isLikeNone(ret) ? 0xFFFFFF : ret ? 1 : 0;
        },
        __wbg___wbindgen_debug_string_0accd80f45e5faa2: function(arg0, arg1) {
            const ret = debugString(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_in_70a403a56e771704: function(arg0, arg1) {
            const ret = arg0 in arg1;
            return ret;
        },
        __wbg___wbindgen_is_bigint_6ffd6468a9bc44b9: function(arg0) {
            const ret = typeof(arg0) === 'bigint';
            return ret;
        },
        __wbg___wbindgen_is_function_754e9f305ff6029e: function(arg0) {
            const ret = typeof(arg0) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_null_87c3bfe968c6a5ad: function(arg0) {
            const ret = arg0 === null;
            return ret;
        },
        __wbg___wbindgen_is_object_56732c2bc353f41d: function(arg0) {
            const val = arg0;
            const ret = typeof(val) === 'object' && val !== null;
            return ret;
        },
        __wbg___wbindgen_is_string_c236cabd84a4d769: function(arg0) {
            const ret = typeof(arg0) === 'string';
            return ret;
        },
        __wbg___wbindgen_is_undefined_67b456be8673d3d7: function(arg0) {
            const ret = arg0 === undefined;
            return ret;
        },
        __wbg___wbindgen_jsval_eq_1068e624fa87f6ab: function(arg0, arg1) {
            const ret = arg0 === arg1;
            return ret;
        },
        __wbg___wbindgen_jsval_loose_eq_2c56564c75129511: function(arg0, arg1) {
            const ret = arg0 == arg1;
            return ret;
        },
        __wbg___wbindgen_number_get_9bb1761122181af2: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'number' ? obj : undefined;
            getDataViewMemory0().setFloat64(arg0 + 8 * 1, isLikeNone(ret) ? 0 : ret, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, !isLikeNone(ret), true);
        },
        __wbg___wbindgen_string_get_72bdf95d3ae505b1: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'string' ? obj : undefined;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_throw_1506f2235d1bdba0: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_call_8a89609d89f6608a: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.call(arg1);
            return ret;
        }, arguments); },
        __wbg_call_9c758de292015997: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.call(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_crypto_38df2bab126b63dc: function(arg0) {
            const ret = arg0.crypto;
            return ret;
        },
        __wbg_done_60cf307fcc680536: function(arg0) {
            const ret = arg0.done;
            return ret;
        },
        __wbg_entries_04b37a02507f1713: function(arg0) {
            const ret = Object.entries(arg0);
            return ret;
        },
        __wbg_getRandomValues_3f44b700395062e5: function() { return handleError(function (arg0, arg1) {
            globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
        }, arguments); },
        __wbg_getRandomValues_c44a50d8cfdaebeb: function() { return handleError(function (arg0, arg1) {
            arg0.getRandomValues(arg1);
        }, arguments); },
        __wbg_get_1f8f054ddbaa7db2: function() { return handleError(function (arg0, arg1) {
            const ret = Reflect.get(arg0, arg1);
            return ret;
        }, arguments); },
        __wbg_get_2b48c7d0d006a781: function(arg0, arg1) {
            const ret = arg0[arg1 >>> 0];
            return ret;
        },
        __wbg_get_unchecked_33f6e5c9e2f2d6b2: function(arg0, arg1) {
            const ret = arg0[arg1 >>> 0];
            return ret;
        },
        __wbg_get_with_ref_key_6412cf3094599694: function(arg0, arg1) {
            const ret = arg0[arg1];
            return ret;
        },
        __wbg_instanceof_ArrayBuffer_8f49811467741499: function(arg0) {
            let result;
            try {
                result = arg0 instanceof ArrayBuffer;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_Map_9fc06d9a951bcee6: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Map;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_Uint8Array_86f30649f63ef9c2: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Uint8Array;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_isArray_67c2c9c4313f4448: function(arg0) {
            const ret = Array.isArray(arg0);
            return ret;
        },
        __wbg_isSafeInteger_66acec27e09e99a7: function(arg0) {
            const ret = Number.isSafeInteger(arg0);
            return ret;
        },
        __wbg_iterator_8732428d309e270e: function() {
            const ret = Symbol.iterator;
            return ret;
        },
        __wbg_length_4a591ecaa01354d9: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_length_66f1a4b2e9026940: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_msCrypto_bd5a034af96bcba6: function(arg0) {
            const ret = arg0.msCrypto;
            return ret;
        },
        __wbg_new_578aeef4b6b94378: function(arg0) {
            const ret = new Uint8Array(arg0);
            return ret;
        },
        __wbg_new_622fc80556be2e26: function() {
            const ret = new Map();
            return ret;
        },
        __wbg_new_ce1ab61c1c2b300d: function() {
            const ret = new Object();
            return ret;
        },
        __wbg_new_d90091b82fdf5b91: function() {
            const ret = new Array();
            return ret;
        },
        __wbg_new_with_length_36a4998e27b014c5: function(arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return ret;
        },
        __wbg_next_9e03acdf51c4960d: function(arg0) {
            const ret = arg0.next;
            return ret;
        },
        __wbg_next_eb8ca7351fa27906: function() { return handleError(function (arg0) {
            const ret = arg0.next();
            return ret;
        }, arguments); },
        __wbg_node_84ea875411254db1: function(arg0) {
            const ret = arg0.node;
            return ret;
        },
        __wbg_process_44c7a14e11e9f69e: function(arg0) {
            const ret = arg0.process;
            return ret;
        },
        __wbg_prototypesetcall_3249fc62a0fafa30: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        },
        __wbg_randomFillSync_6c25eac9869eb53c: function() { return handleError(function (arg0, arg1) {
            arg0.randomFillSync(arg1);
        }, arguments); },
        __wbg_require_b4edbdcf3e2a1ef0: function() { return handleError(function () {
            const ret = module.require;
            return ret;
        }, arguments); },
        __wbg_set_52b1e1eb5bed906a: function(arg0, arg1, arg2) {
            const ret = arg0.set(arg1, arg2);
            return ret;
        },
        __wbg_set_6be42768c690e380: function(arg0, arg1, arg2) {
            arg0[arg1] = arg2;
        },
        __wbg_set_dca99999bba88a9a: function(arg0, arg1, arg2) {
            arg0[arg1 >>> 0] = arg2;
        },
        __wbg_static_accessor_GLOBAL_9d53f2689e622ca1: function() {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_GLOBAL_THIS_a1a35cec07001a8a: function() {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_SELF_4c59f6c7ea29a144: function() {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_WINDOW_e70ae9f2eb052253: function() {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_subarray_4aa221f6a4f5ab22: function(arg0, arg1, arg2) {
            const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
            return ret;
        },
        __wbg_value_f3625092ee4b37f4: function(arg0) {
            const ret = arg0.value;
            return ret;
        },
        __wbg_versions_276b2795b1c6a219: function(arg0) {
            const ret = arg0.versions;
            return ret;
        },
        __wbindgen_cast_0000000000000001: function(arg0) {
            // Cast intrinsic for `F64 -> Externref`.
            const ret = arg0;
            return ret;
        },
        __wbindgen_cast_0000000000000002: function(arg0) {
            // Cast intrinsic for `I64 -> Externref`.
            const ret = arg0;
            return ret;
        },
        __wbindgen_cast_0000000000000003: function(arg0, arg1) {
            // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
            const ret = getArrayU8FromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000004: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000005: function(arg0) {
            // Cast intrinsic for `U64 -> Externref`.
            const ret = BigInt.asUintN(64, arg0);
            return ret;
        },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./kutup_crypto_wasm_bg.js": import0,
    };
}

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

function debugString(val) {
    // primitive types
    const type = typeof val;
    if (type == 'number' || type == 'boolean' || val == null) {
        return  `${val}`;
    }
    if (type == 'string') {
        return `"${val}"`;
    }
    if (type == 'symbol') {
        const description = val.description;
        if (description == null) {
            return 'Symbol';
        } else {
            return `Symbol(${description})`;
        }
    }
    if (type == 'function') {
        const name = val.name;
        if (typeof name == 'string' && name.length > 0) {
            return `Function(${name})`;
        } else {
            return 'Function';
        }
    }
    // objects
    if (Array.isArray(val)) {
        const length = val.length;
        let debug = '[';
        if (length > 0) {
            debug += debugString(val[0]);
        }
        for(let i = 1; i < length; i++) {
            debug += ', ' + debugString(val[i]);
        }
        debug += ']';
        return debug;
    }
    // Test for built-in
    const builtInMatches = /\[object ([^\]]+)\]/.exec(toString.call(val));
    let className;
    if (builtInMatches && builtInMatches.length > 1) {
        className = builtInMatches[1];
    } else {
        // Failed to match the standard '[object ClassName]'
        return toString.call(val);
    }
    if (className == 'Object') {
        // we're a user defined class or Object
        // JSON.stringify avoids problems with cycles, and is generally much
        // easier than looping through ownProperties of `val`.
        try {
            return 'Object(' + JSON.stringify(val) + ')';
        } catch (_) {
            return 'Object';
        }
    }
    // errors
    if (val instanceof Error) {
        return `${val.name}: ${val.message}\n${val.stack}`;
    }
    // TODO we could test for more things here, like `Set`s and `Map`s.
    return className;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    return decodeText(ptr >>> 0, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasmInstance, wasm;
function __wbg_finalize_init(instance, module) {
    wasmInstance = instance;
    wasm = instance.exports;
    wasmModule = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;
    wasm.__wbindgen_start();
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = module.ok && expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('kutup_crypto_wasm_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
