/* @ts-self-types="./kutup_chat_core.d.ts" */

/**
 * Browser-owned handle to one durable chat engine.
 */
export class WasmChatClient {
    static __wrap(ptr) {
        const obj = Object.create(WasmChatClient.prototype);
        obj.__wbg_ptr = ptr;
        WasmChatClientFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmChatClientFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmchatclient_free(ptr, 0);
    }
    /**
     * @param {string} peer
     * @returns {Promise<any>}
     */
    acceptContact(peer) {
        const ptr0 = passStringToWasm0(peer, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_acceptContact(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @param {string} envelope_id
     * @param {string} cursor
     * @param {string} send_id
     * @param {string} server_timestamp
     * @param {any} recipient
     * @param {any} envelope
     * @param {any} expected_sender
     * @returns {Promise<any>}
     */
    applyAnonymousMlsApplicationEnvelope(envelope_id, cursor, send_id, server_timestamp, recipient, envelope, expected_sender) {
        const ptr0 = passStringToWasm0(envelope_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(cursor, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(send_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(server_timestamp, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_applyAnonymousMlsApplicationEnvelope(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, recipient, envelope, expected_sender);
        return ret;
    }
    /**
     * @param {string} envelope_id
     * @param {string} cursor
     * @param {string} send_id
     * @param {Uint8Array} mls_group_id
     * @param {Uint8Array} commit
     * @param {any} expected_members
     * @param {Uint8Array} control_history_page
     * @returns {Promise<any>}
     */
    applyOrderedInboundMlsMembershipCommit(envelope_id, cursor, send_id, mls_group_id, commit, expected_members, control_history_page) {
        const ptr0 = passStringToWasm0(envelope_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(cursor, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(send_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passArray8ToWasm0(commit, wasm.__wbindgen_malloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passArray8ToWasm0(control_history_page, wasm.__wbindgen_malloc);
        const len5 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_applyOrderedInboundMlsMembershipCommit(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, expected_members, ptr5, len5);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {string} approved_at_seconds
     * @returns {Promise<any>}
     */
    approveMlsOwnerApprovalRequest(mls_group_id, approved_at_seconds) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(approved_at_seconds, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_approveMlsOwnerApprovalRequest(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        return ret;
    }
    /**
     * @param {string} peer
     * @returns {Promise<any>}
     */
    blockContact(peer) {
        const ptr0 = passStringToWasm0(peer, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_blockContact(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {any} new_set_certificate
     * @returns {Promise<any>}
     */
    buildMlsAuthorityCommitRequest(mls_group_id, new_set_certificate) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_buildMlsAuthorityCommitRequest(this.__wbg_ptr, ptr0, len0, new_set_certificate);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {any} quorum_certificate
     * @returns {Promise<any>}
     */
    buildMlsCloseCommitRequest(mls_group_id, quorum_certificate) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_buildMlsCloseCommitRequest(this.__wbg_ptr, ptr0, len0, quorum_certificate);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {any} quorum_certificate
     * @returns {Promise<any>}
     */
    buildMlsMembershipCommitRequest(mls_group_id, quorum_certificate) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_buildMlsMembershipCommitRequest(this.__wbg_ptr, ptr0, len0, quorum_certificate);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {any} quorum_certificate
     * @returns {Promise<any>}
     */
    buildMlsOwnerCommitRequest(mls_group_id, quorum_certificate) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_buildMlsOwnerCommitRequest(this.__wbg_ptr, ptr0, len0, quorum_certificate);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {any} quorum_certificate
     * @returns {Promise<any>}
     */
    buildMlsPolicyCommitRequest(mls_group_id, quorum_certificate) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_buildMlsPolicyCommitRequest(this.__wbg_ptr, ptr0, len0, quorum_certificate);
        return ret;
    }
    /**
     * @returns {Promise<any>}
     */
    contacts() {
        const ret = wasm.wasmchatclient_contacts(this.__wbg_ptr);
        return ret;
    }
    /**
     * @param {any} recipient
     * @param {string} send_id
     * @param {Uint8Array} capability
     * @param {any} devices
     * @param {Uint8Array} mls_ciphertext
     * @returns {Promise<any>}
     */
    createAnonymousMlsSubmission(recipient, send_id, capability, devices, mls_ciphertext) {
        const ptr0 = passStringToWasm0(send_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(capability, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(mls_ciphertext, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_createAnonymousMlsSubmission(this.__wbg_ptr, recipient, ptr0, len0, ptr1, len1, devices, ptr2, len2);
        return ret;
    }
    /**
     * @param {string} send_id
     * @param {string} conversation_id
     * @param {string} incarnation
     * @param {Uint8Array} mls_group_id
     * @param {Uint8Array} plaintext
     * @param {string} created_at_ms
     * @returns {Promise<any>}
     */
    createMlsApplicationMessage(send_id, conversation_id, incarnation, mls_group_id, plaintext, created_at_ms) {
        const ptr0 = passStringToWasm0(send_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(conversation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(incarnation, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(created_at_ms, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len5 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_createMlsApplicationMessage(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5);
        return ret;
    }
    /**
     * @param {string} send_id
     * @param {string} conversation_id
     * @param {string} incarnation
     * @param {Uint8Array} mls_group_id
     * @param {string} sent_at
     * @param {any} descriptor
     * @param {string} created_at_ms
     * @param {number | null} [expires_after_seconds]
     * @returns {Promise<any>}
     */
    createMlsAttachmentMessage(send_id, conversation_id, incarnation, mls_group_id, sent_at, descriptor, created_at_ms, expires_after_seconds) {
        const ptr0 = passStringToWasm0(send_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(conversation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(incarnation, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(sent_at, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(created_at_ms, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len5 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_createMlsAttachmentMessage(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, descriptor, ptr5, len5, isLikeNone(expires_after_seconds) ? Number.MAX_SAFE_INTEGER : (expires_after_seconds) >>> 0);
        return ret;
    }
    /**
     * @param {string} send_id
     * @param {string} conversation_id
     * @param {string} incarnation
     * @param {Uint8Array} mls_group_id
     * @param {string} sent_at
     * @param {string} created_at_ms
     * @param {number | null} [duration_seconds]
     * @returns {Promise<any>}
     */
    createMlsDisappearingTimer(send_id, conversation_id, incarnation, mls_group_id, sent_at, created_at_ms, duration_seconds) {
        const ptr0 = passStringToWasm0(send_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(conversation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(incarnation, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(sent_at, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(created_at_ms, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len5 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_createMlsDisappearingTimer(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, isLikeNone(duration_seconds) ? Number.MAX_SAFE_INTEGER : (duration_seconds) >>> 0);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {string} invited_epoch
     * @param {string} accepted_at_seconds
     * @returns {Promise<any>}
     */
    createMlsInvitationAcceptanceMessage(mls_group_id, invited_epoch, accepted_at_seconds) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(invited_epoch, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(accepted_at_seconds, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_createMlsInvitationAcceptanceMessage(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
        return ret;
    }
    /**
     * @param {string} send_id
     * @param {string} conversation_id
     * @param {string} incarnation
     * @param {Uint8Array} mls_group_id
     * @param {string} sent_at
     * @param {string} target_message_id
     * @param {string} operation
     * @param {string | null | undefined} replacement_text
     * @param {string} created_at_ms
     * @returns {Promise<any>}
     */
    createMlsMessageMutation(send_id, conversation_id, incarnation, mls_group_id, sent_at, target_message_id, operation, replacement_text, created_at_ms) {
        const ptr0 = passStringToWasm0(send_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(conversation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(incarnation, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(sent_at, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(target_message_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len5 = WASM_VECTOR_LEN;
        const ptr6 = passStringToWasm0(operation, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len6 = WASM_VECTOR_LEN;
        var ptr7 = isLikeNone(replacement_text) ? 0 : passStringToWasm0(replacement_text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len7 = WASM_VECTOR_LEN;
        const ptr8 = passStringToWasm0(created_at_ms, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len8 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_createMlsMessageMutation(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6, ptr7, len7, ptr8, len8);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @returns {Promise<any>}
     */
    createMlsOwnerApprovalRequestMessage(mls_group_id) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_createMlsOwnerApprovalRequestMessage(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {string} now_seconds
     * @returns {Promise<any>}
     */
    createMlsOwnerCandidateMessage(mls_group_id, now_seconds) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(now_seconds, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_createMlsOwnerCandidateMessage(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        return ret;
    }
    /**
     * @param {string} send_id
     * @param {string} conversation_id
     * @param {string} incarnation
     * @param {Uint8Array} mls_group_id
     * @param {string} sent_at
     * @param {string} target_message_id
     * @param {string} emoji
     * @param {boolean} active
     * @param {string} created_at_ms
     * @returns {Promise<any>}
     */
    createMlsReactionMessage(send_id, conversation_id, incarnation, mls_group_id, sent_at, target_message_id, emoji, active, created_at_ms) {
        const ptr0 = passStringToWasm0(send_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(conversation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(incarnation, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(sent_at, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(target_message_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len5 = WASM_VECTOR_LEN;
        const ptr6 = passStringToWasm0(emoji, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len6 = WASM_VECTOR_LEN;
        const ptr7 = passStringToWasm0(created_at_ms, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len7 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_createMlsReactionMessage(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6, active, ptr7, len7);
        return ret;
    }
    /**
     * @param {string} send_id
     * @param {string} conversation_id
     * @param {string} incarnation
     * @param {Uint8Array} mls_group_id
     * @param {string} sent_at
     * @param {string[]} message_ids
     * @param {string} state
     * @param {string} created_at_ms
     * @returns {Promise<any>}
     */
    createMlsReceiptMessage(send_id, conversation_id, incarnation, mls_group_id, sent_at, message_ids, state, created_at_ms) {
        const ptr0 = passStringToWasm0(send_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(conversation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(incarnation, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(sent_at, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passArrayJsValueToWasm0(message_ids, wasm.__wbindgen_malloc);
        const len5 = WASM_VECTOR_LEN;
        const ptr6 = passStringToWasm0(state, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len6 = WASM_VECTOR_LEN;
        const ptr7 = passStringToWasm0(created_at_ms, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len7 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_createMlsReceiptMessage(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6, ptr7, len7);
        return ret;
    }
    /**
     * @param {string} send_id
     * @param {string} conversation_id
     * @param {string} incarnation
     * @param {Uint8Array} mls_group_id
     * @param {string} sent_at
     * @param {string} text
     * @param {string} created_at_ms
     * @param {string | null} [reply_to]
     * @param {number | null} [expires_after_seconds]
     * @returns {Promise<any>}
     */
    createMlsTextMessage(send_id, conversation_id, incarnation, mls_group_id, sent_at, text, created_at_ms, reply_to, expires_after_seconds) {
        const ptr0 = passStringToWasm0(send_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(conversation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(incarnation, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(sent_at, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len5 = WASM_VECTOR_LEN;
        const ptr6 = passStringToWasm0(created_at_ms, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len6 = WASM_VECTOR_LEN;
        var ptr7 = isLikeNone(reply_to) ? 0 : passStringToWasm0(reply_to, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len7 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_createMlsTextMessage(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6, ptr7, len7, isLikeNone(expires_after_seconds) ? Number.MAX_SAFE_INTEGER : (expires_after_seconds) >>> 0);
        return ret;
    }
    /**
     * @param {string} send_id
     * @param {string} conversation_id
     * @param {string} incarnation
     * @param {Uint8Array} mls_group_id
     * @param {string} sent_at
     * @param {boolean} active
     * @param {string} created_at_ms
     * @returns {Promise<any>}
     */
    createMlsTypingMessage(send_id, conversation_id, incarnation, mls_group_id, sent_at, active, created_at_ms) {
        const ptr0 = passStringToWasm0(send_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(conversation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(incarnation, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(sent_at, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(created_at_ms, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len5 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_createMlsTypingMessage(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, active, ptr5, len5);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {Uint8Array} ciphertext
     * @param {any} expected_sender
     * @returns {Promise<any>}
     */
    decryptMlsApplicationMessage(mls_group_id, ciphertext, expected_sender) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_decryptMlsApplicationMessage(this.__wbg_ptr, ptr0, len0, ptr1, len1, expected_sender);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {string} conversation_id
     * @param {string} incarnation
     * @param {any} recipient
     * @returns {Promise<any>}
     */
    deriveMlsDeliveryCapability(mls_group_id, conversation_id, incarnation, recipient) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(conversation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(incarnation, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_deriveMlsDeliveryCapability(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, recipient);
        return ret;
    }
    /**
     * @returns {number}
     */
    get deviceId() {
        const ret = wasm.wasmchatclient_deviceId(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {string} now_seconds
     * @returns {Promise<any>}
     */
    ensureMlsOwnerCandidate(mls_group_id, now_seconds) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(now_seconds, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_ensureMlsOwnerCandidate(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        return ret;
    }
    /**
     * @param {any} recipient
     * @param {string} conversation_id
     * @param {string} incarnation
     * @param {string} now_seconds
     * @returns {Promise<any>}
     */
    fetchVerifiedIdentifiedMlsKeyPackages(recipient, conversation_id, incarnation, now_seconds) {
        const ptr0 = passStringToWasm0(conversation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(incarnation, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(now_seconds, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_fetchVerifiedIdentifiedMlsKeyPackages(this.__wbg_ptr, recipient, ptr0, len0, ptr1, len1, ptr2, len2);
        return ret;
    }
    /**
     * @param {any} recipient
     * @param {Uint8Array} capability
     * @param {string} now_seconds
     * @returns {Promise<any>}
     */
    fetchVerifiedMlsKeyPackages(recipient, capability, now_seconds) {
        const ptr0 = passArray8ToWasm0(capability, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(now_seconds, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_fetchVerifiedMlsKeyPackages(this.__wbg_ptr, recipient, ptr0, len0, ptr1, len1);
        return ret;
    }
    /**
     * @param {string} domain
     * @returns {Promise<any>}
     */
    fetchVerifiedMlsOrderingPolicy(domain) {
        const ptr0 = passStringToWasm0(domain, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_fetchVerifiedMlsOrderingPolicy(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @param {string} domain
     * @returns {Promise<any>}
     */
    fetchVerifiedMlsOrderingPolicyDetails(domain) {
        const ptr0 = passStringToWasm0(domain, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_fetchVerifiedMlsOrderingPolicyDetails(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {any} acknowledgement
     * @returns {Promise<any>}
     */
    finalizeMlsAuthorityChange(mls_group_id, acknowledgement) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_finalizeMlsAuthorityChange(this.__wbg_ptr, ptr0, len0, acknowledgement);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {any} acknowledgement
     * @returns {Promise<any>}
     */
    finalizeMlsClose(mls_group_id, acknowledgement) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_finalizeMlsClose(this.__wbg_ptr, ptr0, len0, acknowledgement);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {any} acknowledgement
     * @returns {Promise<any>}
     */
    finalizeMlsGroupRecovery(mls_group_id, acknowledgement) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_finalizeMlsGroupRecovery(this.__wbg_ptr, ptr0, len0, acknowledgement);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {any} acknowledgement
     * @returns {Promise<any>}
     */
    finalizeMlsMembershipChange(mls_group_id, acknowledgement) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_finalizeMlsMembershipChange(this.__wbg_ptr, ptr0, len0, acknowledgement);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {any} acknowledgement
     * @returns {Promise<any>}
     */
    finalizeMlsOwnerChange(mls_group_id, acknowledgement) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_finalizeMlsOwnerChange(this.__wbg_ptr, ptr0, len0, acknowledgement);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {any} acknowledgement
     * @returns {Promise<any>}
     */
    finalizeMlsPolicyChange(mls_group_id, acknowledgement) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_finalizeMlsPolicyChange(this.__wbg_ptr, ptr0, len0, acknowledgement);
        return ret;
    }
    /**
     * @param {string} manifest_version
     * @param {string} now_seconds
     * @param {string} expires_at_seconds
     * @returns {Promise<any>}
     */
    generateMlsKeyPackage(manifest_version, now_seconds, expires_at_seconds) {
        const ptr0 = passStringToWasm0(manifest_version, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(now_seconds, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(expires_at_seconds, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_generateMlsKeyPackage(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
        return ret;
    }
    /**
     * @returns {Promise<any>}
     */
    history() {
        const ret = wasm.wasmchatclient_history(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {Promise<any>}
     */
    inboundAttention() {
        const ret = wasm.wasmchatclient_inboundAttention(this.__wbg_ptr);
        return ret;
    }
    /**
     * @param {any} recipient
     * @param {string} send_id
     * @param {any} envelope
     * @returns {Promise<any>}
     */
    inspectAnonymousMlsApplicationEnvelope(recipient, send_id, envelope) {
        const ptr0 = passStringToWasm0(send_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_inspectAnonymousMlsApplicationEnvelope(this.__wbg_ptr, recipient, ptr0, len0, envelope);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {Uint8Array} commit
     * @returns {Promise<any>}
     */
    inspectInboundMlsCommit(mls_group_id, commit) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(commit, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_inspectInboundMlsCommit(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {Uint8Array} welcome
     * @returns {Promise<any>}
     */
    inspectMlsWelcome(mls_group_id, welcome) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(welcome, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_inspectMlsWelcome(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        return ret;
    }
    /**
     * @param {string} envelope_id
     * @param {string} cursor
     * @param {string} send_id
     * @param {Uint8Array} mls_group_id
     * @param {Uint8Array} welcome
     * @param {any} expected_members
     * @param {any} recovery
     * @returns {Promise<any>}
     */
    joinMlsFromRecoveryWelcome(envelope_id, cursor, send_id, mls_group_id, welcome, expected_members, recovery) {
        const ptr0 = passStringToWasm0(envelope_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(cursor, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(send_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passArray8ToWasm0(welcome, wasm.__wbindgen_malloc);
        const len4 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_joinMlsFromRecoveryWelcome(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, expected_members, recovery);
        return ret;
    }
    /**
     * @param {string} envelope_id
     * @param {string} cursor
     * @param {string} send_id
     * @param {Uint8Array} mls_group_id
     * @param {Uint8Array} welcome
     * @param {any} expected_members
     * @param {any} history_pages
     * @returns {Promise<any>}
     */
    joinMlsFromWelcomeWithControlHistory(envelope_id, cursor, send_id, mls_group_id, welcome, expected_members, history_pages) {
        const ptr0 = passStringToWasm0(envelope_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(cursor, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(send_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passArray8ToWasm0(welcome, wasm.__wbindgen_malloc);
        const len4 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_joinMlsFromWelcomeWithControlHistory(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, expected_members, history_pages);
        return ret;
    }
    /**
     * @returns {Promise<any>}
     */
    localMlsConversations() {
        const ret = wasm.wasmchatclient_localMlsConversations(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {Promise<any>}
     */
    localMlsIncarnationHistory() {
        const ret = wasm.wasmchatclient_localMlsIncarnationHistory(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {Promise<any>}
     */
    maintainPrekeys() {
        const ret = wasm.wasmchatclient_maintainPrekeys(this.__wbg_ptr);
        return ret;
    }
    /**
     * @param {string} send_id
     * @returns {Promise<void>}
     */
    markMlsApplicationDelivered(send_id) {
        const ptr0 = passStringToWasm0(send_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_markMlsApplicationDelivered(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @param {string} send_id
     * @param {string} recipient
     * @param {boolean} deduplicated
     * @returns {Promise<any>}
     */
    markMlsApplicationRecipientDelivered(send_id, recipient, deduplicated) {
        const ptr0 = passStringToWasm0(send_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(recipient, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_markMlsApplicationRecipientDelivered(this.__wbg_ptr, ptr0, len0, ptr1, len1, deduplicated);
        return ret;
    }
    /**
     * @param {string} conversation_id
     * @param {string} genesis_hash
     * @returns {Promise<any>}
     */
    markMlsGroupGenesisPublished(conversation_id, genesis_hash) {
        const ptr0 = passStringToWasm0(conversation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(genesis_hash, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_markMlsGroupGenesisPublished(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        return ret;
    }
    /**
     * @param {string} peer
     * @returns {Promise<string>}
     */
    mediaDeliveryCapability(peer) {
        const ptr0 = passStringToWasm0(peer, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_mediaDeliveryCapability(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {string} commit_hash
     * @returns {Promise<any>}
     */
    mergePendingMlsCommit(mls_group_id, commit_hash) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(commit_hash, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_mergePendingMlsCommit(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @returns {Promise<boolean>}
     */
    mlsCloseHasOwnerQuorum(mls_group_id) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_mlsCloseHasOwnerQuorum(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @returns {Promise<any>}
     */
    mlsGroupControlCredential(mls_group_id) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_mlsGroupControlCredential(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @returns {Promise<any>}
     */
    mlsGroupDevices(mls_group_id) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_mlsGroupDevices(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @returns {Promise<any>}
     */
    mlsGroupOwnerCredential(mls_group_id) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_mlsGroupOwnerCredential(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @returns {Promise<any>}
     */
    mlsGroupState(mls_group_id) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_mlsGroupState(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @returns {Promise<any>}
     */
    mlsOwnerCandidates(mls_group_id) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_mlsOwnerCandidates(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @returns {Promise<boolean>}
     */
    mlsOwnerChangeHasQuorum(mls_group_id) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_mlsOwnerChangeHasQuorum(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @returns {Promise<boolean>}
     */
    mlsPolicyChangeHasOwnerQuorum(mls_group_id) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_mlsPolicyChangeHasOwnerQuorum(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @returns {Promise<boolean>}
     */
    mlsRecoveryHasOwnerQuorum(mls_group_id) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_mlsRecoveryHasOwnerQuorum(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @param {string} send_id
     * @returns {Promise<any>}
     */
    noteMlsApplicationAttempt(send_id) {
        const ptr0 = passStringToWasm0(send_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_noteMlsApplicationAttempt(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @param {string} send_id
     * @param {string} recipient
     * @returns {Promise<any>}
     */
    noteMlsApplicationDeliveryAttempt(send_id, recipient) {
        const ptr0 = passStringToWasm0(send_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(recipient, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_noteMlsApplicationDeliveryAttempt(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        return ret;
    }
    /**
     * Open or restart-safely register the local device, then publish its
     * account-signed manifest. The database name must be account scoped.
     * @param {string} database_name
     * @param {string} user
     * @param {string} server_name
     * @param {boolean} sealed_sender_enabled
     * @param {Uint8Array} master_key
     * @param {KutupChatTransport} transport
     * @returns {Promise<WasmChatClient>}
     */
    static open(database_name, user, server_name, sealed_sender_enabled, master_key, transport) {
        const ptr0 = passStringToWasm0(database_name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(user, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(server_name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(master_key, wasm.__wbindgen_malloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_open(ptr0, len0, ptr1, len1, ptr2, len2, sealed_sender_enabled, ptr3, len3, transport);
        return ret;
    }
    /**
     * @param {any} recipient
     * @param {string} send_id
     * @param {any} envelope
     * @returns {Promise<Uint8Array>}
     */
    openAnonymousMlsEnvelope(recipient, send_id, envelope) {
        const ptr0 = passStringToWasm0(send_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_openAnonymousMlsEnvelope(this.__wbg_ptr, recipient, ptr0, len0, envelope);
        return ret;
    }
    /**
     * @returns {Promise<any>}
     */
    pendingMlsApplicationMessages() {
        const ret = wasm.wasmchatclient_pendingMlsApplicationMessages(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {Promise<any>}
     */
    pendingMlsAuthorityChanges() {
        const ret = wasm.wasmchatclient_pendingMlsAuthorityChanges(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {Promise<any>}
     */
    pendingMlsCloses() {
        const ret = wasm.wasmchatclient_pendingMlsCloses(this.__wbg_ptr);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @returns {Promise<any>}
     */
    pendingMlsCommit(mls_group_id) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_pendingMlsCommit(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @returns {Promise<any>}
     */
    pendingMlsMembershipChanges() {
        const ret = wasm.wasmchatclient_pendingMlsMembershipChanges(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {Promise<any>}
     */
    pendingMlsOwnerApprovalRequests() {
        const ret = wasm.wasmchatclient_pendingMlsOwnerApprovalRequests(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {Promise<any>}
     */
    pendingMlsOwnerChanges() {
        const ret = wasm.wasmchatclient_pendingMlsOwnerChanges(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {Promise<any>}
     */
    pendingMlsPolicyChanges() {
        const ret = wasm.wasmchatclient_pendingMlsPolicyChanges(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {Promise<any>}
     */
    pendingMlsRecoveries() {
        const ret = wasm.wasmchatclient_pendingMlsRecoveries(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {Promise<number>}
     */
    pendingSendCount() {
        const ret = wasm.wasmchatclient_pendingSendCount(this.__wbg_ptr);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {string} proposal_id
     * @param {any} authority_policies
     * @param {string} now_seconds
     * @returns {Promise<any>}
     */
    prepareMlsAuthorityChange(mls_group_id, proposal_id, authority_policies, now_seconds) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(proposal_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(now_seconds, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_prepareMlsAuthorityChange(this.__wbg_ptr, ptr0, len0, ptr1, len1, authority_policies, ptr2, len2);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {string} proposal_id
     * @param {any} next_policy
     * @param {string} now_seconds
     * @returns {Promise<any>}
     */
    prepareMlsAuthorizationPolicyChange(mls_group_id, proposal_id, next_policy, now_seconds) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(proposal_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(now_seconds, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_prepareMlsAuthorizationPolicyChange(this.__wbg_ptr, ptr0, len0, ptr1, len1, next_policy, ptr2, len2);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {string} proposal_id
     * @param {string} now_seconds
     * @returns {Promise<any>}
     */
    prepareMlsClose(mls_group_id, proposal_id, now_seconds) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(proposal_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(now_seconds, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_prepareMlsClose(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {string} proposal_id
     * @param {any} next_policy
     * @param {string} now_seconds
     * @returns {Promise<any>}
     */
    prepareMlsCryptographicPolicyChange(mls_group_id, proposal_id, next_policy, now_seconds) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(proposal_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(now_seconds, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_prepareMlsCryptographicPolicyChange(this.__wbg_ptr, ptr0, len0, ptr1, len1, next_policy, ptr2, len2);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {string} proposal_id
     * @param {any} additions
     * @param {any} removed_device_ids
     * @param {string} now_seconds
     * @returns {Promise<any>}
     */
    prepareMlsDeviceSync(mls_group_id, proposal_id, additions, removed_device_ids, now_seconds) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(proposal_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(now_seconds, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_prepareMlsDeviceSync(this.__wbg_ptr, ptr0, len0, ptr1, len1, additions, removed_device_ids, ptr2, len2);
        return ret;
    }
    /**
     * @param {string} conversation_id
     * @param {Uint8Array} mls_group_id
     * @param {any} creator
     * @param {any} authority_policies
     * @param {string} created_at_seconds
     * @returns {Promise<any>}
     */
    prepareMlsGroupGenesis(conversation_id, mls_group_id, creator, authority_policies, created_at_seconds) {
        const ptr0 = passStringToWasm0(conversation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(created_at_seconds, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_prepareMlsGroupGenesis(this.__wbg_ptr, ptr0, len0, ptr1, len1, creator, authority_policies, ptr2, len2);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {Uint8Array} new_mls_group_id
     * @param {string} proposal_id
     * @param {any} authority_policies
     * @param {any} additions
     * @param {string} created_at_seconds
     * @returns {Promise<any>}
     */
    prepareMlsGroupRecovery(mls_group_id, new_mls_group_id, proposal_id, authority_policies, additions, created_at_seconds) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(new_mls_group_id, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(proposal_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(created_at_seconds, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_prepareMlsGroupRecovery(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, authority_policies, additions, ptr3, len3);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {string} proposal_id
     * @param {any} next_roster
     * @param {any} additions
     * @param {string} now_seconds
     * @returns {Promise<any>}
     */
    prepareMlsMembershipChange(mls_group_id, proposal_id, next_roster, additions, now_seconds) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(proposal_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(now_seconds, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_prepareMlsMembershipChange(this.__wbg_ptr, ptr0, len0, ptr1, len1, next_roster, additions, ptr2, len2);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {string} proposal_id
     * @param {any} next_roster
     * @param {any} next_owner_set
     * @param {string} now_seconds
     * @returns {Promise<any>}
     */
    prepareMlsOwnerChange(mls_group_id, proposal_id, next_roster, next_owner_set, now_seconds) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(proposal_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(now_seconds, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_prepareMlsOwnerChange(this.__wbg_ptr, ptr0, len0, ptr1, len1, next_roster, next_owner_set, ptr2, len2);
        return ret;
    }
    /**
     * @param {string} envelope_id
     * @returns {Promise<any>}
     */
    processedMlsApplicationEnvelope(envelope_id) {
        const ptr0 = passStringToWasm0(envelope_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_processedMlsApplicationEnvelope(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @param {string} envelope_id
     * @returns {Promise<any>}
     */
    processedMlsControlEnvelope(envelope_id) {
        const ptr0 = passStringToWasm0(envelope_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_processedMlsControlEnvelope(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @returns {Promise<any>}
     */
    profile() {
        const ret = wasm.wasmchatclient_profile(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {Promise<any>}
     */
    profiles() {
        const ret = wasm.wasmchatclient_profiles(this.__wbg_ptr);
        return ret;
    }
    /**
     * @param {string} now_ms
     * @returns {Promise<any>}
     */
    purgeExpiredMessages(now_ms) {
        const ptr0 = passStringToWasm0(now_ms, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_purgeExpiredMessages(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @param {string} id
     * @returns {Promise<void>}
     */
    quarantineInbound(id) {
        const ptr0 = passStringToWasm0(id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_quarantineInbound(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * Flush crash-surviving sends, drain/decrypt/ack the mailbox, and return
     * the new receive report. WebSocket notifications call this same source-
     * of-truth reconciliation path.
     * @returns {Promise<any>}
     */
    reconcile() {
        const ret = wasm.wasmchatclient_reconcile(this.__wbg_ptr);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {any} certificate
     * @returns {Promise<any>}
     */
    recordMlsAuthorityPreviousQuorum(mls_group_id, certificate) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_recordMlsAuthorityPreviousQuorum(this.__wbg_ptr, ptr0, len0, certificate);
        return ret;
    }
    /**
     * @param {string} peer
     * @returns {Promise<any>}
     */
    rejectContact(peer) {
        const ptr0 = passStringToWasm0(peer, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_rejectContact(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @returns {Promise<void>}
     */
    rejectMlsOwnerApprovalRequest(mls_group_id) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_rejectMlsOwnerApprovalRequest(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {string} commit_hash
     * @returns {Promise<void>}
     */
    rejectPendingMlsCommit(mls_group_id, commit_hash) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(commit_hash, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_rejectPendingMlsCommit(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        return ret;
    }
    /**
     * @param {string} id
     * @returns {Promise<void>}
     */
    resolveDeadLetter(id) {
        const ptr0 = passStringToWasm0(id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_resolveDeadLetter(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @param {any} claimed_sender
     * @returns {Promise<any>}
     */
    resolveMlsSenderClaim(claimed_sender) {
        const ret = wasm.wasmchatclient_resolveMlsSenderClaim(this.__wbg_ptr, claimed_sender);
        return ret;
    }
    /**
     * @param {any} claimed_members
     * @returns {Promise<any>}
     */
    resolveMlsWelcomeClaims(claimed_members) {
        const ret = wasm.wasmchatclient_resolveMlsWelcomeClaims(this.__wbg_ptr, claimed_members);
        return ret;
    }
    /**
     * @param {number} device_id
     * @returns {Promise<any>}
     */
    revokeManifestDevice(device_id) {
        const ret = wasm.wasmchatclient_revokeManifestDevice(this.__wbg_ptr, device_id);
        return ret;
    }
    /**
     * @param {string} peer
     * @returns {Promise<any>}
     */
    safetyNumber(peer) {
        const ptr0 = passStringToWasm0(peer, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_safetyNumber(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @param {string} send_id
     * @param {string} peer
     * @param {string} sent_at
     * @param {any} descriptor
     * @param {number | null} [expires_after_seconds]
     * @returns {Promise<any>}
     */
    sendAttachment(send_id, peer, sent_at, descriptor, expires_after_seconds) {
        const ptr0 = passStringToWasm0(send_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(peer, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(sent_at, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_sendAttachment(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, descriptor, isLikeNone(expires_after_seconds) ? Number.MAX_SAFE_INTEGER : (expires_after_seconds) >>> 0);
        return ret;
    }
    /**
     * @param {string} send_id
     * @param {string} peer
     * @param {string} sent_at
     * @param {number | null} [duration_seconds]
     * @returns {Promise<any>}
     */
    sendDisappearingTimer(send_id, peer, sent_at, duration_seconds) {
        const ptr0 = passStringToWasm0(send_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(peer, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(sent_at, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_sendDisappearingTimer(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, isLikeNone(duration_seconds) ? Number.MAX_SAFE_INTEGER : (duration_seconds) >>> 0);
        return ret;
    }
    /**
     * @param {string} send_id
     * @param {string} peer
     * @param {string} sent_at
     * @param {string} target_message_id
     * @param {string} operation
     * @param {string | null} [replacement_text]
     * @returns {Promise<any>}
     */
    sendMessageMutation(send_id, peer, sent_at, target_message_id, operation, replacement_text) {
        const ptr0 = passStringToWasm0(send_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(peer, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(sent_at, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(target_message_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(operation, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        var ptr5 = isLikeNone(replacement_text) ? 0 : passStringToWasm0(replacement_text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len5 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_sendMessageMutation(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5);
        return ret;
    }
    /**
     * @param {string} send_id
     * @param {string} peer
     * @param {string} sent_at
     * @param {string} target_message_id
     * @param {string} emoji
     * @param {boolean} active
     * @returns {Promise<any>}
     */
    sendReaction(send_id, peer, sent_at, target_message_id, emoji, active) {
        const ptr0 = passStringToWasm0(send_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(peer, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(sent_at, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(target_message_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(emoji, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_sendReaction(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, active);
        return ret;
    }
    /**
     * @param {string} send_id
     * @param {string} peer
     * @param {string} sent_at
     * @param {string[]} message_ids
     * @param {string} state
     * @returns {Promise<any>}
     */
    sendReceipt(send_id, peer, sent_at, message_ids, state) {
        const ptr0 = passStringToWasm0(send_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(peer, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(sent_at, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArrayJsValueToWasm0(message_ids, wasm.__wbindgen_malloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(state, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_sendReceipt(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
        return ret;
    }
    /**
     * @param {string} send_id
     * @param {string} peer
     * @param {string} sent_at
     * @param {string} text
     * @param {string | null} [reply_to]
     * @param {number | null} [expires_after_seconds]
     * @returns {Promise<any>}
     */
    sendText(send_id, peer, sent_at, text, reply_to, expires_after_seconds) {
        const ptr0 = passStringToWasm0(send_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(peer, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(sent_at, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(text, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        var ptr4 = isLikeNone(reply_to) ? 0 : passStringToWasm0(reply_to, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len4 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_sendText(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, isLikeNone(expires_after_seconds) ? Number.MAX_SAFE_INTEGER : (expires_after_seconds) >>> 0);
        return ret;
    }
    /**
     * @param {string} send_id
     * @param {string} peer
     * @param {string} sent_at
     * @param {boolean} active
     * @returns {Promise<any>}
     */
    sendTyping(send_id, peer, sent_at, active) {
        const ptr0 = passStringToWasm0(send_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(peer, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(sent_at, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_sendTyping(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, active);
        return ret;
    }
    /**
     * @param {string} display_name
     * @param {string | null} [avatar]
     * @param {string | null} [avatar_content_type]
     * @returns {Promise<any>}
     */
    setProfile(display_name, avatar, avatar_content_type) {
        const ptr0 = passStringToWasm0(display_name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        var ptr1 = isLikeNone(avatar) ? 0 : passStringToWasm0(avatar, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len1 = WASM_VECTOR_LEN;
        var ptr2 = isLikeNone(avatar_content_type) ? 0 : passStringToWasm0(avatar_content_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_setProfile(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
        return ret;
    }
    /**
     * @param {Uint8Array} mls_group_id
     * @param {string} conversation_id
     * @param {string} incarnation
     * @param {string} proposal_id
     * @param {string} base_epoch
     * @param {number} action_type
     * @param {Uint8Array} encrypted_payload
     * @param {string} created_at_seconds
     * @returns {Promise<any>}
     */
    signMlsControlProposal(mls_group_id, conversation_id, incarnation, proposal_id, base_epoch, action_type, encrypted_payload, created_at_seconds) {
        const ptr0 = passArray8ToWasm0(mls_group_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(conversation_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(incarnation, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(proposal_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(base_epoch, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passArray8ToWasm0(encrypted_payload, wasm.__wbindgen_malloc);
        const len5 = WASM_VECTOR_LEN;
        const ptr6 = passStringToWasm0(created_at_seconds, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len6 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_signMlsControlProposal(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, action_type, ptr5, len5, ptr6, len6);
        return ret;
    }
    /**
     * @param {string} send_id
     * @param {any} recipient
     * @param {Uint8Array} capability
     * @param {any} packages
     * @param {string} now_seconds
     * @returns {Promise<any>}
     */
    stageMlsApplicationDelivery(send_id, recipient, capability, packages, now_seconds) {
        const ptr0 = passStringToWasm0(send_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(capability, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(now_seconds, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_stageMlsApplicationDelivery(this.__wbg_ptr, ptr0, len0, recipient, ptr1, len1, packages, ptr2, len2);
        return ret;
    }
    /**
     * @param {string} send_id
     * @param {string} sent_at
     * @param {any} conversation
     * @param {string} target_message_id
     * @param {string} started_at_ms
     * @returns {Promise<any>}
     */
    startDisappearingExpiry(send_id, sent_at, conversation, target_message_id, started_at_ms) {
        const ptr0 = passStringToWasm0(send_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(sent_at, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(target_message_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(started_at_ms, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_startDisappearingExpiry(this.__wbg_ptr, ptr0, len0, ptr1, len1, conversation, ptr2, len2, ptr3, len3);
        return ret;
    }
    /**
     * @returns {Promise<any>}
     */
    syncManifest() {
        const ret = wasm.wasmchatclient_syncManifest(this.__wbg_ptr);
        return ret;
    }
    /**
     * @param {string} peer
     * @returns {Promise<any>}
     */
    unblockContact(peer) {
        const ptr0 = passStringToWasm0(peer, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_unblockContact(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * @param {string} peer
     * @param {string} scanned_payload
     * @returns {Promise<any>}
     */
    verifySafetyNumber(peer, scanned_payload) {
        const ptr0 = passStringToWasm0(peer, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(scanned_payload, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmchatclient_verifySafetyNumber(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        return ret;
    }
}
if (Symbol.dispose) WasmChatClient.prototype[Symbol.dispose] = WasmChatClient.prototype.free;
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg_Error_92b29b0548f8b746: function(arg0, arg1) {
            const ret = Error(getStringFromWasm0(arg0, arg1));
            return ret;
        },
        __wbg_Number_9a4e0ecb0fa16705: function(arg0) {
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
        __wbg___wbindgen_bigint_get_as_i64_d968e41184ae354f: function(arg0, arg1) {
            const v = arg1;
            const ret = typeof(v) === 'bigint' ? v : undefined;
            getDataViewMemory0().setBigInt64(arg0 + 8 * 1, isLikeNone(ret) ? BigInt(0) : ret, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, !isLikeNone(ret), true);
        },
        __wbg___wbindgen_boolean_get_fa956cfa2d1bd751: function(arg0) {
            const v = arg0;
            const ret = typeof(v) === 'boolean' ? v : undefined;
            return isLikeNone(ret) ? 0xFFFFFF : ret ? 1 : 0;
        },
        __wbg___wbindgen_debug_string_c25d447a39f5578f: function(arg0, arg1) {
            const ret = debugString(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_in_aca499c5de7ff5e5: function(arg0, arg1) {
            const ret = arg0 in arg1;
            return ret;
        },
        __wbg___wbindgen_is_bigint_2f76dc55065b4273: function(arg0) {
            const ret = typeof(arg0) === 'bigint';
            return ret;
        },
        __wbg___wbindgen_is_function_1ff95bcc5517c252: function(arg0) {
            const ret = typeof(arg0) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_null_ea9085d691f535d3: function(arg0) {
            const ret = arg0 === null;
            return ret;
        },
        __wbg___wbindgen_is_object_a27215656b807791: function(arg0) {
            const val = arg0;
            const ret = typeof(val) === 'object' && val !== null;
            return ret;
        },
        __wbg___wbindgen_is_string_ea5e6cc2e4141dfe: function(arg0) {
            const ret = typeof(arg0) === 'string';
            return ret;
        },
        __wbg___wbindgen_is_undefined_c05833b95a3cf397: function(arg0) {
            const ret = arg0 === undefined;
            return ret;
        },
        __wbg___wbindgen_jsval_eq_e659fcf7b0e32763: function(arg0, arg1) {
            const ret = arg0 === arg1;
            return ret;
        },
        __wbg___wbindgen_jsval_loose_eq_db4c3b15f63fc170: function(arg0, arg1) {
            const ret = arg0 == arg1;
            return ret;
        },
        __wbg___wbindgen_number_get_394265ed1e1b84ee: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'number' ? obj : undefined;
            getDataViewMemory0().setFloat64(arg0 + 8 * 1, isLikeNone(ret) ? 0 : ret, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, !isLikeNone(ret), true);
        },
        __wbg___wbindgen_string_get_b0ca35b86a603356: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'string' ? obj : undefined;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_throw_344f42d3211c4765: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg__wbg_cb_unref_fffb441def202758: function(arg0) {
            arg0._wbg_cb_unref();
        },
        __wbg_abort_8a4b90d8b05efcf8: function() { return handleError(function (arg0) {
            arg0.abort();
        }, arguments); },
        __wbg_ackMessages_9dee86a147cd1453: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.ackMessages(arg1 >>> 0, arg2);
            return ret;
        }, arguments); },
        __wbg_advance_185912bf8a08ffee: function() { return handleError(function (arg0, arg1) {
            arg0.advance(arg1 >>> 0);
        }, arguments); },
        __wbg_call_8a2dd23819f8a60a: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.call(arg1);
            return ret;
        }, arguments); },
        __wbg_call_a6e5c5dce5018821: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.call(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_close_4c3686e8e8c6d353: function(arg0) {
            arg0.close();
        },
        __wbg_commit_31c8ddfbb2d25960: function() { return handleError(function (arg0) {
            arg0.commit();
        }, arguments); },
        __wbg_continue_4752ac1d1527ace0: function() { return handleError(function (arg0, arg1) {
            arg0.continue(arg1);
        }, arguments); },
        __wbg_continue_97ad9c8cd4cf7f86: function() { return handleError(function (arg0) {
            arg0.continue();
        }, arguments); },
        __wbg_createIndex_103467368f726782: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4) {
            const ret = arg0.createIndex(getStringFromWasm0(arg1, arg2), arg3, arg4);
            return ret;
        }, arguments); },
        __wbg_createObjectStore_c7a1db4a996dc8ac: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            const ret = arg0.createObjectStore(getStringFromWasm0(arg1, arg2), arg3);
            return ret;
        }, arguments); },
        __wbg_crypto_38df2bab126b63dc: function(arg0) {
            const ret = arg0.crypto;
            return ret;
        },
        __wbg_deleteIndex_d546810d7db51b0d: function() { return handleError(function (arg0, arg1, arg2) {
            arg0.deleteIndex(getStringFromWasm0(arg1, arg2));
        }, arguments); },
        __wbg_deleteObjectStore_a543f5ea070cb60a: function() { return handleError(function (arg0, arg1, arg2) {
            arg0.deleteObjectStore(getStringFromWasm0(arg1, arg2));
        }, arguments); },
        __wbg_delete_e7e50168de5ef96e: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.delete(arg1);
            return ret;
        }, arguments); },
        __wbg_done_89b2b13e91a60321: function(arg0) {
            const ret = arg0.done;
            return ret;
        },
        __wbg_drainMailbox_4d9235768e78961d: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            const ret = arg0.drainMailbox(arg1 >>> 0, arg2, arg3 >>> 0);
            return ret;
        }, arguments); },
        __wbg_entries_015dc610cd81ede0: function(arg0) {
            const ret = Object.entries(arg0);
            return ret;
        },
        __wbg_error_5b02424faf301d7c: function(arg0) {
            const ret = arg0.error;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_error_becd7e1fe6ce0623: function() { return handleError(function (arg0) {
            const ret = arg0.error;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        }, arguments); },
        __wbg_fetchAnonymousMlsKeyPackages_ea6ba7fbfb2bb57b: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.fetchAnonymousMlsKeyPackages(arg1);
            return ret;
        }, arguments); },
        __wbg_fetchBundles_52a4971f8780838f: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.fetchBundles(getStringFromWasm0(arg1, arg2));
            return ret;
        }, arguments); },
        __wbg_fetchIdentifiedMlsKeyPackages_574676305747d15e: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.fetchIdentifiedMlsKeyPackages(arg1);
            return ret;
        }, arguments); },
        __wbg_fetchManifestHistory_6fb01805b9c46a3f: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) {
            const ret = arg0.fetchManifestHistory(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4), getStringFromWasm0(arg5, arg6), getStringFromWasm0(arg7, arg8));
            return ret;
        }, arguments); },
        __wbg_fetchManifest_5d1524c4fcb8c353: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.fetchManifest(getStringFromWasm0(arg1, arg2));
            return ret;
        }, arguments); },
        __wbg_fetchMlsOrderingPolicy_64b05204b8fbe6bf: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.fetchMlsOrderingPolicy(getStringFromWasm0(arg1, arg2));
            return ret;
        }, arguments); },
        __wbg_fetchOwnProfile_c6e0fd1661ab2738: function() { return handleError(function (arg0) {
            const ret = arg0.fetchOwnProfile();
            return ret;
        }, arguments); },
        __wbg_fetchProfile_375be745d58290a1: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4, arg5, arg6) {
            const ret = arg0.fetchProfile(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4), getStringFromWasm0(arg5, arg6));
            return ret;
        }, arguments); },
        __wbg_fetchSealedBundles_85aae3f13e8164f3: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4) {
            const ret = arg0.fetchSealedBundles(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4));
            return ret;
        }, arguments); },
        __wbg_fetchSealedSenderPolicy_493c889fb38dd978: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.fetchSealedSenderPolicy(getStringFromWasm0(arg1, arg2));
            return ret;
        }, arguments); },
        __wbg_fetchSenderCertificate_212e5b81314a1725: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.fetchSenderCertificate(arg1 >>> 0);
            return ret;
        }, arguments); },
        __wbg_fetchSyncBundles_bf11c27357eaf25d: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            const ret = arg0.fetchSyncBundles(getStringFromWasm0(arg1, arg2), arg3 >>> 0);
            return ret;
        }, arguments); },
        __wbg_from_13e323c65fc8f464: function(arg0) {
            const ret = Array.from(arg0);
            return ret;
        },
        __wbg_getAll_0875ca0ac8b3f52c: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.getAll(arg1);
            return ret;
        }, arguments); },
        __wbg_getAll_718890feb1283a7d: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.getAll(arg1, arg2 >>> 0);
            return ret;
        }, arguments); },
        __wbg_getAll_b31fdebb43579f13: function() { return handleError(function (arg0) {
            const ret = arg0.getAll();
            return ret;
        }, arguments); },
        __wbg_getKey_875444ea8895c8fb: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.getKey(arg1);
            return ret;
        }, arguments); },
        __wbg_getRandomValues_3f44b700395062e5: function() { return handleError(function (arg0, arg1) {
            globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
        }, arguments); },
        __wbg_getRandomValues_c44a50d8cfdaebeb: function() { return handleError(function (arg0, arg1) {
            arg0.getRandomValues(arg1);
        }, arguments); },
        __wbg_get_4771b0fab98477d2: function(arg0, arg1, arg2) {
            const ret = arg1[arg2 >>> 0];
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_get_507a50627bffa49b: function(arg0, arg1) {
            const ret = arg0[arg1 >>> 0];
            return ret;
        },
        __wbg_get_78f252d074a84d0b: function() { return handleError(function (arg0, arg1) {
            const ret = Reflect.get(arg0, arg1);
            return ret;
        }, arguments); },
        __wbg_get_c7eb1f358a7654df: function() { return handleError(function (arg0, arg1) {
            const ret = Reflect.get(arg0, arg1);
            return ret;
        }, arguments); },
        __wbg_get_cefddcaffca4fbb7: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.get(arg1);
            return ret;
        }, arguments); },
        __wbg_get_unchecked_6e0ad6d2a41b06f6: function(arg0, arg1) {
            const ret = arg0[arg1 >>> 0];
            return ret;
        },
        __wbg_get_with_ref_key_6412cf3094599694: function(arg0, arg1) {
            const ret = arg0[arg1];
            return ret;
        },
        __wbg_indexNames_5deca5d5f0b3d91d: function(arg0) {
            const ret = arg0.indexNames;
            return ret;
        },
        __wbg_index_10b15a3a760a899d: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.index(getStringFromWasm0(arg1, arg2));
            return ret;
        }, arguments); },
        __wbg_instanceof_ArrayBuffer_4480b9e0068a8adb: function(arg0) {
            let result;
            try {
                result = arg0 instanceof ArrayBuffer;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_IdbCursorWithValue_f2fb4375c5baff87: function(arg0) {
            let result;
            try {
                result = arg0 instanceof IDBCursorWithValue;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_IdbDatabase_1cc734ba1b040dd7: function(arg0) {
            let result;
            try {
                result = arg0 instanceof IDBDatabase;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_IdbFactory_85ccbbe95ef25434: function(arg0) {
            let result;
            try {
                result = arg0 instanceof IDBFactory;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_IdbOpenDbRequest_c34a5f3bfadf1d88: function(arg0) {
            let result;
            try {
                result = arg0 instanceof IDBOpenDBRequest;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_IdbRequest_fe7a4cb10800af5b: function(arg0) {
            let result;
            try {
                result = arg0 instanceof IDBRequest;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_IdbTransaction_cd93f627db2edaa5: function(arg0) {
            let result;
            try {
                result = arg0 instanceof IDBTransaction;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_Map_e5b5e3db98422fcc: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Map;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_Uint8Array_309b927aaf7a3fc7: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Uint8Array;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_isArray_0677c962b281d01a: function(arg0) {
            const ret = Array.isArray(arg0);
            return ret;
        },
        __wbg_isSafeInteger_04f36e4056f1b851: function(arg0) {
            const ret = Number.isSafeInteger(arg0);
            return ret;
        },
        __wbg_iterator_6f722e4a93058b71: function() {
            const ret = Symbol.iterator;
            return ret;
        },
        __wbg_keyPath_58d74164f76a2452: function() { return handleError(function (arg0) {
            const ret = arg0.keyPath;
            return ret;
        }, arguments); },
        __wbg_key_b74c6cd401e5906b: function() { return handleError(function (arg0) {
            const ret = arg0.key;
            return ret;
        }, arguments); },
        __wbg_length_1f0964f4a5e2c6d8: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_length_370319915dc99107: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_length_e01fceeaca9c95fd: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_msCrypto_bd5a034af96bcba6: function(arg0) {
            const ret = arg0.msCrypto;
            return ret;
        },
        __wbg_multiEntry_07797e7e8b7c14b0: function(arg0) {
            const ret = arg0.multiEntry;
            return ret;
        },
        __wbg_new_0_3da9e97f24fc69be: function() {
            const ret = new Date();
            return ret;
        },
        __wbg_new_32b398fb48b6d94a: function() {
            const ret = new Array();
            return ret;
        },
        __wbg_new_7796ffc7ed656783: function() {
            const ret = new Map();
            return ret;
        },
        __wbg_new_b667d279fd5aa943: function(arg0, arg1) {
            const ret = new Error(getStringFromWasm0(arg0, arg1));
            return ret;
        },
        __wbg_new_cd45aabdf6073e84: function(arg0) {
            const ret = new Uint8Array(arg0);
            return ret;
        },
        __wbg_new_da52cf8fe3429cb2: function() {
            const ret = new Object();
            return ret;
        },
        __wbg_new_typed_1824d93f294193e5: function(arg0, arg1) {
            try {
                var state0 = {a: arg0, b: arg1};
                var cb0 = (arg0, arg1) => {
                    const a = state0.a;
                    state0.a = 0;
                    try {
                        return wasm_bindgen_1008b6a7b07acaf3___convert__closures_____invoke___js_sys_309f2fedb9185c0a___Function_fn_wasm_bindgen_1008b6a7b07acaf3___JsValue_____wasm_bindgen_1008b6a7b07acaf3___sys__Undefined___js_sys_309f2fedb9185c0a___Function_fn_wasm_bindgen_1008b6a7b07acaf3___JsValue_____wasm_bindgen_1008b6a7b07acaf3___sys__Undefined_______true_(a, state0.b, arg0, arg1);
                    } finally {
                        state0.a = a;
                    }
                };
                const ret = new Promise(cb0);
                return ret;
            } finally {
                state0.a = 0;
            }
        },
        __wbg_new_with_length_e6785c33c8e4cce8: function(arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return ret;
        },
        __wbg_next_6dbf2c0ac8cde20f: function(arg0) {
            const ret = arg0.next;
            return ret;
        },
        __wbg_next_71f2aa1cb3d1e37e: function() { return handleError(function (arg0) {
            const ret = arg0.next();
            return ret;
        }, arguments); },
        __wbg_node_84ea875411254db1: function(arg0) {
            const ret = arg0.node;
            return ret;
        },
        __wbg_now_86c0d4ba3fa605b8: function() {
            const ret = Date.now();
            return ret;
        },
        __wbg_objectStoreNames_146ab25540bff6db: function(arg0) {
            const ret = arg0.objectStoreNames;
            return ret;
        },
        __wbg_objectStore_d5f47956b6c741e3: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.objectStore(getStringFromWasm0(arg1, arg2));
            return ret;
        }, arguments); },
        __wbg_of_5f1b88183ddb5d94: function(arg0, arg1) {
            const ret = Array.of(arg0, arg1);
            return ret;
        },
        __wbg_of_b0cd2e09b31a9684: function(arg0, arg1, arg2) {
            const ret = Array.of(arg0, arg1, arg2);
            return ret;
        },
        __wbg_openCursor_04059a89749928f3: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.openCursor(arg1);
            return ret;
        }, arguments); },
        __wbg_openCursor_10d9f060128089d5: function() { return handleError(function (arg0) {
            const ret = arg0.openCursor();
            return ret;
        }, arguments); },
        __wbg_openCursor_6a71b165285fcc23: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.openCursor(arg1, __wbindgen_enum_IdbCursorDirection[arg2]);
            return ret;
        }, arguments); },
        __wbg_open_72e5234a49d5f85d: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            const ret = arg0.open(getStringFromWasm0(arg1, arg2), arg3 >>> 0);
            return ret;
        }, arguments); },
        __wbg_open_8b445bd20535cb55: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.open(getStringFromWasm0(arg1, arg2));
            return ret;
        }, arguments); },
        __wbg_prekeyCount_211eea3d5e8f2504: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.prekeyCount(arg1 >>> 0);
            return ret;
        }, arguments); },
        __wbg_process_44c7a14e11e9f69e: function(arg0) {
            const ret = arg0.process;
            return ret;
        },
        __wbg_prototypesetcall_4770620bbe4688a0: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        },
        __wbg_publishManifest_47055b8058d17629: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.publishManifest(arg1);
            return ret;
        }, arguments); },
        __wbg_publishProfile_7c7d2e60a332baf3: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.publishProfile(arg1);
            return ret;
        }, arguments); },
        __wbg_push_d2ae3af0c1217ae6: function(arg0, arg1) {
            const ret = arg0.push(arg1);
            return ret;
        },
        __wbg_put_3067c7a6df4dec59: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.put(arg1);
            return ret;
        }, arguments); },
        __wbg_put_a368805e3dcab3a7: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.put(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_queueMicrotask_0ab5b2d2393e99b9: function(arg0) {
            const ret = arg0.queueMicrotask;
            return ret;
        },
        __wbg_queueMicrotask_6a09b7bc46549209: function(arg0) {
            queueMicrotask(arg0);
        },
        __wbg_randomFillSync_6c25eac9869eb53c: function() { return handleError(function (arg0, arg1) {
            arg0.randomFillSync(arg1);
        }, arguments); },
        __wbg_registerDevice_825d280349f71b9c: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.registerDevice(arg1);
            return ret;
        }, arguments); },
        __wbg_replenishPrekeys_9a461458760d1e26: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.replenishPrekeys(arg1 >>> 0, arg2);
            return ret;
        }, arguments); },
        __wbg_request_cf325c5982659495: function(arg0) {
            const ret = arg0.request;
            return ret;
        },
        __wbg_require_b4edbdcf3e2a1ef0: function() { return handleError(function () {
            const ret = module.require;
            return ret;
        }, arguments); },
        __wbg_resolve_2191a4dfe481c25b: function(arg0) {
            const ret = Promise.resolve(arg0);
            return ret;
        },
        __wbg_result_2b1294a2bf8dc773: function() { return handleError(function (arg0) {
            const ret = arg0.result;
            return ret;
        }, arguments); },
        __wbg_sendMessage_66f8de82e33b5069: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            const ret = arg0.sendMessage(getStringFromWasm0(arg1, arg2), arg3);
            return ret;
        }, arguments); },
        __wbg_sendSealedMessage_d5ffca21eb96ceb8: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            const ret = arg0.sendSealedMessage(getStringFromWasm0(arg1, arg2), arg3);
            return ret;
        }, arguments); },
        __wbg_sendSyncMessage_faeb3abf22ae659f: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.sendSyncMessage(arg1);
            return ret;
        }, arguments); },
        __wbg_set_575dd786d51585f8: function(arg0, arg1, arg2) {
            const ret = arg0.set(arg1, arg2);
            return ret;
        },
        __wbg_set_6be42768c690e380: function(arg0, arg1, arg2) {
            arg0[arg1] = arg2;
        },
        __wbg_set_8a16b38e4805b298: function(arg0, arg1, arg2) {
            arg0[arg1 >>> 0] = arg2;
        },
        __wbg_set_auto_increment_b9511b96dfd26494: function(arg0, arg1) {
            arg0.autoIncrement = arg1 !== 0;
        },
        __wbg_set_key_path_849bf8bbe4f4b75c: function(arg0, arg1) {
            arg0.keyPath = arg1;
        },
        __wbg_set_multi_entry_ddb759130938331c: function(arg0, arg1) {
            arg0.multiEntry = arg1 !== 0;
        },
        __wbg_set_name_429b107b4f535fe0: function(arg0, arg1, arg2) {
            arg0.name = getStringFromWasm0(arg1, arg2);
        },
        __wbg_set_onabort_e8ad31807de2db24: function(arg0, arg1) {
            arg0.onabort = arg1;
        },
        __wbg_set_oncomplete_e6abb66d0ad42731: function(arg0, arg1) {
            arg0.oncomplete = arg1;
        },
        __wbg_set_onerror_3488a474171ed56d: function(arg0, arg1) {
            arg0.onerror = arg1;
        },
        __wbg_set_onerror_f8d31be44335c633: function(arg0, arg1) {
            arg0.onerror = arg1;
        },
        __wbg_set_onsuccess_cd0c3642a2873e66: function(arg0, arg1) {
            arg0.onsuccess = arg1;
        },
        __wbg_set_onupgradeneeded_7b2cf4ba1c57e655: function(arg0, arg1) {
            arg0.onupgradeneeded = arg1;
        },
        __wbg_set_onversionchange_c4d25c90ac386854: function(arg0, arg1) {
            arg0.onversionchange = arg1;
        },
        __wbg_set_unique_11514da4875da882: function(arg0, arg1) {
            arg0.unique = arg1 !== 0;
        },
        __wbg_static_accessor_GLOBAL_4ef717fb391d88b7: function() {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_GLOBAL_THIS_8d1badc68b5a74f4: function() {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_SELF_146583524fe1469b: function() {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_WINDOW_f2829a2234d7819e: function() {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_subarray_3ed232c8a6baee09: function(arg0, arg1, arg2) {
            const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
            return ret;
        },
        __wbg_target_e759594a8d965ed7: function(arg0) {
            const ret = arg0.target;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_then_16d107c451e9905d: function(arg0, arg1, arg2) {
            const ret = arg0.then(arg1, arg2);
            return ret;
        },
        __wbg_then_6ec10ae38b3e92f7: function(arg0, arg1) {
            const ret = arg0.then(arg1);
            return ret;
        },
        __wbg_toISOString_706fbe321055ee58: function(arg0) {
            const ret = arg0.toISOString();
            return ret;
        },
        __wbg_transaction_85424a007686760f: function(arg0) {
            const ret = arg0.transaction;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_transaction_f212158274461f32: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.transaction(arg1, __wbindgen_enum_IdbTransactionMode[arg2]);
            return ret;
        }, arguments); },
        __wbg_unique_f5dfb67739d0e058: function(arg0) {
            const ret = arg0.unique;
            return ret;
        },
        __wbg_value_361064aa58a53344: function() { return handleError(function (arg0) {
            const ret = arg0.value;
            return ret;
        }, arguments); },
        __wbg_value_a5d5488a9589444a: function(arg0) {
            const ret = arg0.value;
            return ret;
        },
        __wbg_versions_276b2795b1c6a219: function(arg0) {
            const ret = arg0.versions;
            return ret;
        },
        __wbg_wasmchatclient_new: function(arg0) {
            const ret = WasmChatClient.__wrap(arg0);
            return ret;
        },
        __wbindgen_cast_0000000000000001: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [Externref], shim_idx: 1871, ret: Result(Unit), inner_ret: Some(Result(Unit)) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen_1008b6a7b07acaf3___convert__closures_____invoke___wasm_bindgen_1008b6a7b07acaf3___JsValue__core_f0fd674eaa06beef___result__Result_____wasm_bindgen_1008b6a7b07acaf3___JsError___true_);
            return ret;
        },
        __wbindgen_cast_0000000000000002: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [NamedExternref("Event")], shim_idx: 1508, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen_1008b6a7b07acaf3___convert__closures_____invoke___web_sys_7ae9755e021dbdc3___features__gen_Event__Event______true_);
            return ret;
        },
        __wbindgen_cast_0000000000000003: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [NamedExternref("IDBVersionChangeEvent")], shim_idx: 1099, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen_1008b6a7b07acaf3___convert__closures_____invoke___web_sys_7ae9755e021dbdc3___features__gen_IdbVersionChangeEvent__IdbVersionChangeEvent______true_);
            return ret;
        },
        __wbindgen_cast_0000000000000004: function(arg0) {
            // Cast intrinsic for `F64 -> Externref`.
            const ret = arg0;
            return ret;
        },
        __wbindgen_cast_0000000000000005: function(arg0) {
            // Cast intrinsic for `I64 -> Externref`.
            const ret = arg0;
            return ret;
        },
        __wbindgen_cast_0000000000000006: function(arg0, arg1) {
            // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
            const ret = getArrayU8FromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000007: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000008: function(arg0) {
            // Cast intrinsic for `U64 -> Externref`.
            const ret = BigInt.asUintN(64, arg0);
            return ret;
        },
        __wbindgen_cast_0000000000000009: function(arg0, arg1) {
            var v0 = getArrayU8FromWasm0(arg0, arg1).slice();
            wasm.__wbindgen_free(arg0, arg1 * 1, 1);
            // Cast intrinsic for `Vector(U8) -> Externref`.
            const ret = v0;
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
        "./kutup_chat_core_bg.js": import0,
    };
}

function wasm_bindgen_1008b6a7b07acaf3___convert__closures_____invoke___web_sys_7ae9755e021dbdc3___features__gen_Event__Event______true_(arg0, arg1, arg2) {
    wasm.wasm_bindgen_1008b6a7b07acaf3___convert__closures_____invoke___web_sys_7ae9755e021dbdc3___features__gen_Event__Event______true_(arg0, arg1, arg2);
}

function wasm_bindgen_1008b6a7b07acaf3___convert__closures_____invoke___web_sys_7ae9755e021dbdc3___features__gen_IdbVersionChangeEvent__IdbVersionChangeEvent______true_(arg0, arg1, arg2) {
    wasm.wasm_bindgen_1008b6a7b07acaf3___convert__closures_____invoke___web_sys_7ae9755e021dbdc3___features__gen_IdbVersionChangeEvent__IdbVersionChangeEvent______true_(arg0, arg1, arg2);
}

function wasm_bindgen_1008b6a7b07acaf3___convert__closures_____invoke___wasm_bindgen_1008b6a7b07acaf3___JsValue__core_f0fd674eaa06beef___result__Result_____wasm_bindgen_1008b6a7b07acaf3___JsError___true_(arg0, arg1, arg2) {
    const ret = wasm.wasm_bindgen_1008b6a7b07acaf3___convert__closures_____invoke___wasm_bindgen_1008b6a7b07acaf3___JsValue__core_f0fd674eaa06beef___result__Result_____wasm_bindgen_1008b6a7b07acaf3___JsError___true_(arg0, arg1, arg2);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

function wasm_bindgen_1008b6a7b07acaf3___convert__closures_____invoke___js_sys_309f2fedb9185c0a___Function_fn_wasm_bindgen_1008b6a7b07acaf3___JsValue_____wasm_bindgen_1008b6a7b07acaf3___sys__Undefined___js_sys_309f2fedb9185c0a___Function_fn_wasm_bindgen_1008b6a7b07acaf3___JsValue_____wasm_bindgen_1008b6a7b07acaf3___sys__Undefined_______true_(arg0, arg1, arg2, arg3) {
    wasm.wasm_bindgen_1008b6a7b07acaf3___convert__closures_____invoke___js_sys_309f2fedb9185c0a___Function_fn_wasm_bindgen_1008b6a7b07acaf3___JsValue_____wasm_bindgen_1008b6a7b07acaf3___sys__Undefined___js_sys_309f2fedb9185c0a___Function_fn_wasm_bindgen_1008b6a7b07acaf3___JsValue_____wasm_bindgen_1008b6a7b07acaf3___sys__Undefined_______true_(arg0, arg1, arg2, arg3);
}


const __wbindgen_enum_IdbCursorDirection = ["next", "nextunique", "prev", "prevunique"];


const __wbindgen_enum_IdbTransactionMode = ["readonly", "readwrite", "versionchange", "readwriteflush", "cleanup"];
const WasmChatClientFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmchatclient_free(ptr, 1));

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

const CLOSURE_DTORS = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(state => wasm.__wbindgen_destroy_closure(state.a, state.b));

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

function makeMutClosure(arg0, arg1, f) {
    const state = { a: arg0, b: arg1, cnt: 1 };
    const real = (...args) => {

        // First up with a closure we increment the internal reference
        // count. This ensures that the Rust closure environment won't
        // be deallocated while we're invoking it.
        state.cnt++;
        const a = state.a;
        state.a = 0;
        try {
            return f(a, state.b, ...args);
        } finally {
            state.a = a;
            real._wbg_cb_unref();
        }
    };
    real._wbg_cb_unref = () => {
        if (--state.cnt === 0) {
            wasm.__wbindgen_destroy_closure(state.a, state.b);
            state.a = 0;
            CLOSURE_DTORS.unregister(state);
        }
    };
    CLOSURE_DTORS.register(real, state, state);
    return real;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passArrayJsValueToWasm0(array, malloc) {
    const ptr = malloc(array.length * 4, 4) >>> 0;
    for (let i = 0; i < array.length; i++) {
        const add = addToExternrefTable0(array[i]);
        getDataViewMemory0().setUint32(ptr + 4 * i, add, true);
    }
    WASM_VECTOR_LEN = array.length;
    return ptr;
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
        module_or_path = new URL('kutup_chat_core_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
