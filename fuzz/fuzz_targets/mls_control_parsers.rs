#![no_main]

use kutup_chat_proto::{
    AnonymousMlsKeyPackageRequestV1, AnonymousMlsSubmissionV1, CommitMlsControlBlockV1,
    FederatedAnonymousMlsTransactionV1, FederatedMlsAuthorityBootstrapPageV1,
    FederatedMlsControlReplicaV1, FederatedMlsOrderingVoteRequestV1,
    FederatedMlsParticipantBootstrapPageV1, MlsAuthorityChangeV1,
    MlsClientControlHistoryPageV1, MlsInvitationFeedbackV1, MlsMailboxPageV1,
    MlsMembershipDeliveryV1, MlsPrivateControlStateV1,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    if let Ok(change) = serde_json::from_slice::<MlsAuthorityChangeV1>(data) {
        let _ = change.validate();
        let _ = change.transition_digest();
    }
    if let Ok(request) = serde_json::from_slice::<FederatedMlsOrderingVoteRequestV1>(data) {
        let _ = request.validate();
    }
    if let Ok(request) = serde_json::from_slice::<CommitMlsControlBlockV1>(data) {
        let _ = request.validate_shape();
    }
    if let Ok(replica) = serde_json::from_slice::<FederatedMlsControlReplicaV1>(data) {
        let _ = replica.validate();
    }
    if let Ok(delivery) = serde_json::from_slice::<MlsMembershipDeliveryV1>(data) {
        let _ = delivery.validate();
        let _ = delivery.canonical_bytes();
        let _ = delivery.delivery_digest();
    }
    if let Ok(feedback) = serde_json::from_slice::<MlsInvitationFeedbackV1>(data) {
        let _ = feedback.validate();
        let _ = feedback.canonical_bytes();
        let _ = feedback.feedback_digest();
    }
    if let Ok(page) = serde_json::from_slice::<FederatedMlsAuthorityBootstrapPageV1>(data) {
        let _ = page.validate();
        let _ = page.page_hash();
    }
    if let Ok(page) = serde_json::from_slice::<MlsClientControlHistoryPageV1>(data) {
        let _ = page.validate();
        let _ = page.canonical_bytes();
    }
    if let Ok(state) = serde_json::from_slice::<MlsPrivateControlStateV1>(data) {
        let _ = state.validate();
        let _ = state.canonical_bytes();
    }
    if let Ok(page) = serde_json::from_slice::<FederatedMlsParticipantBootstrapPageV1>(data) {
        let _ = page.validate();
        let _ = page.page_hash();
    }
    if let Ok(request) = serde_json::from_slice::<AnonymousMlsKeyPackageRequestV1>(data) {
        let _ = request.validate();
    }
    if let Ok(submission) = serde_json::from_slice::<AnonymousMlsSubmissionV1>(data) {
        let _ = submission.validate();
    }
    if let Ok(transaction) = serde_json::from_slice::<FederatedAnonymousMlsTransactionV1>(data) {
        let _ = transaction.validate();
    }
    if let Ok(page) = serde_json::from_slice::<MlsMailboxPageV1>(data) {
        let _ = page.validate();
    }
});
