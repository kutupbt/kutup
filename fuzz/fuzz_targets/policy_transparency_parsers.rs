#![no_main]

use kutup_chat_proto::{
    ChatTransparencyPolicyV1, ManifestUpdateRangeProofV1, SealedSenderServicePolicyV1,
    TransparencyCheckpointResponse, TransparencyForkEvidenceV1, WitnessViewV1,
};
use kutup_federation_proto::{FederatedFeaturePolicyEnvelopeV1, FederatedFeaturePolicyHistoryV1};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 2 * 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    if let Ok(envelope) = serde_json::from_slice::<FederatedFeaturePolicyEnvelopeV1>(data) {
        let _ = envelope.payload_bytes();
        let _ = envelope.signing_bytes();
        let _ = envelope.policy_hash();
    }
    if let Ok(history) = serde_json::from_slice::<FederatedFeaturePolicyHistoryV1>(data) {
        let _ = history.verify();
    }

    let _ = ChatTransparencyPolicyV1::from_canonical_bytes(data);
    if let Ok(policy) = serde_json::from_slice::<ChatTransparencyPolicyV1>(data) {
        let _ = policy.validate();
        let _ = policy.canonical_bytes();
    }
    let _ = SealedSenderServicePolicyV1::from_canonical_bytes(data);
    if let Ok(policy) = serde_json::from_slice::<SealedSenderServicePolicyV1>(data) {
        let _ = policy.validate();
        let _ = policy.canonical_bytes();
    }

    if let Ok(checkpoint) = serde_json::from_slice::<TransparencyCheckpointResponse>(data) {
        let _ = checkpoint.verify(None);
    }
    if let Ok(proof) = serde_json::from_slice::<ManifestUpdateRangeProofV1>(data) {
        let _ = proof.verify_page(&proof.account, proof.from_version, None, None);
    }
    if let Ok(view) = serde_json::from_slice::<WitnessViewV1>(data) {
        let _ = view.verify();
    }
    if let Ok(evidence) = serde_json::from_slice::<TransparencyForkEvidenceV1>(data) {
        let _ = evidence.verify_contradiction();
    }
});
