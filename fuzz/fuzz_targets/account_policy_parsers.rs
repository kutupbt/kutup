#![no_main]

use kutup_chat_proto::{
    AccountManifestHistoryPageV1, AccountManifestPublicationV1, AccountManifestV1,
    MlsOrderingServicePolicyV1, SealedSenderServicePolicyV1,
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

    if let Ok(manifest) = serde_json::from_slice::<AccountManifestV1>(data) {
        let _ = manifest.signing_bytes();
        let _ = manifest.manifest_hash();
        let _ = manifest.verify();
    }
    if let Ok(publication) = serde_json::from_slice::<AccountManifestPublicationV1>(data) {
        let _ = publication.manifest.verify();
    }
    if let Ok(page) = serde_json::from_slice::<AccountManifestHistoryPageV1>(data) {
        let _ = page.validate();
    }

    let _ = SealedSenderServicePolicyV1::from_canonical_bytes(data);
    if let Ok(policy) = serde_json::from_slice::<SealedSenderServicePolicyV1>(data) {
        let _ = policy.validate();
        let _ = policy.canonical_bytes();
    }
    let _ = MlsOrderingServicePolicyV1::from_canonical_bytes(data);
    if let Ok(policy) = serde_json::from_slice::<MlsOrderingServicePolicyV1>(data) {
        let _ = policy.validate();
        let _ = policy.canonical_bytes();
    }
});
