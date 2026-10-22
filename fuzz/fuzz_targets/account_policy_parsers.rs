#![no_main]

use kutup_chat_proto::{
    parse_device_header, AccountIdentityBody, AccountIdentityDistributionRequest,
    AccountManifestHistoryPageV2, AccountManifestPublicationV2, AccountManifestV2,
    AccountPreKeyBundlesResponse, ChatProvisionV1, MlsOrderingServicePolicyV1,
    ProvisionEnvelopeV1, ProvisioningLinkCodeV1, RegisterChatDeviceRequestV2,
    SealedSenderServicePolicyV1,
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

    if let Ok(manifest) = serde_json::from_slice::<AccountManifestV2>(data) {
        let _ = manifest.signing_bytes();
        let _ = manifest.manifest_hash();
        let _ = manifest.verify();
        let _ = manifest.verify_successor(Some(&manifest));
    }
    if let Ok(publication) = serde_json::from_slice::<AccountManifestPublicationV2>(data) {
        let _ = publication.manifest.verify();
    }
    if let Ok(page) = serde_json::from_slice::<AccountManifestHistoryPageV2>(data) {
        let _ = page.validate();
    }
    if let Ok(bundles) = serde_json::from_slice::<AccountPreKeyBundlesResponse>(data) {
        let _ = bundles.check_against_manifest();
    }
    // The account identity's requests and messages
    // (docs/plans/account-identity-key.md).
    if let Ok(request) = serde_json::from_slice::<RegisterChatDeviceRequestV2>(data) {
        let _ = request.validate();
    }
    if let Ok(request) = serde_json::from_slice::<AccountIdentityDistributionRequest>(data) {
        let _ = request.validate(1);
    }
    if let Ok(envelope) = serde_json::from_slice::<ProvisionEnvelopeV1>(data) {
        let _ = envelope.validate();
    }
    if let Ok(message) = serde_json::from_slice::<ChatProvisionV1>(data) {
        let _ = message.validate();
    }
    if let Ok(body) = serde_json::from_slice::<AccountIdentityBody>(data) {
        let _ = body.validate();
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = ProvisioningLinkCodeV1::parse(text);
        let _ = parse_device_header(text);
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
