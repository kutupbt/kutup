//! Ordering policy, KeyPackage publication, capabilities, and anonymous MLS delivery.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingMessageRequestPolicyV1 {
    pub maximum_messages: u16,
    pub maximum_ciphertext_bytes: u32,
    pub expiry_seconds: u64,
}

impl Default for PendingMessageRequestPolicyV1 {
    fn default() -> Self {
        Self {
            maximum_messages: 32,
            maximum_ciphertext_bytes: 1024 * 1024,
            expiry_seconds: 30 * 24 * 60 * 60,
        }
    }
}

impl PendingMessageRequestPolicyV1 {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=128).contains(&self.maximum_messages)
            || !(64 * 1024..=16 * 1024 * 1024).contains(&self.maximum_ciphertext_bytes)
            || !(24 * 60 * 60..=90 * 24 * 60 * 60).contains(&self.expiry_seconds)
        {
            return Err("pending message-request policy is outside the v1 bounds".into());
        }
        Ok(())
    }

    pub fn strictest(self, other: Self) -> Self {
        Self {
            maximum_messages: self.maximum_messages.min(other.maximum_messages),
            maximum_ciphertext_bytes: self
                .maximum_ciphertext_bytes
                .min(other.maximum_ciphertext_bytes),
            expiry_seconds: self.expiry_seconds.min(other.expiry_seconds),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsAbuseLimitsV1 {
    pub anonymous_attempts_per_ip_minute: u32,
    pub capability_bundle_requests_per_minute: u32,
    pub sealed_sends_per_capability_minute: u32,
    pub sealed_sends_per_capability_day: u32,
    pub federated_sealed_sends_per_origin_minute: u32,
    pub maximum_envelopes_per_request: u16,
    pub maximum_request_bytes: u32,
}

impl Default for MlsAbuseLimitsV1 {
    fn default() -> Self {
        Self {
            anonymous_attempts_per_ip_minute: 60,
            capability_bundle_requests_per_minute: 30,
            sealed_sends_per_capability_minute: 120,
            sealed_sends_per_capability_day: 10_000,
            federated_sealed_sends_per_origin_minute: 600,
            maximum_envelopes_per_request: MAX_ANONYMOUS_ENVELOPES as u16,
            maximum_request_bytes: MAX_ANONYMOUS_REQUEST_BYTES as u32,
        }
    }
}

impl MlsAbuseLimitsV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.anonymous_attempts_per_ip_minute == 0
            || self.capability_bundle_requests_per_minute == 0
            || self.sealed_sends_per_capability_minute == 0
            || self.sealed_sends_per_capability_day == 0
            || self.federated_sealed_sends_per_origin_minute == 0
            || self.maximum_envelopes_per_request == 0
            || self.maximum_envelopes_per_request > MAX_ANONYMOUS_ENVELOPES as u16
            || self.maximum_request_bytes < 4096
            || self.maximum_request_bytes > MAX_ANONYMOUS_REQUEST_BYTES as u32
        {
            return Err(
                "anonymous MLS abuse limits are invalid or exceed protocol ceilings".into(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsOrderingServicePolicyV1 {
    pub policy_version: u16,
    pub canonical_domain: String,
    pub suite: MlsCipherSuiteId,
    pub anonymous_delivery_suite: MlsAnonymousDeliverySuiteV1,
    pub control_signing_key_id: String,
    pub control_signing_public_key: String,
    pub accepts_group_ordering: bool,
    pub maximum_group_members: u16,
    pub maximum_authorities: u16,
    pub maximum_control_payload_bytes: u32,
    pub pending_message_requests: PendingMessageRequestPolicyV1,
    pub abuse_limits: MlsAbuseLimitsV1,
}

impl MlsOrderingServicePolicyV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.policy_version != MLS_ORDERING_SERVICE_POLICY_VERSION {
            return Err("unsupported MLS ordering service policy version".into());
        }
        kutup_federation_proto::validate_server_name(&self.canonical_domain)
            .map_err(|error| error.to_string())?;
        validate_ed25519_key(
            "MLS control signing",
            &self.control_signing_key_id,
            &self.control_signing_public_key,
        )?;
        if !(256..=1000).contains(&self.maximum_group_members)
            || !(1..=64).contains(&self.maximum_authorities)
            || !(4096..=MAX_MLS_CONTROL_PAYLOAD_BYTES as u32)
                .contains(&self.maximum_control_payload_bytes)
        {
            return Err("MLS ordering service limits are outside the v1 bounds".into());
        }
        self.pending_message_requests.validate()?;
        self.abuse_limits.validate()
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        decode_canonical(bytes, Self::validate)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsKeyPackageV1 {
    pub device_id: u32,
    pub manifest_version: u64,
    pub suite: MlsCipherSuiteId,
    /// MLS KeyPackageRef for the SHA-256 ciphersuite, lowercase hex.
    pub key_package_ref: String,
    pub key_package: String,
    pub expires_at: i64,
}

impl MlsKeyPackageV1 {
    pub fn validate(&self, now: i64) -> Result<(), String> {
        if self.device_id == 0 || self.manifest_version == 0 || self.expires_at <= now {
            return Err("MLS KeyPackage has invalid device, manifest, or expiry".into());
        }
        validate_hash("keyPackageRef", &self.key_package_ref)?;
        decode_canonical_base64(
            "MLS KeyPackage",
            &self.key_package,
            1,
            MAX_MLS_KEY_PACKAGE_BYTES,
        )?;
        Ok(())
    }
}

/// Authenticated publication of KeyPackages for a device already bound in the
/// current transparency-logged manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublishMlsKeyPackagesRequestV1 {
    pub protocol_version: u16,
    pub manifest_version: u64,
    pub device_id: u32,
    pub key_packages: Vec<MlsKeyPackageV1>,
}

impl PublishMlsKeyPackagesRequestV1 {
    pub fn validate(&self, now: i64) -> Result<(), String> {
        if self.protocol_version != MLS_PROTOCOL_VERSION
            || self.manifest_version == 0
            || self.device_id == 0
            || self.key_packages.is_empty()
            || self.key_packages.len() > 100
        {
            return Err("MLS KeyPackage publication shape is invalid".into());
        }
        let mut references = BTreeSet::new();
        for package in &self.key_packages {
            package.validate(now)?;
            if package.device_id != self.device_id
                || package.manifest_version != self.manifest_version
                || !references.insert(package.key_package_ref.as_str())
            {
                return Err("MLS KeyPackages must be unique and match one device manifest".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub enum MlsDeliveryCapabilityKindV1 {
    Direct,
    Group,
}

/// Publishes only the verifier for an epoch-bound delivery capability. The raw
/// capability is delivered end-to-end inside MLS and is never persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublishMlsDeliveryCapabilityV1 {
    pub protocol_version: u16,
    pub conversation_id: Uuid,
    pub incarnation: u64,
    pub epoch: u64,
    pub capability_kind: MlsDeliveryCapabilityKindV1,
    pub capability_hash: String,
    pub policy_sequence: u64,
}

impl PublishMlsDeliveryCapabilityV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != MLS_PROTOCOL_VERSION
            || self.conversation_id.is_nil()
            || self.incarnation == 0
            || self.policy_sequence == 0
        {
            return Err("MLS delivery capability identifiers are invalid".into());
        }
        validate_hash("capabilityHash", &self.capability_hash)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsKeyPackageCountResponseV1 {
    pub device_id: u32,
    pub available: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnonymousMlsKeyPackageRequestV1 {
    pub protocol_version: u16,
    pub recipient: AccountAddress,
    /// Canonical padded base64 16-byte delivery capability.
    pub capability: String,
    /// Highest transparency checkpoint already pinned by the requesting
    /// client, encoded as canonical decimal to preserve all 64 bits in JS.
    pub transparency_tree_size: String,
}

/// Identified first-contact KeyPackage claim used only to construct an MLS
/// membership invitation. Unlike established application delivery, the
/// destination is allowed to learn the requester account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentifiedMlsKeyPackageRequestV1 {
    pub protocol_version: u16,
    pub recipient: AccountAddress,
    pub conversation_id: Uuid,
    pub incarnation: u64,
    pub transparency_tree_size: String,
}

impl IdentifiedMlsKeyPackageRequestV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != MLS_PROTOCOL_VERSION
            || self.recipient.server.is_none()
            || self.conversation_id.is_nil()
            || self.incarnation == 0
        {
            return Err("identified MLS KeyPackage request has invalid identifiers".into());
        }
        self.known_tree_size()?;
        Ok(())
    }

    pub fn known_tree_size(&self) -> Result<u64, String> {
        let value = self
            .transparency_tree_size
            .parse::<u64>()
            .map_err(|_| "transparencyTreeSize must be canonical decimal".to_string())?;
        if value.to_string() != self.transparency_tree_size {
            return Err("transparencyTreeSize must be canonical decimal".into());
        }
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedIdentifiedMlsKeyPackageRequestV1 {
    pub origin_domain: String,
    pub requester: AccountAddress,
    pub request: IdentifiedMlsKeyPackageRequestV1,
}

impl FederatedIdentifiedMlsKeyPackageRequestV1 {
    pub fn validate(&self) -> Result<(), String> {
        kutup_federation_proto::validate_server_name(&self.origin_domain)
            .map_err(|error| error.to_string())?;
        self.request.validate()?;
        if self.requester.server.as_deref() != Some(self.origin_domain.as_str()) {
            return Err("federated identified MLS request has the wrong requester identity".into());
        }
        Ok(())
    }
}

impl AnonymousMlsKeyPackageRequestV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != MLS_PROTOCOL_VERSION || self.recipient.server.is_none() {
            return Err("anonymous MLS KeyPackage request has invalid version or recipient".into());
        }
        decode_canonical_base64("delivery capability", &self.capability, 16, 16)?;
        self.known_tree_size()?;
        Ok(())
    }

    pub fn known_tree_size(&self) -> Result<u64, String> {
        let value = self
            .transparency_tree_size
            .parse::<u64>()
            .map_err(|_| "transparencyTreeSize must be canonical decimal".to_string())?;
        if value.to_string() != self.transparency_tree_size {
            return Err("transparencyTreeSize must be canonical decimal".into());
        }
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsKeyPackageBundleV1 {
    pub recipient: AccountAddress,
    pub manifest: DeviceManifest,
    pub transparency: ManifestTransparencyProof,
    pub key_packages: Vec<MlsKeyPackageV1>,
}

impl MlsKeyPackageBundleV1 {
    pub fn validate(&self, now: i64) -> Result<(), String> {
        if self.recipient.server.is_none()
            || self.key_packages.is_empty()
            || self.key_packages.len() > MAX_ANONYMOUS_ENVELOPES
        {
            return Err("anonymous MLS KeyPackage response shape is invalid".into());
        }
        self.manifest.verify()?;
        self.transparency
            .leaf
            .matches_manifest(&self.recipient.username, &self.manifest)?;
        self.transparency.verify_inclusion()?;
        self.transparency.verify_current_map()?;
        self.transparency.verify_authentication()?;
        let mut devices = BTreeSet::new();
        for package in &self.key_packages {
            package.validate(now)?;
            if package.manifest_version != self.manifest.version
                || !devices.insert(package.device_id)
            {
                return Err(
                    "anonymous MLS KeyPackages must be unique and use one manifest version".into(),
                );
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnonymousMlsDeliveryResponseV1 {
    pub accepted: bool,
    pub stored_devices: u16,
    pub deduplicated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnonymousMlsDeviceEnvelopeV1 {
    pub device_id: u32,
    /// HPKE KEM encapsulation (uncompressed P-256 point, 65 bytes).
    pub encapsulated_key: String,
    /// HPKE ciphertext containing the entire padded MLS PrivateMessage.
    pub ciphertext: String,
}

impl AnonymousMlsDeviceEnvelopeV1 {
    fn validate(&self) -> Result<usize, String> {
        if self.device_id == 0 {
            return Err("anonymous MLS envelope device id must be positive".into());
        }
        validate_uncompressed_p256("HPKE encapsulated key", &self.encapsulated_key)?;
        let ciphertext = decode_canonical_base64(
            "anonymous MLS ciphertext",
            &self.ciphertext,
            17,
            1024 * 1024,
        )?;
        Ok(ciphertext.len() + 65)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnonymousMlsSubmissionV1 {
    pub protocol_version: u16,
    pub recipient: AccountAddress,
    pub send_id: Uuid,
    pub capability: String,
    pub suite: MlsAnonymousDeliverySuiteV1,
    pub envelopes: Vec<AnonymousMlsDeviceEnvelopeV1>,
}

impl AnonymousMlsSubmissionV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != MLS_PROTOCOL_VERSION
            || self.recipient.server.is_none()
            || self.send_id.is_nil()
            || self.envelopes.is_empty()
            || self.envelopes.len() > MAX_ANONYMOUS_ENVELOPES
        {
            return Err("anonymous MLS submission shape is invalid".into());
        }
        decode_canonical_base64("delivery capability", &self.capability, 16, 16)?;
        let mut total = 0usize;
        let mut previous = None;
        for envelope in &self.envelopes {
            if previous.is_some_and(|device_id| envelope.device_id <= device_id) {
                return Err(
                    "anonymous MLS envelopes must be strictly ordered by destination device".into(),
                );
            }
            previous = Some(envelope.device_id);
            total = total
                .checked_add(envelope.validate()?)
                .ok_or("anonymous MLS request size overflow")?;
        }
        if total > MAX_ANONYMOUS_REQUEST_BYTES {
            return Err("anonymous MLS request exceeds the protocol size ceiling".into());
        }
        Ok(())
    }

    pub fn aad_for_device(&self, device_id: u32) -> Result<Vec<u8>, String> {
        self.validate()?;
        anonymous_mls_delivery_aad(&self.recipient, self.send_id, self.suite, device_id)
    }
}

pub fn anonymous_mls_delivery_aad(
    recipient: &AccountAddress,
    send_id: Uuid,
    suite: MlsAnonymousDeliverySuiteV1,
    device_id: u32,
) -> Result<Vec<u8>, String> {
    if recipient.server.is_none() || send_id.is_nil() || device_id == 0 {
        return Err("anonymous MLS AAD identifiers are invalid".into());
    }
    let mut aad = Vec::with_capacity(256);
    aad.extend_from_slice(ANONYMOUS_MLS_DELIVERY_CONTEXT);
    push_string(&mut aad, &recipient.canonical())?;
    aad.extend_from_slice(&device_id.to_be_bytes());
    aad.extend_from_slice(send_id.as_bytes());
    aad.extend_from_slice(&u16::from(suite).to_be_bytes());
    Ok(aad)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedAnonymousMlsTransactionV1 {
    pub origin_domain: String,
    pub origin_sequence: u64,
    #[serde(flatten)]
    pub submission: AnonymousMlsSubmissionV1,
}

impl FederatedAnonymousMlsTransactionV1 {
    pub fn validate(&self) -> Result<(), String> {
        kutup_federation_proto::validate_server_name(&self.origin_domain)
            .map_err(|error| error.to_string())?;
        if self.origin_sequence == 0 {
            return Err("federated anonymous MLS sequence must be positive".into());
        }
        self.submission.validate()
    }
}

pub fn derive_group_delivery_capability(
    exporter_secret: &[u8],
    conversation_id: Uuid,
    incarnation: u64,
    epoch: u64,
    recipient: &AccountAddress,
) -> Result<[u8; 16], String> {
    if exporter_secret.len() < 16
        || conversation_id.is_nil()
        || incarnation == 0
        || recipient.server.is_none()
    {
        return Err("group delivery capability input is invalid".into());
    }
    let mut info = Vec::with_capacity(256);
    info.extend_from_slice(GROUP_DELIVERY_CAPABILITY_CONTEXT);
    info.extend_from_slice(conversation_id.as_bytes());
    info.extend_from_slice(&incarnation.to_be_bytes());
    info.extend_from_slice(&epoch.to_be_bytes());
    push_string(&mut info, &recipient.canonical())?;
    let mut capability = [0u8; 16];
    Hkdf::<Sha256>::new(None, exporter_secret)
        .expand(&info, &mut capability)
        .map_err(|_| "group delivery capability derivation failed")?;
    Ok(capability)
}
