//! Device initialization and manifest-bound MLS KeyPackage generation.

use super::*;

impl MlsClient {
    pub fn new(db: Rc<dyn ChatDb>) -> Self {
        Self { db }
    }

    /// Parse and authenticate an untrusted KeyPackage against the exact
    /// transparency-verified manifest credential before it is used in a
    /// membership proposal.
    pub fn validate_verified_key_package(
        verified: &VerifiedMlsKeyPackage,
        now_seconds: i64,
    ) -> Result<()> {
        parse_verified_key_package(&KutupMlsProvider::default(), verified, now_seconds).map(|_| ())
    }

    /// Install a new P-256 MLS credential and independent anonymous-delivery
    /// HPKE key, or reopen the exact existing identity. A different identity
    /// never replaces keys implicitly.
    pub async fn initialize(
        &self,
        canonical_device_identity: &str,
    ) -> Result<MlsDevicePublicMaterial> {
        validate_credential_identity(canonical_device_identity)?;
        if let Some(bytes) = self.db.load_mls_state().await? {
            let (_, metadata) = provider_from_snapshot(&bytes)?;
            if metadata.credential_identity != canonical_device_identity {
                return Err(ChatError::Trust(
                    "MLS device identity differs from the durable credential; explicit device rotation is required"
                        .into(),
                ));
            }
            return metadata.public_material();
        }

        let provider = KutupMlsProvider::default();
        let signer = SignatureKeyPair::new(KUTUP_MLS_V1_CIPHERSUITE.signature_algorithm())
            .map_err(|error| mls_error("generate MLS credential", error))?;
        signer
            .store(provider.storage())
            .map_err(|error| mls_error("store MLS credential", error))?;

        let anonymous_private_key = p256::SecretKey::random(&mut OsRng);
        let metadata = SnapshotMetadata {
            credential_identity: canonical_device_identity.to_owned(),
            credential_public_key: signer.to_public_vec(),
            anonymous_delivery_private_key: anonymous_private_key.to_bytes().to_vec(),
            pending_commits: BTreeMap::new(),
            pending_membership_changes: BTreeMap::new(),
            pending_authority_changes: BTreeMap::new(),
            pending_owner_changes: BTreeMap::new(),
            pending_closes: BTreeMap::new(),
            owner_approval_requests: BTreeMap::new(),
            group_control_private_keys: BTreeMap::new(),
            group_owner_private_keys: BTreeMap::new(),
            group_owner_candidate_private_keys: BTreeMap::new(),
            owner_candidates: BTreeMap::new(),
            conversations: BTreeMap::new(),
            processed_control_envelopes: BTreeMap::new(),
        };
        let state = snapshot_provider(&provider, &metadata)?;
        let mut pending = Pending {
            mls_state: Some(state),
            ..Pending::default()
        };
        self.db.apply(&pending).await?;
        pending.clear();
        metadata.public_material()
    }

    /// Generate and durably retain a one-time KeyPackage before returning its
    /// public bytes. The server can therefore never receive a KeyPackage whose
    /// matching private init key was lost in a client crash.
    pub async fn generate_key_package(
        &self,
        manifest_version: u64,
        device_id: u32,
        now_seconds: i64,
        expires_at_seconds: i64,
    ) -> Result<MlsKeyPackageV1> {
        if manifest_version == 0 || device_id == 0 || now_seconds < 0 {
            return Err(ChatError::Invalid(
                "MLS KeyPackage requires a manifest, device, and valid clock".into(),
            ));
        }
        let lifetime = expires_at_seconds
            .checked_sub(now_seconds)
            .ok_or_else(|| ChatError::Invalid("MLS KeyPackage expiry overflow".into()))?;
        if lifetime <= 0 || lifetime > MAX_KEY_PACKAGE_LIFETIME_SECONDS {
            return Err(ChatError::Invalid(
                "MLS KeyPackage lifetime must be within 84 days".into(),
            ));
        }

        let (provider, metadata) = self.load_provider().await?;
        let signer = metadata.read_signer(&provider)?;
        let credential = metadata.credential();
        let not_before = u64::try_from(now_seconds)
            .map_err(|_| ChatError::Invalid("negative MLS KeyPackage clock".into()))?
            .saturating_sub(KEY_PACKAGE_CLOCK_SKEW_SECONDS);
        let not_after = u64::try_from(expires_at_seconds)
            .map_err(|_| ChatError::Invalid("negative MLS KeyPackage expiry".into()))?;
        let bundle = KeyPackage::builder()
            .key_package_lifetime(Lifetime::init(not_before, not_after))
            .key_package_extensions(Extensions::default())
            .leaf_node_capabilities(kutup_mls_capabilities())
            .build(KUTUP_MLS_V1_CIPHERSUITE, &provider, &signer, credential)
            .map_err(|error| mls_error("create MLS KeyPackage", error))?;
        let package = bundle.key_package();
        if package.ciphersuite() != KUTUP_MLS_V1_CIPHERSUITE {
            return Err(ChatError::Protocol(
                "OpenMLS produced a KeyPackage for a non-Kutup suite".into(),
            ));
        }
        let package_bytes = package
            .tls_serialize_detached()
            .map_err(|error| mls_error("serialize MLS KeyPackage", error))?;
        let package_ref = package
            .hash_ref(provider.crypto())
            .map_err(|error| mls_error("hash MLS KeyPackage", error))?;
        let wire = MlsKeyPackageV1 {
            device_id,
            manifest_version,
            suite: MlsCipherSuiteId::Mls128DhKemP256Aes128GcmSha256P256,
            key_package_ref: hex::encode(package_ref.as_slice()),
            key_package: BASE64.encode(package_bytes),
            expires_at: expires_at_seconds,
        };
        wire.validate(now_seconds).map_err(ChatError::Invalid)?;

        let state = snapshot_provider(&provider, &metadata)?;
        let pending = Pending {
            mls_state: Some(state),
            ..Pending::default()
        };
        self.db.apply(&pending).await?;
        Ok(wire)
    }
}
