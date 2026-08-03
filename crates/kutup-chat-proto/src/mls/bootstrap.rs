//! Authority and participant bootstrap descriptors, pages, and independent verification.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommitMlsControlBlockResponseV1 {
    pub conversation_id: Uuid,
    pub incarnation: u64,
    pub height: u64,
    pub epoch: u64,
    pub block_hash: String,
    pub idempotent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsAuthorityTransitionCertificateV1 {
    pub previous_set_certificate: MlsOrderingQuorumCertificateV1,
    pub new_set_certificate: MlsOrderingQuorumCertificateV1,
}

impl MlsAuthorityTransitionCertificateV1 {
    pub fn verify(
        &self,
        block_hash: &str,
        previous: &MlsAuthoritySetV1,
        next: &MlsAuthoritySetV1,
    ) -> Result<(), String> {
        if previous.sequence.checked_add(1) != Some(next.sequence)
            || self.previous_set_certificate.block_hash != block_hash
            || self.new_set_certificate.block_hash != block_hash
        {
            return Err("MLS authority transition is not contiguous or binds another block".into());
        }
        self.previous_set_certificate.verify(previous)?;
        self.new_set_certificate.verify(next)
    }
}

/// Immutable authorization and history commitment used to stage a newly
/// added MLS ordering authority. It contains no roster identities beyond the
/// participant domains already visible to federation routing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsAuthorityBootstrapDescriptorV1 {
    pub protocol_version: u16,
    pub genesis: MlsConversationGenesisV1,
    pub genesis_participant_domains: Vec<String>,
    /// Exact current participant routing after replaying `history_block_count`.
    pub participant_domains: Vec<String>,
    pub transition_block: MlsControlBlockV1,
    pub previous_set_certificate: MlsOrderingQuorumCertificateV1,
    pub authority_change: MlsAuthorityChangeV1,
    pub history_block_count: u64,
    pub history_digest: String,
}

impl MlsAuthorityBootstrapDescriptorV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != MLS_PROTOCOL_VERSION {
            return Err("unsupported MLS authority bootstrap version".into());
        }
        self.genesis.validate()?;
        validate_participant_domain_set(&self.genesis_participant_domains)?;
        validate_participant_domain_set(&self.participant_domains)?;
        self.transition_block.validate()?;
        self.transition_block.proposal.verify()?;
        self.authority_change.validate()?;
        validate_hash("historyDigest", &self.history_digest)?;
        let next_set_digest = self.authority_change.transition_digest()?;
        if self.transition_block.conversation_id != self.genesis.conversation_id
            || self.transition_block.incarnation != self.genesis.incarnation
            || self.transition_block.proposal.action_type
                != MlsControlActionTypeV1::AuthoritySetChange
            || self.authority_change.delivery_transition.conversation_id
                != self.transition_block.conversation_id
            || self.authority_change.delivery_transition.incarnation
                != self.transition_block.incarnation
            || self.authority_change.delivery_transition.proposal_id
                != self.transition_block.proposal.proposal_id
            || self.transition_block.height != self.history_block_count.saturating_add(1)
            || self.previous_set_certificate.height != self.transition_block.height
            || self.previous_set_certificate.block_hash != self.transition_block.block_hash()?
            || self.transition_block.transition_digest.as_deref() != Some(next_set_digest.as_str())
        {
            return Err("MLS authority bootstrap descriptor is internally inconsistent".into());
        }
        match (
            self.history_block_count,
            &self.transition_block.previous_block_hash,
        ) {
            (0, None) => {}
            (count, Some(hash)) if count > 0 => {
                validate_hash("previousBlockHash", hash)?;
            }
            _ => {
                return Err(
                    "MLS authority bootstrap transition has the wrong predecessor shape".into(),
                )
            }
        }
        Ok(())
    }

    pub fn bootstrap_id(&self) -> Result<String, String> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"kutup-mls-authority-bootstrap-v1\0");
        hash.update(serde_json::to_vec(self).map_err(|error| error.to_string())?);
        Ok(hex::encode(hash.finalize()))
    }
}

/// One bounded, hash-chained page of exact finalized control requests. Pages
/// can be retried independently and are not materialized until the complete
/// history digest and every quorum certificate have been verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedMlsAuthorityBootstrapPageV1 {
    pub descriptor: MlsAuthorityBootstrapDescriptorV1,
    pub bootstrap_id: String,
    pub page_index: u32,
    pub page_count: u32,
    pub start_height: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_page_hash: Option<String>,
    pub commits: Vec<CommitMlsControlBlockV1>,
}

impl FederatedMlsAuthorityBootstrapPageV1 {
    pub fn validate(&self) -> Result<(), String> {
        self.descriptor.validate()?;
        validate_hash("bootstrapId", &self.bootstrap_id)?;
        if self.bootstrap_id != self.descriptor.bootstrap_id()?
            || self.page_count == 0
            || self.page_count > i32::MAX as u32
            || self.page_index >= self.page_count
            || self.commits.len() > MAX_AUTHORITY_BOOTSTRAP_COMMITS_PER_PAGE
            || (self.descriptor.history_block_count > 0
                && u64::from(self.page_count) > self.descriptor.history_block_count)
        {
            return Err("MLS authority bootstrap page identifiers or bounds are invalid".into());
        }
        if self.page_index == 0 {
            if self.start_height != 1 || self.previous_page_hash.is_some() {
                return Err("first MLS authority bootstrap page has a predecessor".into());
            }
        } else {
            validate_hash(
                "previousPageHash",
                self.previous_page_hash
                    .as_deref()
                    .ok_or("MLS authority bootstrap page is missing its predecessor")?,
            )?;
        }
        if self.descriptor.history_block_count == 0 {
            if self.page_count != 1
                || self.page_index != 0
                || !self.commits.is_empty()
                || self.start_height != 1
            {
                return Err("empty MLS authority history must use one empty page".into());
            }
        } else {
            if self.commits.is_empty() {
                return Err("non-empty MLS authority history has an empty page".into());
            }
            for (offset, request) in self.commits.iter().enumerate() {
                request.validate_shape()?;
                let expected_height = self
                    .start_height
                    .checked_add(offset as u64)
                    .ok_or("MLS authority bootstrap height overflow")?;
                if request.finalized.block.conversation_id
                    != self.descriptor.genesis.conversation_id
                    || request.finalized.block.incarnation != self.descriptor.genesis.incarnation
                    || request.finalized.block.height != expected_height
                {
                    return Err(
                        "MLS authority bootstrap page contains a block at the wrong height".into(),
                    );
                }
            }
            let end = self
                .start_height
                .checked_add(self.commits.len() as u64 - 1)
                .ok_or("MLS authority bootstrap height overflow")?;
            if end > self.descriptor.history_block_count
                || (self.page_index + 1 == self.page_count
                    && end != self.descriptor.history_block_count)
                || (self.page_index + 1 < self.page_count
                    && end >= self.descriptor.history_block_count)
            {
                return Err("MLS authority bootstrap page has an invalid final height".into());
            }
        }
        let encoded = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if encoded.len() > MAX_AUTHORITY_BOOTSTRAP_PAGE_BYTES {
            return Err("MLS authority bootstrap page exceeds 8 MiB".into());
        }
        Ok(())
    }

    pub fn page_hash(&self) -> Result<String, String> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"kutup-mls-authority-bootstrap-page-v1\0");
        hash.update(serde_json::to_vec(self).map_err(|error| error.to_string())?);
        Ok(hex::encode(hash.finalize()))
    }
}

/// Public-history commitment used to initialize a participant server that is
/// first added after conversation genesis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MlsParticipantBootstrapDescriptorV1 {
    pub protocol_version: u16,
    pub genesis: MlsConversationGenesisV1,
    pub genesis_participant_domains: Vec<String>,
    pub destination: String,
    pub transition_request: CommitMlsControlBlockV1,
    pub delivery_digest: String,
    pub history_block_count: u64,
    pub history_digest: String,
}

impl MlsParticipantBootstrapDescriptorV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != MLS_PROTOCOL_VERSION {
            return Err("unsupported MLS participant bootstrap version".into());
        }
        self.genesis.validate()?;
        validate_participant_domain_set(&self.genesis_participant_domains)?;
        kutup_federation_proto::validate_server_name(&self.destination)
            .map_err(|error| error.to_string())?;
        validate_hash("deliveryDigest", &self.delivery_digest)?;
        validate_hash("historyDigest", &self.history_digest)?;
        self.transition_request.validate_shape()?;
        let block = &self.transition_request.finalized.block;
        let transition = self
            .transition_request
            .membership_transition
            .as_ref()
            .ok_or("MLS participant bootstrap requires a membership transition")?;
        if block.conversation_id != self.genesis.conversation_id
            || block.incarnation != self.genesis.incarnation
            || block.height != self.history_block_count.saturating_add(1)
            || transition
                .previous_participant_domains
                .binary_search_by(|domain| domain.as_str().cmp(&self.destination))
                .is_ok()
            || transition
                .next_participant_domains
                .binary_search_by(|domain| domain.as_str().cmp(&self.destination))
                .is_err()
            || transition
                .delivery_commitment(&self.destination)
                .map(|commitment| commitment.delivery_digest.as_str())
                != Some(self.delivery_digest.as_str())
        {
            return Err("MLS participant bootstrap descriptor is inconsistent".into());
        }
        Ok(())
    }

    pub fn bootstrap_id(&self) -> Result<String, String> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"kutup-mls-participant-bootstrap-v1\0");
        hash.update(serde_json::to_vec(self).map_err(|error| error.to_string())?);
        Ok(hex::encode(hash.finalize()))
    }
}

/// One bounded page of participant bootstrap history. Exactly the final page
/// carries the destination-private delivery committed by the descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedMlsParticipantBootstrapPageV1 {
    pub descriptor: MlsParticipantBootstrapDescriptorV1,
    pub bootstrap_id: String,
    pub page_index: u32,
    pub page_count: u32,
    pub start_height: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_page_hash: Option<String>,
    pub commits: Vec<CommitMlsControlBlockV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub membership_delivery: Option<MlsMembershipDeliveryV1>,
}

impl FederatedMlsParticipantBootstrapPageV1 {
    pub fn validate(&self) -> Result<(), String> {
        self.descriptor.validate()?;
        validate_hash("bootstrapId", &self.bootstrap_id)?;
        if self.bootstrap_id != self.descriptor.bootstrap_id()?
            || self.page_count == 0
            || self.page_count > i32::MAX as u32
            || self.page_index >= self.page_count
            || (self.descriptor.history_block_count > 0
                && u64::from(self.page_count) > self.descriptor.history_block_count)
            || self.commits.len() > MAX_AUTHORITY_BOOTSTRAP_COMMITS_PER_PAGE
        {
            return Err("MLS participant bootstrap page identifiers or bounds are invalid".into());
        }
        if self.page_index == 0 {
            if self.start_height != 1 || self.previous_page_hash.is_some() {
                return Err("first MLS participant bootstrap page has a predecessor".into());
            }
        } else {
            validate_hash(
                "previousPageHash",
                self.previous_page_hash
                    .as_deref()
                    .ok_or("MLS participant bootstrap page is missing its predecessor")?,
            )?;
        }
        if self.descriptor.history_block_count == 0 {
            if self.page_count != 1
                || self.page_index != 0
                || !self.commits.is_empty()
                || self.start_height != 1
            {
                return Err("empty MLS participant history must use one empty page".into());
            }
        } else {
            if self.commits.is_empty() {
                return Err("non-empty MLS participant history has an empty page".into());
            }
            for (offset, request) in self.commits.iter().enumerate() {
                request.validate_shape()?;
                if request.finalized.block.conversation_id
                    != self.descriptor.genesis.conversation_id
                    || request.finalized.block.incarnation != self.descriptor.genesis.incarnation
                    || request.finalized.block.height != self.start_height + offset as u64
                {
                    return Err(
                        "MLS participant bootstrap page contains a block at the wrong height"
                            .into(),
                    );
                }
            }
            let end = self
                .start_height
                .checked_add(self.commits.len() as u64 - 1)
                .ok_or("MLS participant bootstrap height overflow")?;
            if end > self.descriptor.history_block_count
                || (self.page_index + 1 == self.page_count
                    && end != self.descriptor.history_block_count)
                || (self.page_index + 1 < self.page_count
                    && end >= self.descriptor.history_block_count)
            {
                return Err("MLS participant bootstrap page has an invalid final height".into());
            }
        }
        if self.page_index + 1 == self.page_count {
            let delivery = self
                .membership_delivery
                .as_ref()
                .ok_or("final MLS participant bootstrap page omits its private delivery")?;
            delivery.verify_transition(
                self.descriptor
                    .transition_request
                    .membership_transition
                    .as_ref()
                    .expect("descriptor validated membership transition"),
            )?;
            if delivery.destination != self.descriptor.destination
                || delivery.delivery_digest()? != self.descriptor.delivery_digest
            {
                return Err("MLS participant bootstrap delivery commitment does not match".into());
            }
        } else if self.membership_delivery.is_some() {
            return Err("non-final MLS participant bootstrap page carries private delivery".into());
        }
        if serde_json::to_vec(self)
            .map_err(|error| error.to_string())?
            .len()
            > MAX_AUTHORITY_BOOTSTRAP_PAGE_BYTES
        {
            return Err("MLS participant bootstrap page exceeds 8 MiB".into());
        }
        Ok(())
    }

    pub fn page_hash(&self) -> Result<String, String> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"kutup-mls-participant-bootstrap-page-v1\0");
        hash.update(serde_json::to_vec(self).map_err(|error| error.to_string())?);
        Ok(hex::encode(hash.finalize()))
    }
}

pub fn verify_mls_participant_bootstrap_history(
    descriptor: &MlsParticipantBootstrapDescriptorV1,
    commits: &[CommitMlsControlBlockV1],
    delivery: &MlsMembershipDeliveryV1,
) -> Result<(), String> {
    descriptor.validate()?;
    if commits.len() as u64 != descriptor.history_block_count
        || mls_authority_history_digest(commits)? != descriptor.history_digest
    {
        return Err("MLS participant bootstrap history commitment does not match".into());
    }
    let replayed = replay_mls_control_history(
        &descriptor.genesis,
        &descriptor.genesis_participant_domains,
        commits,
    )?;
    let request = &descriptor.transition_request;
    let block = &request.finalized.block;
    if block.height != replayed.height + 1
        || block.epoch_before != replayed.epoch
        || block.previous_block_hash != replayed.previous_hash
    {
        return Err("MLS participant bootstrap transition does not extend history".into());
    }
    request.finalized.verify(&replayed.authorities)?;
    verify_bootstrap_owner_authorization(
        &descriptor.genesis.kind,
        block,
        replayed.owners.as_ref(),
    )?;
    let transition = request
        .membership_transition
        .as_ref()
        .expect("descriptor validated membership transition");
    if transition.previous_roster_commitment != replayed.roster_commitment
        || transition.previous_member_count != replayed.member_count
        || transition.previous_participant_domains != replayed.participant_domains
    {
        return Err("MLS participant bootstrap transition is not roster-contiguous".into());
    }
    delivery.verify_transition(transition)?;
    if delivery.destination != descriptor.destination
        || delivery.delivery_digest()? != descriptor.delivery_digest
        || delivery.epoch_after != block.epoch_after
    {
        return Err("MLS participant bootstrap private delivery does not match".into());
    }
    Ok(())
}

pub fn mls_authority_history_digest(commits: &[CommitMlsControlBlockV1]) -> Result<String, String> {
    let mut hash = Sha256::new();
    hash.update(b"kutup-mls-authority-history-v1\0");
    hash.update(
        u64::try_from(commits.len())
            .map_err(|_| "MLS authority history is too large")?
            .to_be_bytes(),
    );
    for request in commits {
        request.validate_shape()?;
        let bytes = serde_json::to_vec(request).map_err(|error| error.to_string())?;
        hash.update(
            u64::try_from(bytes.len())
                .map_err(|_| "MLS authority history entry is too large")?
                .to_be_bytes(),
        );
        hash.update(bytes);
    }
    Ok(hex::encode(hash.finalize()))
}

/// Verify the complete control history and the old-set authorization for a
/// pending authority transition. The returned set is the exact current set
/// immediately before the transition.
pub fn verify_mls_authority_bootstrap_history(
    descriptor: &MlsAuthorityBootstrapDescriptorV1,
    commits: &[CommitMlsControlBlockV1],
) -> Result<MlsAuthoritySetV1, String> {
    descriptor.validate()?;
    if commits.len() as u64 != descriptor.history_block_count
        || mls_authority_history_digest(commits)? != descriptor.history_digest
    {
        return Err("MLS authority bootstrap history commitment does not match".into());
    }

    let replayed = replay_mls_control_history(
        &descriptor.genesis,
        &descriptor.genesis_participant_domains,
        commits,
    )?;
    if replayed.participant_domains != descriptor.participant_domains {
        return Err("MLS authority bootstrap participant routing does not match history".into());
    }

    let transition = &descriptor.transition_block;
    let delivery = &descriptor.authority_change.delivery_transition;
    if transition.height != replayed.height + 1
        || transition.epoch_before != replayed.epoch
        || transition.previous_block_hash != replayed.previous_hash
        || replayed.authorities.sequence.checked_add(1)
            != Some(descriptor.authority_change.next_authority_set.sequence)
        || delivery.previous_roster_commitment != replayed.roster_commitment
        || delivery.next_roster_commitment != replayed.roster_commitment
        || delivery.previous_member_count != replayed.member_count
        || delivery.next_member_count != replayed.member_count
        || delivery.previous_participant_domains != replayed.participant_domains
        || delivery.next_participant_domains != replayed.participant_domains
    {
        return Err(
            "MLS authority bootstrap transition does not extend the verified history".into(),
        );
    }
    verify_bootstrap_owner_authorization(
        &descriptor.genesis.kind,
        transition,
        replayed.owners.as_ref(),
    )?;
    descriptor
        .previous_set_certificate
        .verify(&replayed.authorities)?;
    Ok(replayed.authorities)
}

pub(super) struct ReplayedMlsControlHistory {
    pub(super) authorities: MlsAuthoritySetV1,
    pub(super) owners: Option<MlsOwnerSetV1>,
    pub(super) height: u64,
    pub(super) epoch: u64,
    pub(super) previous_hash: Option<String>,
    pub(super) roster_commitment: String,
    pub(super) member_count: u32,
    pub(super) participant_domains: Vec<String>,
    pub(super) authorization_policy_sequence: u64,
    pub(super) cryptographic_policy_sequence: u64,
}

pub(super) fn replay_mls_control_history(
    genesis: &MlsConversationGenesisV1,
    genesis_participant_domains: &[String],
    commits: &[CommitMlsControlBlockV1],
) -> Result<ReplayedMlsControlHistory, String> {
    genesis.validate()?;
    validate_participant_domain_set(genesis_participant_domains)?;
    let mut replayed = ReplayedMlsControlHistory {
        authorities: genesis.authority_set.clone(),
        owners: genesis.owner_set.clone(),
        height: 0,
        epoch: genesis.initial_epoch,
        previous_hash: None,
        roster_commitment: genesis.roster_commitment.clone(),
        member_count: genesis.member_count,
        participant_domains: genesis_participant_domains.to_vec(),
        authorization_policy_sequence: 1,
        cryptographic_policy_sequence: 1,
    };
    for request in commits {
        request.validate_shape()?;
        let block = &request.finalized.block;
        block.proposal.verify()?;
        if block.conversation_id != genesis.conversation_id
            || block.incarnation != genesis.incarnation
            || block.height != replayed.height + 1
            || block.epoch_before != replayed.epoch
            || block.previous_block_hash != replayed.previous_hash
        {
            return Err("MLS bootstrap history is not an exact chain".into());
        }
        request.finalized.verify(&replayed.authorities)?;
        verify_bootstrap_owner_authorization(&genesis.kind, block, replayed.owners.as_ref())?;
        let block_hash = block.block_hash()?;
        if block.proposal.action_type == MlsControlActionTypeV1::AuthoritySetChange {
            let change = request
                .authority_change
                .as_ref()
                .ok_or("MLS authority history transition omits its public change")?;
            let next = &change.next_authority_set;
            let delivery = &change.delivery_transition;
            if delivery.previous_roster_commitment != replayed.roster_commitment
                || delivery.next_roster_commitment != replayed.roster_commitment
                || delivery.previous_member_count != replayed.member_count
                || delivery.next_member_count != replayed.member_count
                || delivery.previous_participant_domains != replayed.participant_domains
                || delivery.next_participant_domains != replayed.participant_domains
            {
                return Err("MLS authority history changes its roster or routing".into());
            }
            request
                .authority_transition
                .as_ref()
                .ok_or("MLS authority history transition omits its joint certificate")?
                .verify(&block_hash, &replayed.authorities, next)?;
            replayed.authorities = next.clone();
        } else if matches!(
            block.proposal.action_type,
            MlsControlActionTypeV1::MembershipChange
                | MlsControlActionTypeV1::RoutineAdmin
                | MlsControlActionTypeV1::DeviceSync
        ) && request.membership_transition.is_some()
        {
            let transition = request
                .membership_transition
                .as_ref()
                .expect("guarded transition");
            if transition.previous_roster_commitment != replayed.roster_commitment
                || transition.previous_member_count != replayed.member_count
                || replayed.participant_domains != transition.previous_participant_domains
            {
                return Err("MLS roster history is not contiguous".into());
            }
            replayed.roster_commitment = transition.next_roster_commitment.clone();
            replayed.member_count = transition.next_member_count;
            replayed.participant_domains = transition.next_participant_domains.clone();
        } else if block.proposal.action_type == MlsControlActionTypeV1::OwnerSetChange {
            let current = replayed
                .owners
                .as_ref()
                .ok_or("MLS owner history transition has no current owner set")?;
            let change = request
                .owner_change
                .as_ref()
                .ok_or("MLS owner history transition omits its public change")?;
            let next = &change.next_owner_set;
            next.validate()?;
            if current.sequence.checked_add(1) != Some(next.sequence) {
                return Err("MLS owner history sequence is not contiguous".into());
            }
            if change.delivery_transition.previous_roster_commitment != replayed.roster_commitment
                || change.delivery_transition.previous_member_count != replayed.member_count
                || change.delivery_transition.next_member_count != replayed.member_count
                || change.delivery_transition.previous_participant_domains
                    != replayed.participant_domains
                || change.delivery_transition.next_participant_domains
                    != replayed.participant_domains
            {
                return Err(
                    "MLS owner history changes membership routing or is not contiguous".into(),
                );
            }
            replayed.roster_commitment = change.delivery_transition.next_roster_commitment.clone();
            replayed.owners = Some(next.clone());
        } else if block.proposal.action_type == MlsControlActionTypeV1::CloseConversation {
            let transition = request
                .membership_transition
                .as_ref()
                .ok_or("MLS close history omits its participant delivery transition")?;
            if transition.previous_roster_commitment != replayed.roster_commitment
                || transition.next_roster_commitment != replayed.roster_commitment
                || transition.previous_member_count != replayed.member_count
                || transition.next_member_count != replayed.member_count
                || transition.previous_participant_domains != replayed.participant_domains
                || transition.next_participant_domains != replayed.participant_domains
            {
                return Err("MLS close history changes its roster or routing".into());
            }
        } else if matches!(
            block.proposal.action_type,
            MlsControlActionTypeV1::AuthorizationPolicyChange
                | MlsControlActionTypeV1::CryptographicPolicyChange
        ) {
            let transition = request
                .membership_transition
                .as_ref()
                .ok_or("MLS policy history omits its participant delivery transition")?;
            if transition.previous_roster_commitment != replayed.roster_commitment
                || transition.next_roster_commitment != replayed.roster_commitment
                || transition.previous_member_count != replayed.member_count
                || transition.next_member_count != replayed.member_count
                || transition.previous_participant_domains != replayed.participant_domains
                || transition.next_participant_domains != replayed.participant_domains
            {
                return Err("MLS policy history changes its roster or routing".into());
            }
            let sequence = match block.proposal.action_type {
                MlsControlActionTypeV1::AuthorizationPolicyChange => {
                    &mut replayed.authorization_policy_sequence
                }
                MlsControlActionTypeV1::CryptographicPolicyChange => {
                    &mut replayed.cryptographic_policy_sequence
                }
                _ => unreachable!("policy action checked above"),
            };
            *sequence = sequence
                .checked_add(1)
                .ok_or("MLS private policy sequence overflow")?;
        }
        replayed.height = block.height;
        replayed.epoch = block.epoch_after;
        replayed.previous_hash = Some(block_hash);
    }
    Ok(replayed)
}

fn verify_bootstrap_owner_authorization(
    kind: &MlsConversationKindV1,
    block: &MlsControlBlockV1,
    owners: Option<&MlsOwnerSetV1>,
) -> Result<(), String> {
    if *kind == MlsConversationKindV1::Group && block.proposal.action_type.requires_owner_quorum() {
        block
            .owner_approval
            .as_ref()
            .ok_or("security-sensitive MLS history block omits owner approval")?
            .verify(
                &block.proposal,
                block.transition_digest.as_deref(),
                owners.ok_or("group MLS authority history has no owner set")?,
            )
    } else if let (Some(certificate), Some(owners)) = (&block.owner_approval, owners) {
        certificate.verify(&block.proposal, block.transition_digest.as_deref(), owners)
    } else {
        Ok(())
    }
}

pub(super) fn validate_participant_domain_set(domains: &[String]) -> Result<(), String> {
    if domains.is_empty() || domains.len() > MAX_MLS_GROUP_ACCOUNTS {
        return Err("MLS participant-domain set is empty or too large".into());
    }
    let mut previous = None;
    for domain in domains {
        kutup_federation_proto::validate_server_name(domain).map_err(|error| error.to_string())?;
        if previous.is_some_and(|prior: &str| domain.as_str() <= prior) {
            return Err("MLS participant domains must be strictly ordered".into());
        }
        previous = Some(domain.as_str());
    }
    Ok(())
}

/// Purpose-specific signer for authority votes. HSM providers implement this
/// trait and must fail closed; callers never request exportable key material.
pub trait MlsControlSigner {
    fn key_id(&self) -> String;
    fn public_key(&self) -> String;
    fn sign_mls_control(&self, message: &[u8]) -> Result<[u8; 64], String>;
}

pub struct Ed25519MlsControlSigner(SigningKey);

impl Ed25519MlsControlSigner {
    pub fn new(signing_key: SigningKey) -> Self {
        Self(signing_key)
    }
}

impl MlsControlSigner for Ed25519MlsControlSigner {
    fn key_id(&self) -> String {
        hex::encode(Sha256::digest(self.0.verifying_key().as_bytes()))
    }

    fn public_key(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.0.verifying_key().as_bytes())
    }

    fn sign_mls_control(&self, message: &[u8]) -> Result<[u8; 64], String> {
        Ok(self.0.sign(message).to_bytes())
    }
}

/// Purpose-specific signer for owner approvals. It intentionally has no
/// federation or authority-vote methods.
pub trait MlsOwnerSigner {
    fn owner_id(&self) -> String;
    fn public_key(&self) -> String;
    fn sign_mls_owner_approval(&self, message: &[u8]) -> Result<[u8; 64], String>;
}

pub struct Ed25519MlsOwnerSigner {
    owner_id: String,
    key: SigningKey,
}

impl Ed25519MlsOwnerSigner {
    pub fn new(owner_id: String, key: SigningKey) -> Result<Self, String> {
        validate_hash("ownerId", &owner_id)?;
        Ok(Self { owner_id, key })
    }
}

impl MlsOwnerSigner for Ed25519MlsOwnerSigner {
    fn owner_id(&self) -> String {
        self.owner_id.clone()
    }

    fn public_key(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.key.verifying_key().as_bytes())
    }

    fn sign_mls_owner_approval(&self, message: &[u8]) -> Result<[u8; 64], String> {
        Ok(self.key.sign(message).to_bytes())
    }
}
