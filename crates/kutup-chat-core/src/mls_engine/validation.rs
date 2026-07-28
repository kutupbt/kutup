//! Durable MLS state, control-record, roster, and wire-boundary validation.

use super::*;

pub(super) fn validate_pending_membership_change(
    control: &PendingMlsMembershipChange,
) -> Result<()> {
    validate_group_id(&control.mls_group_id)?;
    validate_sha256_hex("MLS membership commit hash", &control.commit_hash)?;
    validate_group_roster(&control.next_roster)?;
    control
        .transition
        .validate()
        .map_err(|error| ChatError::Db(format!("invalid durable MLS transition: {error}")))?;
    control
        .vote_request
        .validate()
        .map_err(|error| ChatError::Db(format!("invalid durable MLS vote request: {error}")))?;
    let block = &control.vote_request.block;
    let transition_digest = control
        .transition
        .transition_digest()
        .map_err(ChatError::Db)?;
    if !matches!(
        block.proposal.action_type,
        MlsControlActionTypeV1::MembershipChange | MlsControlActionTypeV1::RoutineAdmin
    ) || block.conversation_id != control.transition.conversation_id
        || block.incarnation != control.transition.incarnation
        || block.proposal.proposal_id != control.transition.proposal_id
        || block.transition_digest.as_deref() != Some(transition_digest.as_str())
        || block.proposal.payload_digest != control.commit_hash
        || roster_commitment(&control.next_roster).map_err(ChatError::Db)?
            != control.transition.next_roster_commitment
        || control.next_roster.len() as u32 != control.transition.next_member_count
        || control.deliveries.len() != control.transition.deliveries.len()
    {
        return Err(ChatError::Db(
            "durable MLS membership control fields are inconsistent".into(),
        ));
    }
    match block.proposal.action_type {
        MlsControlActionTypeV1::MembershipChange
            if control.transition.previous_member_count == control.transition.next_member_count =>
        {
            return Err(ChatError::Db(
                "durable MLS membership control does not change membership".into(),
            ));
        }
        MlsControlActionTypeV1::RoutineAdmin
            if control.transition.previous_member_count != control.transition.next_member_count
                || control.transition.previous_participant_domains
                    != control.transition.next_participant_domains =>
        {
            return Err(ChatError::Db(
                "durable MLS administrator control changes membership routing".into(),
            ));
        }
        _ => {}
    }
    let mut previous_destination = None;
    for delivery in &control.deliveries {
        if previous_destination
            .as_deref()
            .is_some_and(|previous| delivery.destination.as_str() <= previous)
        {
            return Err(ChatError::Db(
                "durable MLS membership deliveries are not strictly ordered".into(),
            ));
        }
        delivery
            .verify_transition(&control.transition)
            .map_err(ChatError::Db)?;
        if delivery.epoch_after != block.epoch_after {
            return Err(ChatError::Db(
                "durable MLS membership delivery targets another epoch".into(),
            ));
        }
        previous_destination = Some(delivery.destination.clone());
    }
    if let Some(request) = &control.final_request {
        request.validate_shape().map_err(ChatError::Db)?;
        request
            .finalized
            .verify(&control.vote_request.authority_set)
            .map_err(ChatError::Db)?;
        if request.finalized.block != control.vote_request.block
            || request.membership_transition.as_ref() != Some(&control.transition)
            || request.authority_change.is_some()
            || request.authority_transition.is_some()
            || request.owner_change.is_some()
        {
            return Err(ChatError::Db(
                "durable finalized MLS membership request differs from its retry record".into(),
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_processed_control_envelope(
    receipt: &ProcessedMlsControlEnvelope,
) -> Result<()> {
    if receipt.envelope_id.is_nil()
        || receipt.send_id.is_nil()
        || receipt.conversation_id.is_nil()
        || receipt.incarnation == 0
        || !matches!(receipt.epoch.checked_sub(receipt.height), Some(0 | 1))
        || receipt
            .cursor
            .parse::<u64>()
            .ok()
            .filter(|cursor| *cursor > 0 && cursor.to_string() == receipt.cursor)
            .is_none()
    {
        return Err(ChatError::Db(
            "processed MLS control envelope has invalid identifiers or cursor".into(),
        ));
    }
    validate_sha256_hex("processed MLS control block hash", &receipt.block_hash)
        .map_err(|error| ChatError::Db(error.to_string()))
}

pub(super) fn insert_processed_control_envelope(
    metadata: &mut SnapshotMetadata,
    receipt: ProcessedMlsControlEnvelope,
) -> Result<()> {
    validate_processed_control_envelope(&receipt)?;
    let key = receipt.envelope_id.to_string();
    if let Some(existing) = metadata.processed_control_envelopes.get(&key) {
        if existing == &receipt {
            return Ok(());
        }
        return Err(ChatError::Trust(
            "MLS mailbox envelope id was replayed with different control metadata".into(),
        ));
    }
    if metadata
        .processed_control_envelopes
        .values()
        .any(|existing| {
            existing.send_id == receipt.send_id
                || existing.cursor == receipt.cursor
                || (existing.conversation_id == receipt.conversation_id
                    && existing.incarnation == receipt.incarnation
                    && existing.height == receipt.height
                    && existing.block_hash != receipt.block_hash)
        })
    {
        return Err(ChatError::Trust(
            "MLS control envelope reuses a durable send id, cursor, or height".into(),
        ));
    }
    if metadata.processed_control_envelopes.len() >= MAX_PENDING_COMMITS {
        let oldest = metadata
            .processed_control_envelopes
            .iter()
            .min_by_key(|(_, existing)| {
                existing
                    .cursor
                    .parse::<u64>()
                    .expect("validated durable cursor")
            })
            .map(|(key, _)| key.clone())
            .ok_or_else(|| ChatError::Db("processed MLS receipt index is inconsistent".into()))?;
        metadata.processed_control_envelopes.remove(&oldest);
    }
    metadata.processed_control_envelopes.insert(key, receipt);
    Ok(())
}

pub(super) fn validate_local_control_state(record: &LocalMlsConversationRecord) -> Result<()> {
    if record.request.genesis.kind != MlsConversationKindV1::Group
        || record.current_roster.is_empty()
        || record.current_roster.len() > 1000
    {
        return Err(ChatError::Db(
            "durable MLS group control roster is invalid".into(),
        ));
    }
    match (
        record.request.genesis.incarnation,
        record.recovery_digest.as_deref(),
    ) {
        (1, None) => {}
        (incarnation, Some(digest)) if incarnation > 1 => {
            validate_sha256_hex("durable MLS recovery digest", digest)
                .map_err(|error| ChatError::Db(error.to_string()))?;
        }
        _ => {
            return Err(ChatError::Db(
                "durable MLS recovery binding is inconsistent".into(),
            ))
        }
    }
    let mut previous = None;
    let mut admins = 0usize;
    let mut owner_ids = BTreeSet::new();
    for member in &record.current_roster {
        member
            .validate()
            .map_err(|error| ChatError::Db(format!("invalid durable MLS member: {error}")))?;
        let address = member.address.canonical();
        if previous
            .as_ref()
            .is_some_and(|prior: &String| address <= *prior)
        {
            return Err(ChatError::Db(
                "durable MLS group roster is not strictly ordered".into(),
            ));
        }
        previous = Some(address);
        admins += usize::from(member.is_admin);
        if let Some(owner_id) = &member.owner_id {
            owner_ids.insert(owner_id.as_str());
        }
    }
    record
        .current_authority_set
        .validate()
        .map_err(ChatError::Db)?;
    record.current_owner_set.validate().map_err(ChatError::Db)?;
    let declared_owners = record
        .current_owner_set
        .owners
        .iter()
        .map(|owner| owner.owner_id.as_str())
        .collect::<BTreeSet<_>>();
    if admins == 0
        || owner_ids != declared_owners
        || record.last_finalized_epoch
            != record
                .request
                .genesis
                .initial_epoch
                .saturating_add(record.last_finalized_height)
    {
        return Err(ChatError::Db(
            "durable MLS group roles or control epoch are inconsistent".into(),
        ));
    }
    match (record.last_finalized_height, &record.last_block_hash) {
        (0, None)
            if record.current_roster == record.request.members
                && record.current_authority_set == record.request.genesis.authority_set
                && &record.current_owner_set
                    == record.request.genesis.owner_set.as_ref().ok_or_else(|| {
                        ChatError::Db("group genesis has no owner set".into())
                    })? => {}
        (height, Some(hash)) if height > 0 => {
            validate_sha256_hex("durable MLS control block hash", hash)
                .map_err(|error| ChatError::Db(error.to_string()))?;
        }
        _ => {
            return Err(ChatError::Db(
                "durable MLS control head has an invalid predecessor shape".into(),
            ))
        }
    }
    Ok(())
}

fn validate_local_genesis_request(request: &CreateMlsConversationRequestV1) -> Result<()> {
    if request.genesis.incarnation == 1 {
        return request
            .validate()
            .map_err(|error| ChatError::Db(format!("invalid durable MLS genesis: {error}")));
    }
    request.genesis.validate().map_err(ChatError::Db)?;
    if request.genesis.kind != MlsConversationKindV1::Group
        || request.genesis.initial_epoch != 1
        || request.members.len() != request.genesis.member_count as usize
        || roster_commitment(&request.members).map_err(ChatError::Db)?
            != request.genesis.roster_commitment
    {
        return Err(ChatError::Db(
            "durable recovered MLS genesis has an inexact roster".into(),
        ));
    }
    let mut previous = None;
    let mut admins = 0usize;
    let mut owner_ids = BTreeSet::new();
    for member in &request.members {
        member.validate().map_err(ChatError::Db)?;
        let address = member.address.canonical();
        if previous
            .as_ref()
            .is_some_and(|prior: &String| address <= *prior)
        {
            return Err(ChatError::Db(
                "durable recovered MLS genesis roster is not ordered".into(),
            ));
        }
        previous = Some(address);
        admins += usize::from(member.is_admin);
        if let Some(owner_id) = member.owner_id.as_deref() {
            if !owner_ids.insert(owner_id) {
                return Err(ChatError::Db(
                    "durable recovered MLS genesis repeats an owner".into(),
                ));
            }
        }
    }
    let declared = request
        .genesis
        .owner_set
        .as_ref()
        .ok_or_else(|| ChatError::Db("recovered MLS genesis has no owners".into()))?
        .owners
        .iter()
        .map(|owner| owner.owner_id.as_str())
        .collect::<BTreeSet<_>>();
    if admins == 0 || owner_ids != declared {
        return Err(ChatError::Db(
            "durable recovered MLS genesis has inconsistent private roles".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_group_roster(roster: &[MlsConversationMemberV1]) -> Result<()> {
    if !(2..=1000).contains(&roster.len()) {
        return Err(ChatError::Invalid(
            "MLS group roster must contain 2-1000 accounts".into(),
        ));
    }
    let mut previous = None;
    let mut admins = 0usize;
    for member in roster {
        member.validate().map_err(ChatError::Invalid)?;
        let address = member.address.canonical();
        if previous
            .as_ref()
            .is_some_and(|prior: &String| address <= *prior)
        {
            return Err(ChatError::Invalid(
                "MLS group roster must be strictly ordered".into(),
            ));
        }
        previous = Some(address);
        admins += usize::from(member.is_admin);
    }
    if admins == 0 {
        return Err(ChatError::Invalid(
            "MLS group roster requires an administrator".into(),
        ));
    }
    roster_commitment(roster).map_err(ChatError::Invalid)?;
    Ok(())
}

pub(super) fn roster_by_address(
    roster: &[MlsConversationMemberV1],
) -> Result<BTreeMap<String, MlsConversationMemberV1>> {
    let mut result = BTreeMap::new();
    for member in roster {
        let address = member.address.canonical();
        if result.insert(address, member.clone()).is_some() {
            return Err(ChatError::Invalid(
                "MLS group roster repeats an account".into(),
            ));
        }
    }
    Ok(result)
}

pub(super) fn validate_private_roster_action(
    previous: &[MlsConversationMemberV1],
    next: &[MlsConversationMemberV1],
    action_type: MlsControlActionTypeV1,
) -> std::result::Result<(), String> {
    let previous_by_address = previous
        .iter()
        .map(|member| (member.address.canonical(), member))
        .collect::<BTreeMap<_, _>>();
    let next_by_address = next
        .iter()
        .map(|member| (member.address.canonical(), member))
        .collect::<BTreeMap<_, _>>();
    if previous_by_address.len() != previous.len() || next_by_address.len() != next.len() {
        return Err("MLS roster action repeats an account".into());
    }
    let added = next_by_address
        .keys()
        .filter(|address| !previous_by_address.contains_key(*address))
        .count();
    let removed = previous_by_address
        .keys()
        .filter(|address| !next_by_address.contains_key(*address))
        .count();
    let previous_owners = previous_by_address
        .iter()
        .filter_map(|(address, member)| {
            member
                .owner_id
                .as_ref()
                .map(|owner_id| (address.as_str(), owner_id.as_str()))
        })
        .collect::<BTreeMap<_, _>>();
    let next_owners = next_by_address
        .iter()
        .filter_map(|(address, member)| {
            member
                .owner_id
                .as_ref()
                .map(|owner_id| (address.as_str(), owner_id.as_str()))
        })
        .collect::<BTreeMap<_, _>>();
    if previous_owners != next_owners {
        return Err("ordinary MLS roster action cannot transfer, add, or remove owners".into());
    }
    match action_type {
        MlsControlActionTypeV1::MembershipChange => {
            if (added == 0 && removed == 0) || (added > 0 && removed > 0) {
                return Err(
                    "V1 MLS membership control must be exactly one add-only or remove-only change"
                        .into(),
                );
            }
            if previous_by_address.iter().any(|(address, current)| {
                next_by_address
                    .get(address)
                    .is_some_and(|next| *current != *next)
            }) {
                return Err(
                    "membership control cannot also change administrator or owner roles".into(),
                );
            }
        }
        MlsControlActionTypeV1::RoutineAdmin => {
            if added != 0 || removed != 0 {
                return Err(
                    "routine administrator control cannot add, remove, or replace members".into(),
                );
            }
            let administrator_changes = previous_by_address
                .iter()
                .filter(|(address, current)| {
                    next_by_address
                        .get(*address)
                        .is_some_and(|next| current.is_admin != next.is_admin)
                })
                .count();
            if administrator_changes == 0 {
                return Err(
                    "MLS routine administrator control must change at least one administrator role"
                        .into(),
                );
            }
        }
        _ => return Err("MLS private roster transition uses an unrelated action type".into()),
    }
    Ok(())
}

pub(super) fn participant_domains(roster: &[MlsConversationMemberV1]) -> Result<Vec<String>> {
    roster
        .iter()
        .map(|member| {
            member
                .address
                .server
                .clone()
                .ok_or_else(|| ChatError::Invalid("MLS member has no federation domain".into()))
        })
        .collect::<Result<BTreeSet<_>>>()
        .map(|domains| domains.into_iter().collect())
}

pub(super) fn parse_device_credential_identity(identity: &str) -> Result<(String, u32)> {
    let (account, device_id) = identity.rsplit_once('#').ok_or_else(|| {
        ChatError::Trust("MLS credential identity must be account@server#device".into())
    })?;
    let address: AccountAddress = account
        .parse()
        .map_err(|error: kutup_chat_proto::AddressError| ChatError::Trust(error.to_string()))?;
    if address.server.is_none() {
        return Err(ChatError::Trust(
            "MLS credential identity requires a federation domain".into(),
        ));
    }
    let device_id: u32 = device_id
        .parse()
        .map_err(|_| ChatError::Trust("MLS credential device id is invalid".into()))?;
    if !(1..=127).contains(&device_id) || format!("{}#{device_id}", address.canonical()) != identity
    {
        return Err(ChatError::Trust(
            "MLS credential identity is not canonical".into(),
        ));
    }
    Ok((address.canonical(), device_id))
}

pub(super) fn verify_exact_roster(
    members: impl Iterator<Item = Member>,
    expected: &[VerifiedMlsCredential],
) -> Result<()> {
    let mut expected_by_identity = BTreeMap::new();
    for credential in expected {
        validate_credential_identity(&credential.credential_identity)?;
        validate_credential_public_key(&credential.credential_public_key)?;
        if expected_by_identity
            .insert(
                credential.credential_identity.as_bytes().to_vec(),
                credential.credential_public_key.as_slice(),
            )
            .is_some()
        {
            return Err(ChatError::Trust(
                "expected MLS roster contains duplicate credential identities".into(),
            ));
        }
    }
    let mut actual_count = 0usize;
    let mut actual_identities = HashSet::new();
    for member in members {
        actual_count += 1;
        let identity = member.credential.serialized_content();
        if !actual_identities.insert(identity.to_vec()) {
            return Err(ChatError::Trust(
                "MLS roster contains duplicate credential identities".into(),
            ));
        }
        let expected_key = expected_by_identity.get(identity).ok_or_else(|| {
            ChatError::Trust("MLS roster contains a credential absent from the manifest".into())
        })?;
        if member.signature_key.as_slice() != *expected_key {
            return Err(ChatError::Trust(
                "MLS roster credential key differs from the manifest".into(),
            ));
        }
    }
    if actual_count != expected_by_identity.len() {
        return Err(ChatError::Trust(
            "MLS roster omits a transparency-verified expected member".into(),
        ));
    }
    Ok(())
}

pub(super) fn verify_member_credential(
    member: &Member,
    expected: &VerifiedMlsCredential,
) -> Result<()> {
    validate_credential_identity(&expected.credential_identity)?;
    validate_credential_public_key(&expected.credential_public_key)?;
    if member.credential.serialized_content() != expected.credential_identity.as_bytes()
        || member.signature_key != expected.credential_public_key
    {
        return Err(ChatError::Trust(
            "MLS sender credential differs from the transparency-verified manifest".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_pending_commit(pending: &PendingMlsCommit) -> Result<()> {
    validate_group_id(&pending.mls_group_id)?;
    validate_sha256_hex("MLS commit hash", &pending.commit_hash)?;
    if pending.epoch_after != pending.epoch_before.saturating_add(1)
        || pending.commit.is_empty()
        || pending.commit.len() > MAX_APPLICATION_BYTES
        || pending
            .welcome
            .as_ref()
            .is_some_and(|welcome| welcome.is_empty() || welcome.len() > MAX_APPLICATION_BYTES)
        || hex::encode(Sha256::digest(&pending.commit)) != pending.commit_hash
    {
        return Err(ChatError::Db(
            "durable MLS pending Commit material is invalid".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_sha256_hex(label: &str, value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ChatError::Invalid(format!(
            "{label} must be lowercase SHA-256 hex"
        )));
    }
    Ok(())
}

pub(super) fn validate_credential_public_key(key: &[u8]) -> Result<()> {
    if key.len() != 65 || key.first() != Some(&4) {
        return Err(ChatError::Invalid(
            "MLS credential key must be uncompressed P-256".into(),
        ));
    }
    p256::ecdsa::VerifyingKey::from_sec1_bytes(key)
        .map_err(|_| ChatError::Invalid("MLS credential key is invalid P-256".into()))?;
    Ok(())
}

pub(super) fn validate_metadata(metadata: &SnapshotMetadata) -> Result<()> {
    validate_credential_identity(&metadata.credential_identity)?;
    validate_credential_public_key(&metadata.credential_public_key)
        .map_err(|error| ChatError::Db(error.to_string()))?;
    let secret = p256::SecretKey::from_slice(&metadata.anonymous_delivery_private_key)
        .map_err(|_| ChatError::Db("invalid durable anonymous-delivery private key".into()))?;
    if secret.public_key().to_encoded_point(false).as_bytes().len() != 65 {
        return Err(ChatError::Db(
            "anonymous-delivery key is not uncompressed P-256".into(),
        ));
    }
    if metadata.pending_commits.len() > MAX_PENDING_COMMITS
        || metadata.pending_membership_changes.len() > MAX_PENDING_COMMITS
        || metadata.pending_authority_changes.len() > MAX_PENDING_COMMITS
        || metadata.pending_owner_changes.len() > MAX_PENDING_COMMITS
        || metadata.pending_closes.len() > MAX_PENDING_COMMITS
        || metadata.pending_recoveries.len() > MAX_PENDING_COMMITS
        || metadata.owner_approval_requests.len() > MAX_PENDING_COMMITS
    {
        return Err(ChatError::Db(
            "too many durable MLS pending control records".into(),
        ));
    }
    if metadata.group_control_private_keys.len() > MAX_PENDING_COMMITS {
        return Err(ChatError::Db(
            "too many durable MLS group control keys".into(),
        ));
    }
    if metadata.group_owner_private_keys.len() > MAX_PENDING_COMMITS
        || metadata.group_owner_candidate_private_keys.len() > MAX_PENDING_COMMITS
        || metadata.conversations.len() > MAX_PENDING_COMMITS
        || metadata.incarnation_history.len() > MAX_PENDING_COMMITS
        || metadata.processed_control_envelopes.len() > MAX_PENDING_COMMITS
    {
        return Err(ChatError::Db(
            "too many durable MLS owner or conversation records".into(),
        ));
    }
    for (group_id, private_key) in &metadata.group_control_private_keys {
        let decoded = decode_canonical_base64("MLS control group id", group_id, 0)?;
        validate_group_id(&decoded)?;
        if private_key.len() != 32 {
            return Err(ChatError::Db(
                "durable MLS group control key has the wrong length".into(),
            ));
        }
        P256SigningKey::from_slice(private_key)
            .map_err(|_| ChatError::Db("invalid durable MLS group control key".into()))?;
    }
    for (key, pending) in &metadata.pending_commits {
        validate_pending_commit(pending)?;
        if key != &BASE64.encode(&pending.mls_group_id) {
            return Err(ChatError::Db(
                "durable MLS pending Commit key does not match its group".into(),
            ));
        }
    }
    for (key, control) in &metadata.pending_membership_changes {
        validate_pending_membership_change(control)?;
        if key != &BASE64.encode(&control.mls_group_id)
            || !metadata.pending_commits.contains_key(key)
        {
            return Err(ChatError::Db(
                "durable MLS membership control key or pending Commit is inconsistent".into(),
            ));
        }
    }
    for (key, control) in &metadata.pending_authority_changes {
        control.validate_durable()?;
        if key != &BASE64.encode(&control.mls_group_id)
            || !metadata.pending_commits.contains_key(key)
            || metadata.pending_membership_changes.contains_key(key)
        {
            return Err(ChatError::Db(
                "durable MLS authority control key or pending Commit is inconsistent".into(),
            ));
        }
    }
    for (key, control) in &metadata.pending_owner_changes {
        control.validate_durable()?;
        if key != &BASE64.encode(&control.mls_group_id)
            || !metadata.pending_commits.contains_key(key)
            || metadata.pending_membership_changes.contains_key(key)
            || metadata.pending_authority_changes.contains_key(key)
        {
            return Err(ChatError::Db(
                "durable MLS owner control key or pending Commit is inconsistent".into(),
            ));
        }
    }
    for (key, control) in &metadata.pending_closes {
        control.validate_durable()?;
        if key != &BASE64.encode(&control.mls_group_id)
            || !metadata.pending_commits.contains_key(key)
            || metadata.pending_membership_changes.contains_key(key)
            || metadata.pending_authority_changes.contains_key(key)
            || metadata.pending_owner_changes.contains_key(key)
        {
            return Err(ChatError::Db(
                "durable MLS close key or pending Commit is inconsistent".into(),
            ));
        }
    }
    for (key, control) in &metadata.pending_recoveries {
        control.validate_durable()?;
        let new_key = BASE64.encode(&control.new_mls_group_id);
        if key != &BASE64.encode(&control.mls_group_id)
            || !metadata.pending_commits.contains_key(&new_key)
            || metadata.pending_membership_changes.contains_key(key)
            || metadata.pending_authority_changes.contains_key(key)
            || metadata.pending_owner_changes.contains_key(key)
            || metadata.pending_closes.contains_key(key)
            || !metadata.group_control_private_keys.contains_key(&new_key)
            || !metadata.group_owner_private_keys.contains_key(&new_key)
        {
            return Err(ChatError::Db(
                "durable MLS recovery key or replacement Commit is inconsistent".into(),
            ));
        }
    }
    for (key, request) in &metadata.owner_approval_requests {
        request.validate_durable()?;
        if key != &BASE64.encode(&request.mls_group_id)
            || metadata.pending_owner_changes.contains_key(key)
            || metadata.pending_closes.contains_key(key)
            || metadata.pending_recoveries.contains_key(key)
        {
            return Err(ChatError::Db(
                "durable MLS owner approval request conflicts with local control state".into(),
            ));
        }
    }
    for (group_id, private_key) in &metadata.group_owner_private_keys {
        let decoded = decode_canonical_base64("MLS owner group id", group_id, 0)?;
        validate_group_id(&decoded)?;
        let seed: [u8; 32] = private_key.as_slice().try_into().map_err(|_| {
            ChatError::Db("durable MLS group owner key has the wrong length".into())
        })?;
        ed25519_dalek::SigningKey::from_bytes(&seed);
    }
    for (group_id, private_key) in &metadata.group_owner_candidate_private_keys {
        let decoded = decode_canonical_base64("MLS owner candidate group id", group_id, 0)?;
        validate_group_id(&decoded)?;
        let seed: [u8; 32] = private_key.as_slice().try_into().map_err(|_| {
            ChatError::Db("durable MLS owner candidate key has the wrong length".into())
        })?;
        ed25519_dalek::SigningKey::from_bytes(&seed);
        if metadata.group_owner_private_keys.contains_key(group_id) {
            return Err(ChatError::Db(
                "MLS group has both active and candidate owner private keys".into(),
            ));
        }
    }
    let mut conversation_group_ids = HashSet::with_capacity(metadata.conversations.len());
    for (conversation_id, record) in &metadata.conversations {
        validate_local_genesis_request(&record.request)?;
        if record.request.genesis.kind != MlsConversationKindV1::Group
            || conversation_id != &record.request.genesis.conversation_id.to_string()
        {
            return Err(ChatError::Db(
                "durable MLS conversation key or kind is invalid".into(),
            ));
        }
        validate_local_control_state(record)?;
        let group_id = decode_canonical_base64(
            "durable MLS genesis group id",
            &record.request.genesis.mls_group_id,
            0,
        )?;
        let group_key = BASE64.encode(&group_id);
        if !conversation_group_ids.insert(group_key.clone()) {
            return Err(ChatError::Db(
                "durable MLS conversations contain a duplicate GroupId".into(),
            ));
        }
        if !metadata.group_control_private_keys.contains_key(&group_key) {
            return Err(ChatError::Db(
                "durable MLS genesis has no group control key".into(),
            ));
        }
        if let Some(candidates) = metadata.owner_candidates.get(&group_key) {
            for (account, candidate) in candidates {
                candidate.verify().map_err(ChatError::Db)?;
                if candidate.conversation_id != record.request.genesis.conversation_id
                    || candidate.incarnation != record.request.genesis.incarnation
                    || candidate.account.canonical() != *account
                    || !record
                        .current_roster
                        .iter()
                        .any(|member| member.address.canonical() == *account)
                {
                    return Err(ChatError::Db(
                        "durable MLS owner candidate differs from its conversation".into(),
                    ));
                }
            }
        }
        if metadata.group_owner_private_keys.contains_key(&group_key) {
            let owner = group_owner_credential(metadata, &group_id)?;
            let (local_address, _) =
                parse_device_credential_identity(&metadata.credential_identity)?;
            if record
                .current_owner_set
                .owner(&owner.owner_id)
                .is_none_or(|declared| declared.public_key != BASE64.encode(&owner.public_key))
                || !record.current_roster.iter().any(|member| {
                    member.address.canonical() == local_address
                        && member.owner_id.as_deref() == Some(owner.owner_id.as_str())
                })
            {
                return Err(ChatError::Db(
                    "durable MLS owner key differs from its current private role".into(),
                ));
            }
        }
        match (record.status, &record.server_genesis_hash) {
            (LocalMlsConversationStatus::PendingGenesis, None) => {}
            (
                LocalMlsConversationStatus::Active | LocalMlsConversationStatus::Closed,
                Some(hash),
            ) => {
                validate_sha256_hex("durable MLS genesis hash", hash)
                    .map_err(|error| ChatError::Db(error.to_string()))?;
                let expected = record
                    .request
                    .genesis
                    .genesis_hash()
                    .map_err(ChatError::Db)?;
                if hash != &expected {
                    return Err(ChatError::Db(
                        "durable MLS genesis hash differs from its request".into(),
                    ));
                }
            }
            (LocalMlsConversationStatus::ReadOnly, _) => {
                return Err(ChatError::Db(
                    "current MLS conversation cannot be read-only".into(),
                ))
            }
            _ => {
                return Err(ChatError::Db(
                    "durable MLS genesis publication state is inconsistent".into(),
                ))
            }
        }
        if let Some(control) = metadata.pending_membership_changes.get(&group_key) {
            let block = &control.vote_request.block;
            if block.conversation_id != record.request.genesis.conversation_id
                || block.incarnation != record.request.genesis.incarnation
                || block.height != record.last_finalized_height.saturating_add(1)
                || block.previous_block_hash != record.last_block_hash
                || block.epoch_before != record.last_finalized_epoch
                || control.transition.previous_roster_commitment
                    != roster_commitment(&record.current_roster).map_err(ChatError::Db)?
            {
                return Err(ChatError::Db(
                    "durable MLS membership control does not extend its conversation pin".into(),
                ));
            }
        }
        if let Some(control) = metadata.pending_authority_changes.get(&group_key) {
            let block = &control.vote_request.block;
            let transition = &control.authority_change.delivery_transition;
            if block.conversation_id != record.request.genesis.conversation_id
                || block.incarnation != record.request.genesis.incarnation
                || block.height != record.last_finalized_height.saturating_add(1)
                || block.previous_block_hash != record.last_block_hash
                || block.epoch_before != record.last_finalized_epoch
                || control.vote_request.authority_set != record.current_authority_set
                || transition.previous_roster_commitment
                    != roster_commitment(&record.current_roster).map_err(ChatError::Db)?
                || transition.next_roster_commitment != transition.previous_roster_commitment
            {
                return Err(ChatError::Db(
                    "durable MLS authority control does not extend its conversation pin".into(),
                ));
            }
            block
                .owner_approval
                .as_ref()
                .ok_or_else(|| {
                    ChatError::Db("durable authority change has no owner quorum".into())
                })?
                .verify(
                    &block.proposal,
                    block.transition_digest.as_deref(),
                    &record.current_owner_set,
                )
                .map_err(ChatError::Db)?;
        }
        if let Some(control) = metadata.pending_owner_changes.get(&group_key) {
            let block = &control.vote_request.block;
            let transition = &control.owner_change.delivery_transition;
            if block.conversation_id != record.request.genesis.conversation_id
                || block.incarnation != record.request.genesis.incarnation
                || block.height != record.last_finalized_height.saturating_add(1)
                || block.previous_block_hash != record.last_block_hash
                || block.epoch_before != record.last_finalized_epoch
                || control.vote_request.authority_set != record.current_authority_set
                || transition.previous_roster_commitment
                    != roster_commitment(&record.current_roster).map_err(ChatError::Db)?
                || record.current_owner_set.sequence.checked_add(1)
                    != Some(control.owner_change.next_owner_set.sequence)
            {
                return Err(ChatError::Db(
                    "durable MLS owner control does not extend its conversation pin".into(),
                ));
            }
            control
                .vote_request
                .block
                .owner_approval
                .as_ref()
                .ok_or_else(|| ChatError::Db("durable owner change has no owner quorum".into()))?
                .verify_partial(
                    &block.proposal,
                    block.transition_digest.as_deref(),
                    &record.current_owner_set,
                )
                .map_err(ChatError::Db)?;
        }
        if let Some(control) = metadata.pending_closes.get(&group_key) {
            let block = &control.vote_request.block;
            let transition = &control.transition;
            if record.status != LocalMlsConversationStatus::Active
                || block.conversation_id != record.request.genesis.conversation_id
                || block.incarnation != record.request.genesis.incarnation
                || block.height != record.last_finalized_height.saturating_add(1)
                || block.previous_block_hash != record.last_block_hash
                || block.epoch_before != record.last_finalized_epoch
                || control.vote_request.authority_set != record.current_authority_set
                || transition.previous_roster_commitment
                    != roster_commitment(&record.current_roster).map_err(ChatError::Db)?
                || transition.next_roster_commitment != transition.previous_roster_commitment
                || control.current_roster != record.current_roster
            {
                return Err(ChatError::Db(
                    "durable MLS close does not extend its conversation pin".into(),
                ));
            }
            control
                .vote_request
                .block
                .owner_approval
                .as_ref()
                .ok_or_else(|| ChatError::Db("durable close has no owner approvals".into()))?
                .verify_partial(
                    &block.proposal,
                    block.transition_digest.as_deref(),
                    &record.current_owner_set,
                )
                .map_err(ChatError::Db)?;
        }
        if let Some(control) = metadata.pending_recoveries.get(&group_key) {
            super::recovery::validate_pending_recovery(control, record)?;
        }
        if let Some(pending) = metadata.owner_approval_requests.get(&group_key) {
            let request = &pending.request;
            let requester = pending.requester.canonical();
            let requester_is_owner = record.current_roster.iter().any(|member| {
                member.address.canonical() == requester
                    && member
                        .owner_id
                        .as_deref()
                        .is_some_and(|owner_id| record.current_owner_set.owner(owner_id).is_some())
            });
            if request.proposal.conversation_id != record.request.genesis.conversation_id
                || request.proposal.incarnation != record.request.genesis.incarnation
                || request.proposal.base_epoch != record.last_finalized_epoch
                || request.owner_set_sequence != record.current_owner_set.sequence
                || !requester_is_owner
            {
                return Err(ChatError::Db(
                    "durable MLS owner approval request differs from its conversation pin".into(),
                ));
            }
            let pinned_roster = roster_commitment(&record.current_roster).map_err(ChatError::Db)?;
            match request.proposal.action_type {
                MlsControlActionTypeV1::OwnerSetChange
                | MlsControlActionTypeV1::CloseConversation
                    if request
                        .delivery_transition()
                        .map_err(ChatError::Db)?
                        .previous_roster_commitment
                        == pinned_roster => {}
                MlsControlActionTypeV1::RecoverIncarnation
                    if request
                        .incarnation_recovery
                        .as_ref()
                        .is_some_and(|recovery| {
                            recovery.previous_genesis_hash
                                == record.request.genesis.genesis_hash().unwrap_or_default()
                                && recovery.previous_height == record.last_finalized_height
                                && recovery.previous_epoch == record.last_finalized_epoch
                                && recovery.previous_block_hash == record.last_block_hash
                                && recovery.previous_roster_commitment == pinned_roster
                                && recovery.new_genesis.owner_set.as_ref()
                                    == Some(&record.current_owner_set)
                        }) => {}
                _ => {
                    return Err(ChatError::Db(
                        "durable MLS owner approval transition differs from its pin".into(),
                    ))
                }
            }
        }
    }
    let mut last_incarnation = BTreeMap::<Uuid, u64>::new();
    for (key, record) in &metadata.incarnation_history {
        validate_local_genesis_request(&record.request)?;
        validate_local_control_state(record)?;
        let expected_key = format!(
            "{}:{:020}",
            record.request.genesis.conversation_id, record.request.genesis.incarnation
        );
        if key != &expected_key
            || record.status != LocalMlsConversationStatus::ReadOnly
            || record.server_genesis_hash.as_deref()
                != Some(
                    record
                        .request
                        .genesis
                        .genesis_hash()
                        .map_err(ChatError::Db)?
                        .as_str(),
                )
        {
            return Err(ChatError::Db(
                "durable MLS incarnation history is inconsistent".into(),
            ));
        }
        let previous = last_incarnation
            .entry(record.request.genesis.conversation_id)
            .or_insert(0);
        if previous.checked_add(1) != Some(record.request.genesis.incarnation) {
            return Err(ChatError::Db(
                "durable MLS incarnation history has a gap".into(),
            ));
        }
        *previous = record.request.genesis.incarnation;
    }
    for (conversation_id, last) in last_incarnation {
        let current = metadata
            .conversations
            .get(&conversation_id.to_string())
            .ok_or_else(|| ChatError::Db("MLS incarnation history has no current record".into()))?;
        if last.checked_add(1) != Some(current.request.genesis.incarnation) {
            return Err(ChatError::Db(
                "current MLS incarnation does not extend its history".into(),
            ));
        }
    }
    let mut receipt_send_ids = HashSet::with_capacity(metadata.processed_control_envelopes.len());
    let mut receipt_cursors = HashSet::with_capacity(metadata.processed_control_envelopes.len());
    for (envelope_id, receipt) in &metadata.processed_control_envelopes {
        validate_processed_control_envelope(receipt)?;
        if envelope_id != &receipt.envelope_id.to_string()
            || !receipt_send_ids.insert(receipt.send_id)
            || !receipt_cursors.insert(receipt.cursor.as_str())
        {
            return Err(ChatError::Db(
                "durable MLS control receipts contain duplicate identifiers".into(),
            ));
        }
        let conversation = metadata
            .conversations
            .get(&receipt.conversation_id.to_string())
            .filter(|record| record.request.genesis.incarnation == receipt.incarnation)
            .or_else(|| {
                metadata.incarnation_history.values().find(|record| {
                    record.request.genesis.conversation_id == receipt.conversation_id
                        && record.request.genesis.incarnation == receipt.incarnation
                })
            })
            .ok_or_else(|| {
                ChatError::Db("durable MLS control receipt has no incarnation".into())
            })?;
        if conversation.request.genesis.incarnation != receipt.incarnation
            || conversation
                .request
                .genesis
                .initial_epoch
                .checked_add(receipt.height)
                != Some(receipt.epoch)
            || receipt.height > conversation.last_finalized_height
            || receipt.epoch > conversation.last_finalized_epoch
            || (receipt.height == conversation.last_finalized_height
                && conversation
                    .last_block_hash
                    .as_deref()
                    .or(conversation.recovery_digest.as_deref())
                    != Some(receipt.block_hash.as_str()))
        {
            return Err(ChatError::Db(
                "durable MLS control receipt differs from its conversation pin".into(),
            ));
        }
    }
    for group_id in metadata
        .group_owner_private_keys
        .keys()
        .chain(metadata.group_owner_candidate_private_keys.keys())
        .chain(metadata.owner_candidates.keys())
        .chain(metadata.owner_approval_requests.keys())
        .chain(metadata.pending_closes.keys())
    {
        if !metadata
            .conversations
            .values()
            .any(|record| &record.request.genesis.mls_group_id == group_id)
            && !metadata
                .pending_recoveries
                .values()
                .any(|recovery| BASE64.encode(&recovery.new_mls_group_id) == *group_id)
        {
            return Err(ChatError::Db(
                "durable MLS owner material has no conversation record".into(),
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_credential_identity(identity: &str) -> Result<()> {
    if identity.is_empty()
        || identity.len() > MAX_CREDENTIAL_IDENTITY_BYTES
        || identity.trim() != identity
        || identity.chars().any(char::is_control)
    {
        return Err(ChatError::Invalid(
            "MLS credential identity must be canonical and at most 512 bytes".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_group_id(group_id: &[u8]) -> Result<()> {
    if !(MIN_MLS_GROUP_ID_BYTES..=MAX_MLS_GROUP_ID_BYTES).contains(&group_id.len()) {
        return Err(ChatError::Invalid(
            "MLS GroupId must contain 16-255 bytes".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_send(
    send_id: &str,
    conversation_id: [u8; 16],
    incarnation: u64,
    group_id: &[u8],
    plaintext: &[u8],
    created_at_ms: i64,
) -> Result<()> {
    Uuid::parse_str(send_id)
        .map_err(|_| ChatError::Invalid("MLS send id must be a UUID".into()))?;
    if conversation_id == [0; 16]
        || incarnation == 0
        || plaintext.is_empty()
        || plaintext.len() > MAX_APPLICATION_BYTES
        || created_at_ms < 0
    {
        return Err(ChatError::Invalid(
            "MLS application message has invalid conversation, size, or clock".into(),
        ));
    }
    validate_group_id(group_id)
}

pub(super) fn ensure_v1_group(group: &MlsGroup) -> Result<()> {
    if group.ciphersuite() != KUTUP_MLS_V1_CIPHERSUITE {
        return Err(ChatError::UnsupportedSuite(group.ciphersuite() as u16));
    }
    Ok(())
}

pub(super) fn local_group_state(group: &MlsGroup) -> LocalMlsGroupState {
    LocalMlsGroupState {
        mls_group_id: group.group_id().as_slice().to_vec(),
        epoch: group.epoch().as_u64(),
    }
}

pub(super) fn mls_error(context: &str, error: impl std::fmt::Display) -> ChatError {
    ChatError::Protocol(format!("{context}: {error}"))
}
