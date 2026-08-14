//! Shared validation helpers for MLS HTTP and repository boundaries.

use std::collections::BTreeSet;

use axum::http::header::{AUTHORIZATION, COOKIE};
use axum::http::HeaderMap;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use sha2::{Digest as _, Sha256};

use crate::error::{AppError, AppResult};

pub(super) fn ensure_anonymous_context(headers: &HeaderMap) -> AppResult<()> {
    if headers.contains_key(AUTHORIZATION) || headers.contains_key(COOKIE) {
        return Err(AppError::bad_request(
            "anonymous MLS routes reject authorization and cookie context",
        ));
    }
    Ok(())
}

pub(super) fn decode_capability(value: &str) -> AppResult<[u8; 16]> {
    let bytes = decode_canonical_base64("MLS delivery capability", value)?;
    bytes
        .try_into()
        .map_err(|_| AppError::bad_request("MLS delivery capability must be 16 bytes"))
}

pub(super) fn decode_canonical_base64(name: &str, value: &str) -> AppResult<Vec<u8>> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| AppError::bad_request(format!("{name} must be canonical base64")))?;
    if STANDARD.encode(&bytes) != value {
        return Err(AppError::bad_request(format!(
            "{name} must be canonical base64"
        )));
    }
    Ok(bytes)
}

pub(super) fn validate_participant_domains(
    members: &[kutup_chat_proto::MlsConversationMemberV1],
    participant_domains: &[String],
) -> AppResult<()> {
    if participant_domains.is_empty()
        || participant_domains.len() > kutup_chat_proto::MAX_MLS_GROUP_ACCOUNTS
    {
        return Err(AppError::bad_request(
            "MLS participant-domain set is empty or too large",
        ));
    }
    let mut previous = None;
    for domain in participant_domains {
        kutup_federation_proto::validate_server_name(domain)
            .map_err(|error| AppError::bad_request(error.to_string()))?;
        if previous.is_some_and(|prior: &str| domain.as_str() <= prior) {
            return Err(AppError::bad_request(
                "MLS participant domains must be strictly ordered",
            ));
        }
        previous = Some(domain.as_str());
    }
    if !members.is_empty() {
        let actual: BTreeSet<&str> = members
            .iter()
            .filter_map(|member| member.address.server.as_deref())
            .collect();
        let expected: BTreeSet<&str> = participant_domains.iter().map(String::as_str).collect();
        if actual != expected {
            return Err(AppError::bad_request(
                "MLS participant domains do not match the initial roster",
            ));
        }
    }
    Ok(())
}

pub(super) fn unavailable() -> AppError {
    AppError::not_found("MLS recipient unavailable")
}

pub(super) fn scoped_digest(context: &[u8], value: &[u8]) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(context);
    hash.update(value);
    hash.finalize().to_vec()
}
