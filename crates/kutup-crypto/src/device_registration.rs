//! A collaboration device signed by its account (docs/plans/device-registration.md).
//!
//! A browser tab or the CLI signs collaboration frames with a device key of
//! its own; the server keeps a frame only from an active device of the
//! sender's account. The account authority (from the master key) vouches for
//! each device key, so a session token alone, without the account's keys,
//! cannot add one. The statement names the incarnation (the authority's hash),
//! the account's server and that server's id for it, the device key, what it
//! is for, a one-time challenge the server issued (so a captured registration
//! cannot be played again) and when it was made. The time gives a statement
//! an age: a server elsewhere keeps an announced device only while its newest
//! statement is fresh (a lease, renewed by the client), so a revocation a
//! bridge withholds matters for a bounded time. The device's label is not in
//! it: it can be renamed.

use crate::primitives::{Suite, VerifyingKey};
use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::drive_object::parse_canonical_uuid;
use crate::error::{CryptoError, Result};
use crate::identity::{incarnation_id_from_authority_public, AccountIdentityKeysV1};

const DOMAIN: &[u8] = b"kutup/device-registration/v1\0";
/// The device signs collaboration frames.
pub const PURPOSE_COLLAB_FRAMES: u8 = 1;
/// The server's one-time challenge.
pub const CHALLENGE_LEN: usize = 32;

fn invalid(what: &str) -> CryptoError {
    CryptoError::InvalidInput(format!("device registration: {what}"))
}

/// What the account says about one device.
#[derive(Clone, Copy, Debug)]
pub struct DeviceStatement<'a> {
    /// The account's server (its domain, as in `username@server`): the
    /// statement holds on that server only.
    pub server: &'a str,
    /// The server's id for the account (a canonical UUID).
    pub user_id: &'a str,
    /// The Ed25519 key the device signs frames with.
    pub device_public: &'a [u8; 32],
    /// What the device is for ([`PURPOSE_COLLAB_FRAMES`]).
    pub purpose: u8,
    /// The server's one-time challenge.
    pub challenge: &'a [u8; CHALLENGE_LEN],
    /// When it was made, UTC milliseconds: the statement's age.
    pub issued_at_ms: i64,
}

/// The bytes the authority signs for `statement` under `incarnation_id`.
pub fn signing_bytes(incarnation_id: &str, statement: &DeviceStatement<'_>) -> Result<Vec<u8>> {
    let incarnation = hex::decode(incarnation_id)
        .ok()
        .filter(|bytes| bytes.len() == 32 && hex::encode(bytes) == incarnation_id)
        .ok_or_else(|| invalid("incarnation id"))?;
    let user =
        parse_canonical_uuid(statement.user_id, "account").map_err(|_| invalid("user id"))?;
    let server = statement.server;
    check_server(server)?;
    if statement.purpose != PURPOSE_COLLAB_FRAMES {
        return Err(invalid("purpose"));
    }
    if statement.issued_at_ms <= 0 {
        return Err(invalid("issuedAtMs"));
    }
    let mut out =
        Vec::with_capacity(DOMAIN.len() + 32 + 2 + server.len() + 16 + 32 + 1 + CHALLENGE_LEN + 8);
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(&incarnation);
    out.extend_from_slice(&(server.len() as u16).to_be_bytes());
    out.extend_from_slice(server.as_bytes());
    out.extend_from_slice(&user);
    out.extend_from_slice(statement.device_public);
    out.push(statement.purpose);
    out.extend_from_slice(statement.challenge);
    out.extend_from_slice(&statement.issued_at_ms.to_be_bytes());
    Ok(out)
}

/// The account's statement, signed with its authority: the canonical base64
/// signature.
pub fn sign(identity: &AccountIdentityKeysV1, statement: &DeviceStatement<'_>) -> Result<String> {
    let bytes = signing_bytes(&identity.incarnation_id(), statement)?;
    Ok(STANDARD.encode(identity.authority_signing_key().sign(&bytes)))
}

/// Checks a statement against the account's authority key (whose hash is the
/// incarnation it must name). That the challenge is the server's, fresh and
/// unused, and how old the statement may be, are the server's to check; this
/// is the signature and its form.
pub fn verify(
    authority_public: &[u8; 32],
    statement: &DeviceStatement<'_>,
    signature: &str,
) -> Result<()> {
    let bytes = signing_bytes(
        &incarnation_id_from_authority_public(authority_public),
        statement,
    )?;
    verify_signature(authority_public, &bytes, signature)
}

// --- revocation --------------------------------------------------------------

const REVOCATION_DOMAIN: &[u8] = b"kutup/device-revocation/v1\0";

/// The bytes the authority signs to revoke `device_public` for good: the
/// account's incarnation, its server, the key, and when.
pub fn revocation_bytes(
    incarnation_id: &str,
    server: &str,
    device_public: &[u8; 32],
    revoked_at_ms: i64,
) -> Result<Vec<u8>> {
    let incarnation = hex::decode(incarnation_id)
        .ok()
        .filter(|bytes| bytes.len() == 32 && hex::encode(bytes) == incarnation_id)
        .ok_or_else(|| invalid("incarnation id"))?;
    check_server(server)?;
    if revoked_at_ms <= 0 {
        return Err(invalid("revokedAtMs"));
    }
    let mut out = Vec::with_capacity(REVOCATION_DOMAIN.len() + 32 + 2 + server.len() + 32 + 8);
    out.extend_from_slice(REVOCATION_DOMAIN);
    out.extend_from_slice(&incarnation);
    out.extend_from_slice(&(server.len() as u16).to_be_bytes());
    out.extend_from_slice(server.as_bytes());
    out.extend_from_slice(device_public);
    out.extend_from_slice(&revoked_at_ms.to_be_bytes());
    Ok(out)
}

/// The account's revocation of a device key, signed with its authority:
/// the canonical base64 signature. Every client that unlocks the account
/// (from the master key, or after recovery) can make one.
pub fn sign_revocation(
    identity: &AccountIdentityKeysV1,
    server: &str,
    device_public: &[u8; 32],
    revoked_at_ms: i64,
) -> Result<String> {
    let bytes = revocation_bytes(
        &identity.incarnation_id(),
        server,
        device_public,
        revoked_at_ms,
    )?;
    Ok(STANDARD.encode(identity.authority_signing_key().sign(&bytes)))
}

/// Checks a revocation against the account's authority key.
pub fn verify_revocation(
    authority_public: &[u8; 32],
    server: &str,
    device_public: &[u8; 32],
    revoked_at_ms: i64,
    signature: &str,
) -> Result<()> {
    let bytes = revocation_bytes(
        &incarnation_id_from_authority_public(authority_public),
        server,
        device_public,
        revoked_at_ms,
    )?;
    verify_signature(authority_public, &bytes, signature)
}

fn verify_signature(authority_public: &[u8; 32], bytes: &[u8], signature: &str) -> Result<()> {
    let signature: [u8; 64] = STANDARD
        .decode(signature)
        .ok()
        .filter(|raw| STANDARD.encode(raw) == signature)
        .and_then(|raw| raw.try_into().ok())
        .ok_or_else(|| invalid("signature"))?;
    VerifyingKey::from_bytes(Suite::V1, authority_public)
        .map_err(|_| invalid("authority key"))?
        .verify(bytes, &signature)
        .map_err(|_| CryptoError::AuthFailed)
}

fn check_server(server: &str) -> Result<()> {
    if server.is_empty()
        || server.len() > 253
        || !server
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-:".contains(&b))
    {
        return Err(invalid("server"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &str = "11111111-1111-4111-8111-111111111111";
    const SERVER: &str = "kutup.dev";
    const T: i64 = 1_790_000_000_000;

    #[test]
    fn only_the_accounts_own_statement_for_this_device_verifies() {
        let id = AccountIdentityKeysV1::derive(&[1; 32]).unwrap();
        let other = AccountIdentityKeysV1::derive(&[2; 32]).unwrap();
        let (device, challenge) = ([7u8; 32], [9u8; CHALLENGE_LEN]);
        let statement = DeviceStatement {
            server: SERVER,
            user_id: USER,
            device_public: &device,
            purpose: PURPOSE_COLLAB_FRAMES,
            challenge: &challenge,
            issued_at_ms: T,
        };
        let signature = sign(&id, &statement).unwrap();
        let a = id.authority_public_key();
        verify(&a, &statement, &signature).unwrap();
        // Another authority, server, account, device, purpose, challenge or time: refused.
        assert!(verify(&other.authority_public_key(), &statement, &signature).is_err());
        let (other_device, zero) = ([8u8; 32], [0u8; CHALLENGE_LEN]);
        for changed in [
            DeviceStatement {
                server: "other.dev",
                ..statement
            },
            DeviceStatement {
                user_id: "22222222-2222-4222-8222-222222222222",
                ..statement
            },
            DeviceStatement {
                device_public: &other_device,
                ..statement
            },
            DeviceStatement {
                purpose: 2,
                ..statement
            },
            DeviceStatement {
                challenge: &zero,
                ..statement
            },
            DeviceStatement {
                issued_at_ms: T + 1,
                ..statement
            },
        ] {
            assert!(verify(&a, &changed, &signature).is_err(), "{changed:?}");
        }
        // Signed by another account for this one: refused.
        let foreign = sign(&other, &statement).unwrap();
        assert!(verify(&a, &statement, &foreign).is_err());
    }

    #[test]
    fn only_the_account_revokes_its_device() {
        let id = AccountIdentityKeysV1::derive(&[1; 32]).unwrap();
        let other = AccountIdentityKeysV1::derive(&[2; 32]).unwrap();
        let device = [7u8; 32];
        let revocation = sign_revocation(&id, SERVER, &device, T).unwrap();
        let authority = id.authority_public_key();
        verify_revocation(&authority, SERVER, &device, T, &revocation).unwrap();
        assert!(verify_revocation(&authority, SERVER, &[8u8; 32], T, &revocation).is_err());
        assert!(verify_revocation(&authority, "other.dev", &device, T, &revocation).is_err());
        assert!(verify_revocation(&authority, SERVER, &device, T + 1, &revocation).is_err());
        let foreign = sign_revocation(&other, SERVER, &device, T).unwrap();
        assert!(verify_revocation(&authority, SERVER, &device, T, &foreign).is_err());
    }
}
