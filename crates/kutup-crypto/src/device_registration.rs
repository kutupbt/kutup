//! A collaboration device signed by its account (docs/plans/device-registration.md).
//!
//! A browser tab or the CLI signs collaboration frames with a device key of
//! its own; the server keeps a frame only from an active device of the
//! sender's account. The account authority (from the master key) vouches for
//! each device key, so a session token alone, without the account's keys,
//! cannot add one. The statement names the incarnation (the authority's hash),
//! the account's server and that server's id for it, the device key, what it
//! is for, and a one-time challenge the server issued, so a captured registration
//! cannot be played again and no client clock is trusted. The device's label
//! is not in it: it can be renamed.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Signer as _, VerifyingKey};

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

/// The bytes the authority signs. `server` is the account's server (its
/// domain, as in `username@server`): a statement holds on that server only.
pub fn signing_bytes(
    incarnation_id: &str,
    server: &str,
    user_id: &str,
    device_public: &[u8; 32],
    purpose: u8,
    challenge: &[u8; CHALLENGE_LEN],
) -> Result<Vec<u8>> {
    let incarnation = hex::decode(incarnation_id)
        .ok()
        .filter(|bytes| bytes.len() == 32 && hex::encode(bytes) == incarnation_id)
        .ok_or_else(|| invalid("incarnation id"))?;
    let user = parse_canonical_uuid(user_id, "account").map_err(|_| invalid("user id"))?;
    if server.is_empty()
        || server.len() > 253
        || !server
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-:".contains(&b))
    {
        return Err(invalid("server"));
    }
    if purpose != PURPOSE_COLLAB_FRAMES {
        return Err(invalid("purpose"));
    }
    let mut out = Vec::with_capacity(DOMAIN.len() + 32 + 16 + 32 + 1 + CHALLENGE_LEN);
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(&incarnation);
    out.extend_from_slice(&(server.len() as u16).to_be_bytes());
    out.extend_from_slice(server.as_bytes());
    out.extend_from_slice(&user);
    out.extend_from_slice(device_public);
    out.push(purpose);
    out.extend_from_slice(challenge);
    Ok(out)
}

/// The account's statement for `device_public`, signed with its authority:
/// the canonical base64 signature.
pub fn sign(
    identity: &AccountIdentityKeysV1,
    server: &str,
    user_id: &str,
    device_public: &[u8; 32],
    purpose: u8,
    challenge: &[u8; CHALLENGE_LEN],
) -> Result<String> {
    let bytes = signing_bytes(
        &identity.incarnation_id(),
        server,
        user_id,
        device_public,
        purpose,
        challenge,
    )?;
    Ok(STANDARD.encode(identity.authority_signing_key().sign(&bytes).to_bytes()))
}

/// Checks a registration against the account's authority key (whose hash is
/// the incarnation it must name). That the challenge is the server's, fresh
/// and unused is the server's to check; this is the signature and its form.
pub fn verify(
    authority_public: &[u8; 32],
    server: &str,
    user_id: &str,
    device_public: &[u8; 32],
    purpose: u8,
    challenge: &[u8; CHALLENGE_LEN],
    signature: &str,
) -> Result<()> {
    let bytes = signing_bytes(
        &incarnation_id_from_authority_public(authority_public),
        server,
        user_id,
        device_public,
        purpose,
        challenge,
    )?;
    let signature: [u8; 64] = STANDARD
        .decode(signature)
        .ok()
        .filter(|raw| STANDARD.encode(raw) == signature)
        .and_then(|raw| raw.try_into().ok())
        .ok_or_else(|| invalid("signature"))?;
    VerifyingKey::from_bytes(authority_public)
        .map_err(|_| invalid("authority key"))?
        .verify_strict(&bytes, &Signature::from_bytes(&signature))
        .map_err(|_| CryptoError::AuthFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &str = "11111111-1111-4111-8111-111111111111";
    const SERVER: &str = "kutup.dev";

    #[test]
    fn only_the_accounts_own_statement_for_this_device_verifies() {
        let id = AccountIdentityKeysV1::derive(&[1; 32]).unwrap();
        let other = AccountIdentityKeysV1::derive(&[2; 32]).unwrap();
        let (device, challenge) = ([7u8; 32], [9u8; CHALLENGE_LEN]);
        let signature = sign(
            &id,
            SERVER,
            USER,
            &device,
            PURPOSE_COLLAB_FRAMES,
            &challenge,
        )
        .unwrap();
        let authority = id.authority_public_key();
        let check = |authority: &[u8; 32],
                     server: &str,
                     user: &str,
                     device: &[u8; 32],
                     purpose: u8,
                     challenge: &[u8; 32],
                     signature: &str| {
            verify(
                authority, server, user, device, purpose, challenge, signature,
            )
            .is_ok()
        };
        assert!(check(
            &authority, SERVER, USER, &device, 1, &challenge, &signature
        ));
        // Another authority, server, account, device, purpose or challenge: refused.
        assert!(!check(
            &other.authority_public_key(),
            SERVER,
            USER,
            &device,
            1,
            &challenge,
            &signature
        ));
        assert!(!check(
            &authority,
            "other.dev",
            USER,
            &device,
            1,
            &challenge,
            &signature
        ));
        assert!(!check(
            &authority,
            SERVER,
            "22222222-2222-4222-8222-222222222222",
            &device,
            1,
            &challenge,
            &signature
        ));
        assert!(!check(
            &authority, SERVER, USER, &[8u8; 32], 1, &challenge, &signature
        ));
        assert!(!check(
            &authority, SERVER, USER, &device, 2, &challenge, &signature
        ));
        assert!(!check(
            &authority,
            SERVER,
            USER,
            &device,
            1,
            &[0u8; CHALLENGE_LEN],
            &signature
        ));
        // Signed by another account for this one: refused.
        let foreign = sign(&other, SERVER, USER, &device, 1, &challenge).unwrap();
        assert!(!check(
            &authority, SERVER, USER, &device, 1, &challenge, &foreign
        ));
    }
}
