//! The Drive key binding (docs/plans/drive-identity-pins.md): the account
//! authority vouches for the account's Drive keys.
//!
//! A named share is sealed to the recipient's Drive HPKE key and signed with
//! the sender's Drive share-signing key (`named_share`). Both public keys
//! reach a client through the server; this signature ties them to the
//! account and its authority, whose hash is the account's incarnation id. A
//! client that remembers an account's authority (`identity_pins`) can then
//! tell when a server hands out someone else's keys.
//!
//! Drive keys and the authority both derive from the master key, so one
//! binding holds for the account's whole lifetime; an administrative wipe
//! starts a new incarnation and a new binding.

use ed25519_dalek::{Signature, Signer as _, VerifyingKey};

use crate::error::{CryptoError, Result};
use crate::identity::{incarnation_id_from_authority_public, AccountIdentityKeysV1};
use crate::named_share::canonical_account;

const DOMAIN: &[u8] = b"kutup/drive-key-binding/v1\0";
/// The account identity suite of the bound keys (X25519 + Ed25519).
const SUITE_V1: u16 = 1;

/// The bytes the authority signs.
pub fn binding_bytes(
    account: &str,
    authority_public: &[u8; 32],
    drive_hpke_public: &[u8; 32],
    drive_signing_public: &[u8; 32],
) -> Result<Vec<u8>> {
    let account = canonical_account(account)
        .map_err(|_| CryptoError::InvalidInput("account is not canonical".into()))?;
    let account_len = u16::try_from(account.len())
        .map_err(|_| CryptoError::InvalidInput("account is too long".into()))?;
    let incarnation = hex::decode(incarnation_id_from_authority_public(authority_public))
        .map_err(|_| CryptoError::Backend("incarnation hex".into()))?;
    let mut out = Vec::with_capacity(DOMAIN.len() + 2 + account.len() + 32 * 4 + 2);
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(&account_len.to_be_bytes());
    out.extend_from_slice(account.as_bytes());
    out.extend_from_slice(&incarnation);
    out.extend_from_slice(authority_public);
    out.extend_from_slice(&SUITE_V1.to_be_bytes());
    out.extend_from_slice(drive_hpke_public);
    out.extend_from_slice(drive_signing_public);
    Ok(out)
}

/// The account's binding, signed with its authority.
pub fn sign(identity: &AccountIdentityKeysV1, account: &str) -> Result<[u8; 64]> {
    let bytes = binding_bytes(
        account,
        &identity.authority_public_key(),
        &identity.drive_hpke_public_key(),
        &identity.drive_signing_public_key(),
    )?;
    Ok(identity.authority_signing_key().sign(&bytes).to_bytes())
}

/// Checks that `authority_public` vouches for these Drive keys of `account`.
pub fn verify(
    account: &str,
    authority_public: &[u8; 32],
    drive_hpke_public: &[u8; 32],
    drive_signing_public: &[u8; 32],
    signature: &[u8],
) -> Result<()> {
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| CryptoError::InvalidLength {
            expected: 64,
            got: signature.len(),
        })?;
    let bytes = binding_bytes(
        account,
        authority_public,
        drive_hpke_public,
        drive_signing_public,
    )?;
    VerifyingKey::from_bytes(authority_public)
        .map_err(|_| CryptoError::InvalidInput("authority key is invalid".into()))?
        .verify_strict(&bytes, &Signature::from_bytes(&signature))
        .map_err(|_| CryptoError::AuthFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: &str = "alice@kutup.dev";

    #[test]
    fn a_binding_verifies_only_for_its_account_and_keys() {
        let alice = AccountIdentityKeysV1::derive(&[1u8; 32]).unwrap();
        let mallory = AccountIdentityKeysV1::derive(&[2u8; 32]).unwrap();
        let signature = sign(&alice, ACCOUNT).unwrap();
        let (authority, hpke, signing) = (
            alice.authority_public_key(),
            alice.drive_hpke_public_key(),
            alice.drive_signing_public_key(),
        );
        verify(ACCOUNT, &authority, &hpke, &signing, &signature).unwrap();
        // Another account's address, another signer, another recipient key.
        assert!(verify("bob@kutup.dev", &authority, &hpke, &signing, &signature).is_err());
        assert!(verify(
            ACCOUNT,
            &authority,
            &hpke,
            &mallory.drive_signing_public_key(),
            &signature
        )
        .is_err());
        assert!(verify(
            ACCOUNT,
            &authority,
            &mallory.drive_hpke_public_key(),
            &signing,
            &signature
        )
        .is_err());
        // Someone else's authority cannot vouch with Alice's signature.
        assert!(verify(
            ACCOUNT,
            &mallory.authority_public_key(),
            &hpke,
            &signing,
            &signature
        )
        .is_err());
        assert!(verify(ACCOUNT, &authority, &hpke, &signing, &signature[..63]).is_err());
    }

    #[test]
    fn only_a_canonical_address_is_bound() {
        let alice = AccountIdentityKeysV1::derive(&[1u8; 32]).unwrap();
        for account in ["Alice@kutup.dev", " alice@kutup.dev", "alice", "a@b@c"] {
            assert!(sign(&alice, account).is_err(), "{account}");
        }
    }
}
