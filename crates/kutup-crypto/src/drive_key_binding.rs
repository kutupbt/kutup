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
//! It binds the account as (server, account id), never its name
//! (docs/plans/account-ids.md, as Signal binds identity to the ACI): a
//! rename changes nothing here. Drive keys and the authority both derive
//! from the master key, so one binding holds for the incarnation's whole
//! lifetime; an administrative reset starts a new incarnation and a new
//! binding, for the same account id.

use ed25519_dalek::{Signature, Signer as _, VerifyingKey};

use crate::account_ref::AccountRef;
use crate::error::{CryptoError, Result};
use crate::identity::{incarnation_id_from_authority_public, AccountIdentityKeysV1};

const DOMAIN: &[u8] = b"kutup/drive-key-binding/v1\0";
/// The account identity suite of the bound keys (X25519 + Ed25519).
const SUITE_V1: u16 = 1;

/// The bytes the authority signs.
pub fn binding_bytes(
    account: &AccountRef,
    authority_public: &[u8; 32],
    drive_hpke_public: &[u8; 32],
    drive_signing_public: &[u8; 32],
) -> Result<Vec<u8>> {
    let account = account.bytes();
    let incarnation = hex::decode(incarnation_id_from_authority_public(authority_public))
        .map_err(|_| CryptoError::Backend("incarnation hex".into()))?;
    let mut out = Vec::with_capacity(DOMAIN.len() + account.len() + 32 * 4 + 2);
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(&account);
    out.extend_from_slice(&incarnation);
    out.extend_from_slice(authority_public);
    out.extend_from_slice(&SUITE_V1.to_be_bytes());
    out.extend_from_slice(drive_hpke_public);
    out.extend_from_slice(drive_signing_public);
    Ok(out)
}

/// The account's binding, signed with its authority.
pub fn sign(identity: &AccountIdentityKeysV1, account: &AccountRef) -> Result<[u8; 64]> {
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
    account: &AccountRef,
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

    fn person(id: &str) -> AccountRef {
        AccountRef::new("kutup.dev", id).unwrap()
    }

    #[test]
    fn a_binding_verifies_only_for_its_account_and_keys() {
        let alice = AccountIdentityKeysV1::derive(&[1u8; 32]).unwrap();
        let mallory = AccountIdentityKeysV1::derive(&[2u8; 32]).unwrap();
        let account = person("00000000-0000-4000-8000-0000000000a1");
        let signature = sign(&alice, &account).unwrap();
        let (authority, hpke, signing) = (
            alice.authority_public_key(),
            alice.drive_hpke_public_key(),
            alice.drive_signing_public_key(),
        );
        verify(&account, &authority, &hpke, &signing, &signature).unwrap();
        // Another account id, the same id on another server.
        assert!(verify(
            &person("00000000-0000-4000-8000-0000000000b0"),
            &authority,
            &hpke,
            &signing,
            &signature
        )
        .is_err());
        assert!(verify(
            &AccountRef::new("other.dev", &account.account_id).unwrap(),
            &authority,
            &hpke,
            &signing,
            &signature
        )
        .is_err());
        // Another signer, another recipient key.
        assert!(verify(
            &account,
            &authority,
            &hpke,
            &mallory.drive_signing_public_key(),
            &signature
        )
        .is_err());
        assert!(verify(
            &account,
            &authority,
            &mallory.drive_hpke_public_key(),
            &signing,
            &signature
        )
        .is_err());
        // Someone else's authority cannot vouch with Alice's signature.
        assert!(verify(
            &account,
            &mallory.authority_public_key(),
            &hpke,
            &signing,
            &signature
        )
        .is_err());
        assert!(verify(&account, &authority, &hpke, &signing, &signature[..63]).is_err());
    }
}
