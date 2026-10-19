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
//!
//! Version 2 (docs/plans/pq-shares.md) binds an X-Wing Drive key (identity
//! suite 2) and carries an `epoch`, which only grows for an incarnation, so
//! that clients can refuse an older binding a server still holds a valid
//! signature for. Clients don't keep the highest (suite, epoch) per account
//! yet: only epoch 1 exists, so there is nothing to roll back to. Pins must
//! record it before any epoch 2 is signed (docs/roadmap.md).

use ed25519_dalek::{Signature, Signer as _, VerifyingKey};

use crate::account_ref::AccountRef;
use crate::error::{CryptoError, Result};
use crate::identity::{incarnation_id_from_authority_public, AccountIdentityKeysV1};

const DOMAIN: &[u8] = b"kutup/drive-key-binding/v2\0";
/// The account identity suite of the bound keys (X-Wing + Ed25519).
pub const SUITE: u16 = crate::identity::IDENTITY_SUITE;
/// The epoch of an account's first suite-2 binding: at registration and at
/// the suite upgrade.
pub const FIRST_DRIVE_KEY_BINDING_EPOCH: u32 = 1;

type HpkePublic = [u8; crate::hpke_xwing::PUBLIC_KEY_LEN];

/// The bytes the authority signs.
pub fn binding_bytes(
    account: &AccountRef,
    authority_public: &[u8; 32],
    epoch: u32,
    drive_hpke_public: &HpkePublic,
    drive_signing_public: &[u8; 32],
) -> Result<Vec<u8>> {
    if epoch == 0 {
        return Err(CryptoError::InvalidInput(
            "binding epoch starts at 1".into(),
        ));
    }
    let account = account.bytes();
    let incarnation = hex::decode(incarnation_id_from_authority_public(authority_public))
        .map_err(|_| CryptoError::Backend("incarnation hex".into()))?;
    let mut out =
        Vec::with_capacity(DOMAIN.len() + account.len() + 32 * 3 + 2 + 4 + drive_hpke_public.len());
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(&account);
    out.extend_from_slice(&incarnation);
    out.extend_from_slice(authority_public);
    out.extend_from_slice(&SUITE.to_be_bytes());
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(drive_hpke_public);
    out.extend_from_slice(drive_signing_public);
    Ok(out)
}

/// The account's binding at `epoch`, signed with its authority.
pub fn sign(
    identity: &AccountIdentityKeysV1,
    account: &AccountRef,
    epoch: u32,
) -> Result<[u8; 64]> {
    let bytes = binding_bytes(
        account,
        &identity.authority_public_key(),
        epoch,
        &identity.drive_hpke_public_key(),
        &identity.drive_signing_public_key(),
    )?;
    Ok(identity.authority_signing_key().sign(&bytes).to_bytes())
}

/// Checks that `authority_public` vouches for these Drive keys of `account`
/// at `epoch`. A caller that has seen this account before also checks the
/// epoch is not below the highest it saw.
pub fn verify(
    account: &AccountRef,
    authority_public: &[u8; 32],
    epoch: u32,
    drive_hpke_public: &HpkePublic,
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
        epoch,
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
        let signature = sign(&alice, &account, 1).unwrap();
        let (authority, hpke, signing) = (
            alice.authority_public_key(),
            alice.drive_hpke_public_key(),
            alice.drive_signing_public_key(),
        );
        verify(&account, &authority, 1, &hpke, &signing, &signature).unwrap();
        // Another epoch is another statement.
        assert!(verify(&account, &authority, 2, &hpke, &signing, &signature).is_err());
        assert!(sign(&alice, &account, 0).is_err());
        // Another account id, the same id on another server.
        assert!(verify(
            &person("00000000-0000-4000-8000-0000000000b0"),
            &authority,
            1,
            &hpke,
            &signing,
            &signature
        )
        .is_err());
        assert!(verify(
            &AccountRef::new("other.dev", &account.account_id).unwrap(),
            &authority,
            1,
            &hpke,
            &signing,
            &signature
        )
        .is_err());
        // Another signer, another recipient key.
        assert!(verify(
            &account,
            &authority,
            1,
            &hpke,
            &mallory.drive_signing_public_key(),
            &signature
        )
        .is_err());
        assert!(verify(
            &account,
            &authority,
            1,
            &mallory.drive_hpke_public_key(),
            &signing,
            &signature
        )
        .is_err());
        // Someone else's authority cannot vouch with Alice's signature.
        assert!(verify(
            &account,
            &mallory.authority_public_key(),
            1,
            &hpke,
            &signing,
            &signature
        )
        .is_err());
        assert!(verify(&account, &authority, 1, &hpke, &signing, &signature[..63]).is_err());
    }
}
