//! Who signs a Drive revision's manifest, and whether a manifest's signer
//! holds (docs/plans/drive-block-format.md §2, "The signature";
//! docs/plans/drive-identity-pins.md).
//!
//! Every block-format revision this CLI uploads is signed with the account's
//! Drive signing key and names the account id and its incarnation (signer
//! kind 2), as the web does (`manifestSignerOf`). Every revision it opens has
//! its signer checked as drive-core's `manifestSigners.ts` does: this
//! account's own key, or the key the named account's pinned authority (at the
//! incarnation named) vouches for. A signature that doesn't hold, or an
//! incarnation the pins don't stand for, warns on stderr; it never blocks
//! (the bytes are already bound to the file's key and committed digest).
//! The CLI shows no revision author, so the web's `authorMismatch` has no
//! counterpart here.

use std::rc::Rc;

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_crypto::account_roots::IdentityRoot;
use kutup_crypto::blocks::{Manifest, SignerIdentity};
use kutup_crypto::identity::AccountIdentityKeysV1;
use kutup_crypto::identity_pins::IdentityPinsV2;
use kutup_crypto::primitives::{SigningKey, Suite, VerifyingKey};

use crate::api::Client;

/// The signed-in account as a revision's uploader: its id, its identity keys
/// (from the identity root) and its incarnation.
pub struct DriveIdentity {
    account: [u8; 16],
    incarnation: [u8; 32],
    keys: AccountIdentityKeysV1,
}

impl DriveIdentity {
    pub fn derive(identity_root: &IdentityRoot, account_id: &str) -> Result<Self> {
        let keys = AccountIdentityKeysV1::derive(identity_root)?;
        let account = uuid::Uuid::parse_str(account_id)
            .ok()
            .filter(|id| !id.is_nil() && id.hyphenated().to_string() == account_id)
            .ok_or_else(|| anyhow!("the session's account id is not a canonical UUID"))?;
        let incarnation: [u8; 32] = hex::decode(keys.incarnation_id())
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| anyhow!("the account's incarnation id is not 32 bytes"))?;
        Ok(Self {
            account: *account.as_bytes(),
            incarnation,
            keys,
        })
    }

    /// What a manifest this account signs names, and the key it signs with.
    pub fn signer(&self) -> (&SigningKey, SignerIdentity) {
        (
            self.keys.drive_signing_key(),
            SignerIdentity {
                account_id: self.account,
                incarnation_id: self.incarnation,
            },
        )
    }
}

/// The signed-in account's identity, set on the client when the session
/// loads (`context::require_session`).
pub fn identity(client: &Client) -> Result<Rc<DriveIdentity>> {
    client
        .drive_identity()
        .context("not signed in: a Drive revision is signed by its uploader's account")
}

/// Reads the account's identity pins onto the client, so every revision it
/// opens is checked against them; best effort (without them, only this
/// account's own signatures are told apart).
pub fn load_pins(ctx: &crate::context::Ctx, profile: &str) {
    let loaded =
        crate::identity::Me::of(ctx, profile).and_then(|me| crate::identity::load_pins(ctx, &me));
    match loaded {
        Ok((_, list)) => ctx.client.set_identity_pins(list),
        Err(error) => {
            eprintln!("note: revision signers are not checked against your pins: {error:#}")
        }
    }
}

/// What can be said of a revision's signature.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Verified,
    /// A known key that did not make it: written under another's name.
    Forged(Option<String>),
    /// An incarnation the pins (or this account) don't stand for.
    Changed(Option<String>),
    /// Can't be told (an account never met, a lookup that failed).
    Unknown,
}

/// Checks `manifest`'s signer and warns on stderr when it is in doubt.
pub fn check(client: &Client, manifest: &Manifest, file_id: &str, revision_id: &str) {
    let warning = match verdict(client, manifest) {
        Verdict::Verified | Verdict::Unknown => return,
        Verdict::Forged(name) => format!(
            "revision {revision_id} of file {file_id} is signed in the name of {} but not with their key: someone else with the file's key may have written it",
            name.as_deref().unwrap_or("an account you know")
        ),
        Verdict::Changed(name) => format!(
            "revision {revision_id} of file {file_id} is signed by {} under an identity you have not accepted: the account may have been reset, or the name is being passed off",
            name.as_deref().unwrap_or("an account you know")
        ),
    };
    eprintln!("warning: {warning}");
}

fn verdict(client: &Client, manifest: &Manifest) -> Verdict {
    let Some(signer) = manifest.signer.as_ref() else {
        return Verdict::Unknown;
    };
    let Some(me) = client.drive_identity() else {
        return Verdict::Unknown;
    };
    if signer.account_id == me.account {
        if signer.incarnation_id != me.incarnation {
            return Verdict::Changed(None);
        }
        return if manifest
            .verify_signer(&me.keys.drive_signing_key().verifying_key())
            .is_ok()
        {
            Verdict::Verified
        } else {
            Verdict::Forged(None)
        };
    }
    let Some(pins) = client.identity_pins() else {
        return Verdict::Unknown;
    };
    pins_verdict(&pins, manifest, |address, authority| {
        bound_signing_key(client, address, authority)
    })
}

/// The pins' verdict on a manifest of another account; `signing_key` gives
/// the Drive signing key that account's pinned authority vouches for (its
/// address, its authority), or `None` when it can't be had.
fn pins_verdict(
    pins: &IdentityPinsV2,
    manifest: &Manifest,
    signing_key: impl Fn(&str, &str) -> Option<[u8; 32]>,
) -> Verdict {
    let Some(signer) = manifest.signer.as_ref() else {
        return Verdict::Unknown;
    };
    let account = uuid::Uuid::from_bytes(signer.account_id)
        .hyphenated()
        .to_string();
    let incarnation = hex::encode(signer.incarnation_id);
    let found: Vec<_> = pins
        .pins
        .iter()
        .filter(|pin| pin.account.account_id == account)
        .collect();
    if found.is_empty() {
        return Verdict::Unknown;
    }
    for pin in &found {
        if pin.incarnation_id().ok().as_deref() != Some(incarnation.as_str()) {
            continue;
        }
        let name = pin.address().map(str::to_string);
        let Some(key) = name
            .as_deref()
            .and_then(|address| signing_key(address, &pin.authority_public_key))
        else {
            return Verdict::Unknown;
        };
        let Ok(key) = VerifyingKey::from_bytes(Suite::V1, &key) else {
            return Verdict::Unknown;
        };
        return if manifest.verify_signer(&key).is_ok() {
            Verdict::Verified
        } else {
            Verdict::Forged(name)
        };
    }
    // One the user accepted a change from is only old content.
    if found.iter().any(|pin| pin.replaced.contains(&incarnation)) {
        return Verdict::Unknown;
    }
    Verdict::Changed(found[0].address().map(str::to_string))
}

/// The Drive signing key `address` publishes, when its account authority
/// is `authority` and that authority signed it (the key binding).
fn bound_signing_key(client: &Client, address: &str, authority: &str) -> Option<[u8; 32]> {
    let person = crate::identity::published_with(client, address).ok()?;
    if person.authority != authority || !crate::identity::bound(&person) {
        return None;
    }
    STANDARD
        .decode(&person.signing)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kutup_crypto::drive_blocks::{self, DriveBlobContextV2};

    const FILE: &str = "11111111-1111-4111-8111-111111111111";
    const REVISION: &str = "22222222-2222-4222-8222-222222222222";
    const ACCOUNT: &str = "33333333-3333-4333-8333-333333333333";

    fn manifest_by(identity: &DriveIdentity) -> Manifest {
        let context = DriveBlobContextV2::new(FILE, REVISION, 1).unwrap();
        let (key, signer) = identity.signer();
        let sealed = drive_blocks::seal_file(b"hello", &[7; 32], context, key, signer).unwrap();
        let content = kutup_crypto::file_metadata::ContentCommitmentV1::new(
            context.revision_id,
            sealed.manifest_sha256,
        );
        drive_blocks::open_file(&sealed.bytes, &[7; 32], context, &content, 5)
            .unwrap()
            .1
    }

    fn pins_for(identity: &DriveIdentity, address: &str) -> IdentityPinsV2 {
        let authority = STANDARD.encode(identity.keys.authority_public_key());
        serde_json::from_value(serde_json::json!({
            "pins": [{
                "account": { "server": "kutup.test", "accountId": uuid::Uuid::from_bytes(identity.account).hyphenated().to_string() },
                "authorityPublicKey": authority,
                "state": "seen",
                "since": "2026-11-12T00:00:00Z",
                "addresses": [{ "address": address, "seenAt": "2026-11-12T00:00:00Z" }]
            }]
        }))
        .unwrap()
    }

    #[test]
    fn a_pinned_signer_is_verified_and_another_key_is_forged() {
        let them = DriveIdentity::derive(&IdentityRoot::from_bytes([4; 32]), ACCOUNT).unwrap();
        let manifest = manifest_by(&them);
        let pins = pins_for(&them, "them@kutup.test");
        let theirs = them.keys.drive_signing_public_key();
        assert_eq!(
            pins_verdict(&pins, &manifest, |_, _| Some(theirs)),
            Verdict::Verified
        );
        assert_eq!(
            pins_verdict(&pins, &manifest, |_, _| Some([9; 32])),
            Verdict::Forged(Some("them@kutup.test".into()))
        );
        // Signed under another incarnation of that account: changed.
        let reset = DriveIdentity::derive(&IdentityRoot::from_bytes([5; 32]), ACCOUNT).unwrap();
        assert!(matches!(
            pins_verdict(&pins, &manifest_by(&reset), |_, _| Some(theirs)),
            Verdict::Changed(_)
        ));
        // An account never met: nothing to say.
        let stranger = DriveIdentity::derive(
            &IdentityRoot::from_bytes([6; 32]),
            "44444444-4444-4444-8444-444444444444",
        )
        .unwrap();
        assert_eq!(
            pins_verdict(&pins, &manifest_by(&stranger), |_, _| Some(theirs)),
            Verdict::Unknown
        );
    }
}
