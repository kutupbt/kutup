//! Contacts (docs/plans/contacts.md): one encrypted address book per account.
//!
//! Proton splits a contact into a signed, readable vCard part (name, emails,
//! pinned keys) and an encrypted, signed part (everything else). Kutup keeps
//! the same split in its own formats:
//!
//! - [`ContactSummaryV1`]: what the server may read and index (UID, name,
//!   emails, groups, pinned PGP keys), canonical JSON signed by the account
//!   authority, so a server cannot rewrite who a contact is.
//! - The contact card: the full vCard 4.0 text, an account record
//!   (`account_record`, purpose `ContactCard`) under the master key, whose
//!   object is the SHA-256 of the contact's UID: bound to the account and
//!   UID, and the server checks it is the card of the summary's contact.
//!
//! A contact is replaced over time, so both carry its revision (a time in
//! unix milliseconds, above every revision seen: `RevisionGuard` on the web):
//! the card in its header, under the AAD, and the summary in its signature,
//! so the server can neither pass an older card off as the newest nor pair a
//! summary with another card. A card's vCard is padded to a multiple of 256
//! bytes, so its length says little of what it holds.
//!
//! Both bind the account by its key binding (docs/plans/account-identity.md),
//! never by its address, which may change: summary signatures under the
//! `kutup/contact-summary/v2` domain, and cards in their account record.

use crate::account_record::{self, AccountRecordPurpose, MasterKeyGeneration};
use crate::primitives::{hash, SigningKey, Suite, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::identity::{authority_key_id_from_public, incarnation_id_from_authority_public};
use crate::key_binding;

const SUMMARY_DOMAIN: &[u8] = crate::labels::CONTACT_SUMMARY_V2;

/// The largest summary accepted, encoded.
pub const MAX_SUMMARY_BYTES: usize = 32 * 1024;
/// The largest vCard sealed in a card (room for a small photo).
pub const MAX_CARD_BYTES: usize = 512 * 1024;
pub const MAX_UID_CHARS: usize = 200;
pub const MAX_NAME_CHARS: usize = 200;
pub const MAX_EMAILS: usize = 50;
pub const MAX_ADDRESS_CHARS: usize = 320;
pub const MAX_LABEL_CHARS: usize = 40;
pub const MAX_GROUPS: usize = 50;
pub const MAX_PINNED_KEYS: usize = 20;

/// One email address of a contact (Proton's `ContactEmail`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContactEmailV1 {
    /// Lowercase `local@domain`. For a Kutup user this is also their Chat and
    /// Drive address.
    pub address: String,
    /// "home", "work", or the person's own word.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// An outside OpenPGP key pinned for one of the contact's addresses
/// (Proton's `KEY` with `X-PM-ENCRYPT` and `X-PM-SIGN`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PinnedKeyV1 {
    pub address: String,
    /// Lowercase hex v4 fingerprint.
    pub fingerprint: String,
    /// Encrypt mail to this address with this key.
    pub encrypt: bool,
    /// Expect mail from this address signed with this key.
    pub sign: bool,
}

/// What the server may read about a contact. Fields in this order, absent
/// optionals omitted; groups sorted; pinned keys sorted by address then
/// fingerprint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContactSummaryV1 {
    pub uid: String,
    pub name: String,
    #[serde(default)]
    pub emails: Vec<ContactEmailV1>,
    /// Ids (UUIDs) of the account's contact groups.
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub pinned_keys: Vec<PinnedKeyV1>,
}

fn invalid(reason: &str) -> CryptoError {
    CryptoError::InvalidInput(format!("contact: {reason}"))
}

fn plain_text(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value == value.trim()
        && value.chars().count() <= max
        && !value.chars().any(char::is_control)
}

/// A lowercase email-shaped address: one `@`, no spaces or controls.
pub fn canonical_contact_address(value: &str) -> Result<String> {
    let lower = value.trim().to_lowercase();
    let ok = lower.chars().count() <= MAX_ADDRESS_CHARS
        && lower.matches('@').count() == 1
        && !lower
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "<>\",;".contains(c))
        && lower.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty()
                && !domain.is_empty()
                && (domain.contains('.') || domain == "localhost")
                && !domain.starts_with('.')
                && !domain.ends_with('.')
        });
    if !ok {
        return Err(invalid("address is not an email address"));
    }
    Ok(lower)
}

impl ContactSummaryV1 {
    fn validate(&self) -> Result<()> {
        if !plain_text(&self.uid, MAX_UID_CHARS) {
            return Err(invalid("uid is invalid"));
        }
        if !plain_text(&self.name, MAX_NAME_CHARS) {
            return Err(invalid("name is invalid"));
        }
        if self.emails.len() > MAX_EMAILS {
            return Err(invalid("too many emails"));
        }
        let mut seen = std::collections::HashSet::new();
        for email in &self.emails {
            if canonical_contact_address(&email.address)? != email.address {
                return Err(invalid("address is not canonical"));
            }
            if !seen.insert(email.address.as_str()) {
                return Err(invalid("an address is listed twice"));
            }
            if email
                .label
                .as_deref()
                .is_some_and(|label| !plain_text(label, MAX_LABEL_CHARS))
            {
                return Err(invalid("email label is invalid"));
            }
        }
        if self.groups.len() > MAX_GROUPS
            || !self.groups.windows(2).all(|pair| pair[0] < pair[1])
            || self.groups.iter().any(|id| !is_canonical_uuid(id))
        {
            return Err(invalid("groups are invalid"));
        }
        if self.pinned_keys.len() > MAX_PINNED_KEYS
            || !self.pinned_keys.windows(2).all(|pair| {
                (&pair[0].address, &pair[0].fingerprint) < (&pair[1].address, &pair[1].fingerprint)
            })
        {
            return Err(invalid("pinned keys are invalid"));
        }
        for key in &self.pinned_keys {
            if !seen.contains(key.address.as_str())
                || key.fingerprint.len() != 40
                || !key
                    .fingerprint
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(invalid("a pinned key is not for a listed address"));
            }
        }
        Ok(())
    }
}

fn is_canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        })
}

/// The canonical bytes of a summary, after checking it.
pub fn encode_summary(summary: &ContactSummaryV1) -> Result<Vec<u8>> {
    summary.validate()?;
    let bytes = serde_json::to_vec(summary).map_err(|_| invalid("encode"))?;
    if bytes.len() > MAX_SUMMARY_BYTES {
        return Err(invalid("summary is too large"));
    }
    Ok(bytes)
}

/// A summary as stored: strictly checked, and only in its canonical bytes.
pub fn decode_summary(bytes: &[u8]) -> Result<ContactSummaryV1> {
    if bytes.len() > MAX_SUMMARY_BYTES {
        return Err(invalid("summary is too large"));
    }
    let summary: ContactSummaryV1 = serde_json::from_slice(bytes).map_err(|_| invalid("decode"))?;
    if encode_summary(&summary)? != bytes {
        return Err(invalid("summary is not canonical"));
    }
    Ok(summary)
}

fn summary_signing_bytes(
    binding: &str,
    revision: u64,
    authority_public: &[u8; 32],
    summary: &[u8],
) -> Result<Vec<u8>> {
    let binding = key_binding::check(binding).map_err(|_| invalid("key binding is invalid"))?;
    check_revision(revision)?;
    let mut out = Vec::with_capacity(SUMMARY_DOMAIN.len() + binding.len() + 148 + summary.len());
    out.extend_from_slice(SUMMARY_DOMAIN);
    out.extend_from_slice(&(binding.len() as u16).to_be_bytes());
    out.extend_from_slice(binding.as_bytes());
    out.extend_from_slice(&revision.to_be_bytes());
    out.extend_from_slice(
        &hex::decode(incarnation_id_from_authority_public(authority_public)).expect("hex"),
    );
    out.extend_from_slice(
        &hex::decode(authority_key_id_from_public(authority_public)).expect("hex"),
    );
    out.extend_from_slice(&(summary.len() as u32).to_be_bytes());
    out.extend_from_slice(summary);
    Ok(out)
}

fn check_revision(revision: u64) -> Result<()> {
    if revision == 0 {
        return Err(invalid("revisions start at 1"));
    }
    Ok(())
}

/// Encodes and signs revision `revision` of a summary with the authority of
/// the account whose key binding is `binding`. Returns the canonical bytes
/// and the signature.
pub fn sign_summary(
    summary: &ContactSummaryV1,
    binding: &str,
    revision: u64,
    authority: &SigningKey,
) -> Result<(Vec<u8>, [u8; 64])> {
    let bytes = encode_summary(summary)?;
    let signing = summary_signing_bytes(
        binding,
        revision,
        &authority.verifying_key().to_array(),
        &bytes,
    )?;
    Ok((bytes, authority.sign_array(&signing)))
}

/// Checks a stored summary's signature against the authority of the account
/// whose key binding is `binding`, for revision `revision` (its card's), and
/// returns it.
pub fn verify_summary(
    summary: &[u8],
    signature: &[u8],
    binding: &str,
    revision: u64,
    authority_public: &[u8; 32],
) -> Result<ContactSummaryV1> {
    let parsed = decode_summary(summary)?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| CryptoError::InvalidLength {
            expected: 64,
            got: signature.len(),
        })?;
    let signing = summary_signing_bytes(binding, revision, authority_public, summary)?;
    VerifyingKey::from_bytes(Suite::V1, authority_public)
        .map_err(|_| invalid("authority key is invalid"))?
        .verify(&signing, &signature)
        .map_err(|_| CryptoError::AuthFailed)?;
    Ok(parsed)
}

/// A card's object in its account record: the SHA-256 of the contact's UID
/// (which the server reads from the summary, so it can check the card is
/// that contact's).
pub fn card_object(uid: &str) -> Result<[u8; 32]> {
    if !plain_text(uid, MAX_UID_CHARS) {
        return Err(invalid("uid is invalid"));
    }
    Ok(hash(Suite::V1, uid.as_bytes()).to_array())
}

/// Seals revision `revision` of a contact's vCard text under the master key:
/// an account record bound to the account's key binding, the contact's UID
/// and the revision.
pub fn seal_card(
    master_key: &[u8; 32],
    generation: MasterKeyGeneration,
    binding: &str,
    uid: &str,
    revision: u64,
    vcard: &[u8],
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 24];
    crate::primitives::random(&mut nonce);
    seal_card_with_nonce(
        master_key, generation, binding, uid, revision, vcard, &nonce,
    )
}

/// [`seal_card`] with a fixed nonce, for checked-in vectors only.
pub fn seal_card_with_nonce(
    master_key: &[u8; 32],
    generation: MasterKeyGeneration,
    binding: &str,
    uid: &str,
    revision: u64,
    vcard: &[u8],
    nonce: &[u8; 24],
) -> Result<Vec<u8>> {
    if vcard.is_empty() || vcard.len() > MAX_CARD_BYTES {
        return Err(invalid("card size is invalid"));
    }
    check_revision(revision)?;
    account_record::seal_suite(
        account_record::AccountRecordSuiteId::V1,
        vcard,
        master_key,
        AccountRecordPurpose::ContactCard,
        generation,
        binding,
        &card_object(uid)?,
        Some(revision),
        nonce,
    )
}

/// Opens a sealed card of the account whose key binding is `binding`, for
/// `uid`: the vCard and the revision it was sealed at (refuse one older than
/// seen).
pub fn open_card(
    master_key: &[u8; 32],
    binding: &str,
    uid: &str,
    sealed: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, u64)> {
    let (vcard, revision) = account_record::open_revision(
        sealed,
        master_key,
        AccountRecordPurpose::ContactCard,
        binding,
        &card_object(uid)?,
    )?;
    let vcard = Zeroizing::new(vcard);
    if vcard.is_empty() || vcard.len() > MAX_CARD_BYTES {
        return Err(invalid("card size is invalid"));
    }
    check_revision(revision)?;
    Ok((vcard, revision))
}

/// What the server checks before storing a card: a well-formed card record
/// of the account bound by `binding`, for the contact `uid` (the summary's),
/// at a valid revision, which it returns.
pub fn validate_card(sealed: &[u8], binding: &str, uid: &str) -> Result<u64> {
    let header = account_record::validate_for(
        sealed,
        AccountRecordPurpose::ContactCard,
        binding,
        &card_object(uid)?,
    )?;
    let revision = header
        .revision
        .ok_or_else(|| invalid("a card has a revision"))?;
    check_revision(revision)?;
    Ok(revision)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AccountIdentityKeysV1;

    const ACCOUNT: &str = "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";
    const OTHER: &str = "7d3f1a2b-9c4e-4f6a-8b1d-2e5c7a9f0b3d";

    fn summary() -> ContactSummaryV1 {
        ContactSummaryV1 {
            uid: "urn:uuid:3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70".into(),
            name: "Ayşe Yılmaz".into(),
            emails: vec![
                ContactEmailV1 {
                    address: "ayse@example.com".into(),
                    label: Some("work".into()),
                },
                ContactEmailV1 {
                    address: "ayse@kutup.dev".into(),
                    label: None,
                },
            ],
            groups: vec!["11111111-1111-4111-8111-111111111111".into()],
            pinned_keys: vec![PinnedKeyV1 {
                address: "ayse@example.com".into(),
                fingerprint: "a".repeat(40),
                encrypt: true,
                sign: true,
            }],
        }
    }

    #[test]
    fn summaries_sign_verify_and_refuse_tampering() {
        let identity = AccountIdentityKeysV1::derive(&[5u8; 32]).unwrap();
        let other = AccountIdentityKeysV1::derive(&[6u8; 32]).unwrap();
        let authority = identity.authority_public_key();
        let (bytes, signature) =
            sign_summary(&summary(), ACCOUNT, 7, identity.authority_signing_key()).unwrap();
        assert_eq!(
            verify_summary(&bytes, &signature, ACCOUNT, 7, &authority).unwrap(),
            summary()
        );
        // Another revision's card cannot be paired with it.
        assert!(verify_summary(&bytes, &signature, ACCOUNT, 8, &authority).is_err());
        assert!(verify_summary(&bytes, &signature, OTHER, 7, &authority).is_err());
        assert!(verify_summary(&bytes, &signature, "alice@kutup.dev", 7, &authority).is_err());
        assert!(verify_summary(
            &bytes,
            &signature,
            ACCOUNT,
            7,
            &other.authority_public_key()
        )
        .is_err());
        let swapped = String::from_utf8(bytes.clone())
            .unwrap()
            .replace("ayse@example.com", "evil@example.com");
        assert!(verify_summary(swapped.as_bytes(), &signature, ACCOUNT, 7, &authority).is_err());
        // Non-canonical bytes are refused even with a matching meaning.
        let spaced = String::from_utf8(bytes).unwrap().replacen('{', "{ ", 1);
        assert!(decode_summary(spaced.as_bytes()).is_err());
    }

    #[test]
    fn summaries_refuse_invalid_shapes() {
        let mut bad = summary();
        bad.emails.push(bad.emails[0].clone());
        assert!(encode_summary(&bad).is_err());
        let mut bad = summary();
        bad.emails[0].address = "Ayse@Example.com".into();
        assert!(encode_summary(&bad).is_err());
        let mut bad = summary();
        bad.pinned_keys[0].address = "someone@else.com".into();
        assert!(encode_summary(&bad).is_err());
        let mut bad = summary();
        bad.name = " padded ".into();
        assert!(encode_summary(&bad).is_err());
        let mut bad = summary();
        bad.groups
            .insert(0, "22222222-2222-4222-8222-222222222222".into());
        assert!(encode_summary(&bad).is_err());
        assert!(canonical_contact_address("not an address").is_err());
        assert_eq!(
            canonical_contact_address(" Ali@Example.COM ").unwrap(),
            "ali@example.com"
        );
    }

    #[test]
    fn cards_seal_and_open_only_for_their_contact() {
        let master = [5u8; 32];
        let first = MasterKeyGeneration::FIRST;
        let vcard = b"BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Ay\xc5\x9fe\r\nTEL:+90 555 000 00 00\r\nEND:VCARD\r\n";
        let sealed = seal_card(&master, first, ACCOUNT, "uid-1", 42, vcard).unwrap();
        // The server's check: this account, this contact, revision 42.
        assert_eq!(validate_card(&sealed, ACCOUNT, "uid-1").unwrap(), 42);
        assert!(validate_card(&sealed, ACCOUNT, "uid-2").is_err());
        assert!(validate_card(&sealed, OTHER, "uid-1").is_err());
        // Padded to a multiple of 256 bytes.
        let header = account_record::inspect(&sealed).unwrap();
        assert_eq!(header.ciphertext_len as usize, 256 + 16);
        let (opened, revision) = open_card(&master, ACCOUNT, "uid-1", &sealed).unwrap();
        assert_eq!((&opened[..], revision), (&vcard[..], 42));
        // The revision is authenticated: relabelled newer, it does not open.
        let revision_at = sealed.len() - header.ciphertext_len as usize - 4 - 24 - 32 - 8;
        let mut relabelled = sealed.clone();
        relabelled[revision_at..revision_at + 8].copy_from_slice(&43u64.to_be_bytes());
        assert!(open_card(&master, ACCOUNT, "uid-1", &relabelled).is_err());
        assert!(seal_card(&master, first, ACCOUNT, "uid-1", 0, vcard).is_err());
        let mut short = sealed.clone();
        short.pop();
        assert!(validate_card(&short, ACCOUNT, "uid-1").is_err());
        assert!(open_card(&master, ACCOUNT, "uid-2", &sealed).is_err());
        assert!(open_card(&master, OTHER, "uid-1", &sealed).is_err());
        assert!(open_card(&master, "alice@kutup.dev", "uid-1", &sealed).is_err());
        assert!(open_card(&[6u8; 32], ACCOUNT, "uid-1", &sealed).is_err());
        assert!(card_object(&"u".repeat(MAX_UID_CHARS + 1)).is_err());
    }
}
