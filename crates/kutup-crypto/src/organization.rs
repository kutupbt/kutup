//! An organization's key and what admins and members exchange with it
//! (docs/plans/organizations.md §3, following Proton's organization keys).
//!
//! - The **organization key** is an X-Wing key pair from a random 32-byte
//!   seed; its id is a hash of the public key (`kutup/org/key-id/v1`).
//! - [`KeyCertificateV1`]: the admin who made it vouches for it, signed with
//!   their account authority (Proton's fingerprint signature). Verifying
//!   gives a [`VerifiedKeyCertificate`], the only way to an organization's
//!   public key that a member's escrow is sealed to.
//! - [`KeyShareV1`]: the seed sealed to a new admin's Drive X-Wing key, taken
//!   from their verified, authority-signed Drive key binding
//!   ([`VerifiedDriveKey`]); bound to the organization, the key, the
//!   recipient (and a hash of their public key) and the granting admin, and
//!   signed by the granting admin (Proton's `OrganizationKeyInvitation`).
//! - [`AccessRequestV1`]: an admin's signed request that a private member
//!   become managed (Proton's signed `InvitationData`).
//! - [`EscrowV1`]: a managed member's master key sealed to the organization
//!   key of a verified certificate, bound to the member, their incarnation
//!   and the master key's generation. Unsigned: whoever opens it derives the
//!   authority from the master key and checks it is the member's, so a
//!   server can't plant one.
//!
//! Each format is an 8-byte magic, a suite, then length-prefixed fields; a
//! signature covers its label then every byte before it. Nothing binds a
//! username, an address or the organization's name. Whether a signer is an
//! admin is the server's word, as at Proton: these formats prove who signed,
//! and the member's client checks the rest at consent (§3).

use zeroize::Zeroizing;

use crate::account_envelope::MasterKeyGeneration;
use crate::account_ref::AccountRef;
use crate::error::{CryptoError, Result};
use crate::identity::{
    authority_key_id_from_public, incarnation_id_from_authority_public, AccountIdentityKeysV1,
};
use crate::labels;
use crate::primitives::{
    hash, hpke_open, hpke_public_key, hpke_seal, SigningKey, Suite, VerifyingKey,
};

const CERTIFICATE_MAGIC: &[u8; 8] = b"KUTPOC1\0";
const SHARE_MAGIC: &[u8; 8] = b"KUTPOS1\0";
const REQUEST_MAGIC: &[u8; 8] = b"KUTPOR1\0";
const ESCROW_MAGIC: &[u8; 8] = b"KUTPOE1\0";
/// X-Wing, HKDF-SHA256, ChaCha20-Poly1305, Ed25519 (docs/plans/pq-shares.md).
const SUITE: u16 = 1;
const SIGNATURE_LEN: usize = 64;
const PUBLIC_KEY_LEN: usize = crate::hpke_xwing::PUBLIC_KEY_LEN;
const ENCAPSULATED_LEN: usize = crate::hpke_xwing::ENCAPSULATED_KEY_LEN;
/// A 32-byte secret sealed with ChaCha20-Poly1305.
const SEALED_SECRET_LEN: usize = 32 + 16;

/// An organization key's id: a hash of its public key.
pub type KeyId = [u8; 32];

/// The organization key's public key for its seed.
pub fn public_key(seed: &[u8; 32]) -> Vec<u8> {
    hpke_public_key(Suite::V1, seed)
}

/// An organization key's id.
pub fn key_id(public_key: &[u8]) -> KeyId {
    let mut input = labels::ORG_KEY_ID_V1.to_vec();
    input.extend_from_slice(public_key);
    hash(Suite::V1, input).into()
}

/// A new organization key: its seed (kept as purpose 7 by each admin), its
/// public key and its id.
pub fn generate() -> (Zeroizing<[u8; 32]>, Vec<u8>, KeyId) {
    let seed = Zeroizing::new(crate::primitives::random_array::<32>());
    let public = public_key(&seed);
    let id = key_id(&public);
    (seed, public, id)
}

/// Someone a document names: their account and its incarnation (32 bytes,
/// `AccountIdentityKeysV1::incarnation_id` in hex).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Party {
    pub account: AccountRef,
    pub incarnation_id: [u8; 32],
}

impl Party {
    pub fn new(account: &AccountRef, incarnation_id: &str) -> Result<Self> {
        Ok(Self {
            account: account.clone(),
            incarnation_id: hex_32(incarnation_id, "incarnation")?,
        })
    }

    fn put(&self, out: &mut Vec<u8>) -> Result<()> {
        put(out, &self.account.bytes())?;
        out.extend_from_slice(&self.incarnation_id);
        Ok(())
    }

    fn take(reader: &mut Reader<'_>) -> Result<Self> {
        let bytes = reader.prefixed()?;
        let (account, used) = AccountRef::read(bytes)
            .map_err(|_| CryptoError::InvalidInput("organization document: account".into()))?;
        if used != bytes.len() {
            return Err(CryptoError::InvalidInput(
                "organization document: account has trailing bytes".into(),
            ));
        }
        Ok(Self {
            account,
            incarnation_id: reader.array()?,
        })
    }

    /// Whether `authority` is this party's: the incarnation it derives.
    fn is_authority(&self, authority: &[u8; 32]) -> Result<bool> {
        Ok(hex_32(
            &incarnation_id_from_authority_public(authority),
            "incarnation",
        )? == self.incarnation_id)
    }
}

fn hex_32(value: &str, what: &str) -> Result<[u8; 32]> {
    let bytes =
        hex::decode(value).map_err(|_| CryptoError::InvalidInput(format!("{what}: hex")))?;
    bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidInput(format!("{what}: 32 bytes")))
}

fn uuid_bytes(value: &str) -> Result<[u8; 16]> {
    crate::drive_object::parse_canonical_uuid(value, "organization")
}

fn put(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len = u16::try_from(bytes.len())
        .map_err(|_| CryptoError::InvalidInput("organization document field too long".into()))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Reads a document field by field; every read past the end is refused.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], magic: &[u8; 8]) -> Result<Self> {
        if bytes.get(..8) != Some(magic.as_slice()) {
            return Err(CryptoError::InvalidInput(
                "not this organization document".into(),
            ));
        }
        let mut reader = Self { bytes, at: 8 };
        if u16::from_be_bytes(reader.array()?) != SUITE {
            return Err(CryptoError::InvalidInput(
                "unknown organization suite".into(),
            ));
        }
        Ok(reader)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len());
        let end =
            end.ok_or_else(|| CryptoError::InvalidInput("organization document too short".into()))?;
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("N bytes"))
    }

    fn prefixed(&mut self) -> Result<&'a [u8]> {
        let len = u16::from_be_bytes(self.array()?) as usize;
        self.take(len)
    }

    fn text(&mut self) -> Result<String> {
        String::from_utf8(self.prefixed()?.to_vec())
            .map_err(|_| CryptoError::InvalidInput("organization document: text".into()))
    }

    /// The signed part and the signature that ends the document.
    fn signed(self) -> Result<(&'a [u8], [u8; SIGNATURE_LEN])> {
        if self.bytes.len() != self.at + SIGNATURE_LEN {
            return Err(CryptoError::InvalidInput(
                "organization document length".into(),
            ));
        }
        Ok((
            &self.bytes[..self.at],
            self.bytes[self.at..].try_into().expect("64 bytes"),
        ))
    }

    fn end(self) -> Result<()> {
        if self.at != self.bytes.len() {
            return Err(CryptoError::InvalidInput(
                "organization document length".into(),
            ));
        }
        Ok(())
    }
}

fn header(magic: &[u8; 8]) -> Vec<u8> {
    let mut out = magic.to_vec();
    out.extend_from_slice(&SUITE.to_be_bytes());
    out
}

fn signing_input(label: &[u8], body: &[u8]) -> Vec<u8> {
    let mut input = label.to_vec();
    input.extend_from_slice(body);
    input
}

fn sign(label: &[u8], mut body: Vec<u8>, key: &SigningKey) -> Vec<u8> {
    let signature: [u8; SIGNATURE_LEN] = key.sign_array(&signing_input(label, &body));
    body.extend_from_slice(&signature);
    body
}

fn verify(label: &[u8], body: &[u8], signature: &[u8], authority: &[u8; 32]) -> Result<()> {
    VerifyingKey::from_bytes(Suite::V1, authority)?
        .verify(&signing_input(label, body), signature)
        .map_err(|_| CryptoError::AuthFailed)
}

/// An admin's certificate of an organization key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyCertificateV1 {
    pub organization_id: [u8; 16],
    pub key_id: KeyId,
    pub public_key: Vec<u8>,
    /// Unix seconds.
    pub issued_at: u64,
    pub admin: Party,
    /// The admin's authority key id at signing: a rotation needs a new one
    /// (W6 rotation checklist).
    pub admin_authority_key_id: String,
}

/// A certificate whose signature, key id and admin were checked: the only
/// way to the public key an escrow is sealed to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedKeyCertificate(KeyCertificateV1);

impl std::ops::Deref for VerifiedKeyCertificate {
    type Target = KeyCertificateV1;

    fn deref(&self) -> &KeyCertificateV1 {
        &self.0
    }
}

impl KeyCertificateV1 {
    /// Signs a certificate of `public_key` for `organization_id` with
    /// `admin`'s authority.
    pub fn sign(
        organization_id: &str,
        public_key: &[u8],
        issued_at: u64,
        admin: &Party,
        admin_keys: &AccountIdentityKeysV1,
    ) -> Result<Vec<u8>> {
        if public_key.len() != PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidInput(
                "organization public key length".into(),
            ));
        }
        if !admin.is_authority(&admin_keys.authority_public_key())? {
            return Err(CryptoError::InvalidInput(
                "the admin's incarnation is not their authority's".into(),
            ));
        }
        let mut body = header(CERTIFICATE_MAGIC);
        body.extend_from_slice(&uuid_bytes(organization_id)?);
        body.extend_from_slice(&key_id(public_key));
        put(&mut body, public_key)?;
        body.extend_from_slice(&issued_at.to_be_bytes());
        admin.put(&mut body)?;
        put(&mut body, admin_keys.authority_key_id().as_bytes())?;
        Ok(sign(
            labels::ORG_KEY_CERTIFICATE_V1,
            body,
            admin_keys.authority_signing_key(),
        ))
    }

    /// The certificate, if `admin_authority` (the admin's published account
    /// authority) signed it, its key id is its public key's, and the admin
    /// it names is that authority's (incarnation and authority key id).
    /// This proves who signed; whether they are an admin is the server's
    /// word (§3, what the member's client checks at consent).
    pub fn verify(bytes: &[u8], admin_authority: &[u8; 32]) -> Result<VerifiedKeyCertificate> {
        let mut reader = Reader::new(bytes, CERTIFICATE_MAGIC)?;
        let organization_id = reader.array()?;
        let key_id_read: KeyId = reader.array()?;
        let public_key = reader.prefixed()?.to_vec();
        let issued_at = u64::from_be_bytes(reader.array()?);
        let admin = Party::take(&mut reader)?;
        let admin_authority_key_id = reader.text()?;
        let (body, signature) = reader.signed()?;
        verify(
            labels::ORG_KEY_CERTIFICATE_V1,
            body,
            &signature,
            admin_authority,
        )?;
        if public_key.len() != PUBLIC_KEY_LEN
            || key_id(&public_key) != key_id_read
            || authority_key_id_from_public(admin_authority) != admin_authority_key_id
            || !admin.is_authority(admin_authority)?
        {
            return Err(CryptoError::AuthFailed);
        }
        Ok(VerifiedKeyCertificate(Self {
            organization_id,
            key_id: key_id_read,
            public_key,
            issued_at,
            admin,
            admin_authority_key_id,
        }))
    }
}

/// An account's Drive X-Wing key from its authority-signed Drive key binding
/// (`drive_key_binding`): the only key an organization key share is sealed
/// to, so a server can't swap in its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDriveKey {
    account: AccountRef,
    authority: [u8; 32],
    hpke_public: [u8; PUBLIC_KEY_LEN],
}

impl VerifiedDriveKey {
    /// Checks the binding `signature` by `authority_public` over the
    /// account's Drive keys at `epoch`.
    pub fn verify(
        account: &AccountRef,
        authority_public: &[u8; 32],
        epoch: u32,
        drive_hpke_public: &[u8; PUBLIC_KEY_LEN],
        drive_signing_public: &[u8; 32],
        signature: &[u8],
    ) -> Result<Self> {
        crate::drive_key_binding::verify(
            account,
            authority_public,
            epoch,
            drive_hpke_public,
            drive_signing_public,
            signature,
        )?;
        Ok(Self {
            account: account.clone(),
            authority: *authority_public,
            hpke_public: *drive_hpke_public,
        })
    }
}

fn public_key_hash(public_key: &[u8]) -> [u8; 32] {
    hash(Suite::V1, public_key).into()
}

/// The organization key's seed for one admin.
pub struct KeyShareV1;

impl KeyShareV1 {
    fn header(
        organization_id: &[u8; 16],
        key_id: &KeyId,
        recipient: &Party,
        recipient_key_hash: &[u8; 32],
        granter: &Party,
        granter_authority_key_id: &str,
    ) -> Result<Vec<u8>> {
        let mut out = header(SHARE_MAGIC);
        out.extend_from_slice(organization_id);
        out.extend_from_slice(key_id);
        recipient.put(&mut out)?;
        out.extend_from_slice(recipient_key_hash);
        granter.put(&mut out)?;
        put(&mut out, granter_authority_key_id.as_bytes())?;
        Ok(out)
    }

    /// Seals `seed` to `recipient`'s verified Drive X-Wing key, signed by
    /// the granting admin.
    pub fn seal(
        seed: &[u8; 32],
        organization_id: &str,
        recipient: &Party,
        recipient_key: &VerifiedDriveKey,
        granter: &Party,
        granter_keys: &AccountIdentityKeysV1,
    ) -> Result<Vec<u8>> {
        if recipient_key.account != recipient.account
            || !recipient.is_authority(&recipient_key.authority)?
            || !granter.is_authority(&granter_keys.authority_public_key())?
        {
            return Err(CryptoError::InvalidInput(
                "the share's parties are not their keys'".into(),
            ));
        }
        let key_id = key_id(&public_key(seed));
        let mut body = Self::header(
            &uuid_bytes(organization_id)?,
            &key_id,
            recipient,
            &public_key_hash(&recipient_key.hpke_public),
            granter,
            &granter_keys.authority_key_id(),
        )?;
        let sealed = hpke_seal(
            Suite::V1,
            &recipient_key.hpke_public,
            labels::ORG_KEY_SHARE_V1,
            &body,
            seed,
        )?;
        body.extend_from_slice(&sealed.encapsulated);
        put(&mut body, &sealed.ciphertext)?;
        Ok(sign(
            labels::ORG_KEY_SHARE_SIGNATURE_V1,
            body,
            granter_keys.authority_signing_key(),
        ))
    }

    /// Opens a share for `recipient` with their Drive X-Wing seed, if
    /// `granter_authority` signed it for this organization and key and the
    /// granter it names is that authority's: the organization key's seed,
    /// checked against `key_id`, and the granter.
    pub fn open(
        bytes: &[u8],
        organization_id: &str,
        key_id_expected: &KeyId,
        recipient: &Party,
        recipient_hpke_seed: &[u8; 32],
        granter_authority: &[u8; 32],
    ) -> Result<(Zeroizing<[u8; 32]>, Party)> {
        let mut reader = Reader::new(bytes, SHARE_MAGIC)?;
        let organization: [u8; 16] = reader.array()?;
        let key: KeyId = reader.array()?;
        let named_recipient = Party::take(&mut reader)?;
        let recipient_key_hash: [u8; 32] = reader.array()?;
        let granter = Party::take(&mut reader)?;
        let granter_authority_key_id = reader.text()?;
        let header_len = reader.at;
        let encapsulated: [u8; ENCAPSULATED_LEN] = reader.array()?;
        let ciphertext = reader.prefixed()?;
        if ciphertext.len() != SEALED_SECRET_LEN {
            return Err(CryptoError::InvalidInput(
                "organization key share length".into(),
            ));
        }
        let (body, signature) = reader.signed()?;
        verify(
            labels::ORG_KEY_SHARE_SIGNATURE_V1,
            body,
            &signature,
            granter_authority,
        )?;
        if organization != uuid_bytes(organization_id)?
            || &key != key_id_expected
            || &named_recipient != recipient
            || recipient_key_hash
                != public_key_hash(&hpke_public_key(Suite::V1, recipient_hpke_seed))
            || authority_key_id_from_public(granter_authority) != granter_authority_key_id
            || !granter.is_authority(granter_authority)?
        {
            return Err(CryptoError::AuthFailed);
        }
        let seed = hpke_open(
            Suite::V1,
            recipient_hpke_seed,
            &encapsulated,
            labels::ORG_KEY_SHARE_V1,
            &bytes[..header_len],
            ciphertext,
        )?;
        let seed: [u8; 32] = seed
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::AuthFailed)?;
        let seed = Zeroizing::new(seed);
        if key_id(&public_key(&seed)) != key {
            return Err(CryptoError::AuthFailed);
        }
        Ok((seed, granter))
    }
}

/// An admin's signed request that a member become managed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessRequestV1 {
    pub organization_id: [u8; 16],
    pub key_id: KeyId,
    pub member: Party,
    pub admin: Party,
    /// Unix seconds.
    pub issued_at: u64,
}

impl AccessRequestV1 {
    pub fn sign(&self, admin_keys: &AccountIdentityKeysV1) -> Result<Vec<u8>> {
        if !self
            .admin
            .is_authority(&admin_keys.authority_public_key())?
        {
            return Err(CryptoError::InvalidInput(
                "the admin's incarnation is not their authority's".into(),
            ));
        }
        let mut body = header(REQUEST_MAGIC);
        body.extend_from_slice(&self.organization_id);
        body.extend_from_slice(&self.key_id);
        self.member.put(&mut body)?;
        self.admin.put(&mut body)?;
        body.extend_from_slice(&self.issued_at.to_be_bytes());
        Ok(sign(
            labels::ORG_ACCESS_REQUEST_V1,
            body,
            admin_keys.authority_signing_key(),
        ))
    }

    /// The request, if `admin_authority` signed it and is the admin it names.
    pub fn verify(bytes: &[u8], admin_authority: &[u8; 32]) -> Result<Self> {
        let mut reader = Reader::new(bytes, REQUEST_MAGIC)?;
        let request = Self {
            organization_id: reader.array()?,
            key_id: reader.array()?,
            member: Party::take(&mut reader)?,
            admin: Party::take(&mut reader)?,
            issued_at: u64::from_be_bytes(reader.array()?),
        };
        let (body, signature) = reader.signed()?;
        verify(
            labels::ORG_ACCESS_REQUEST_V1,
            body,
            &signature,
            admin_authority,
        )?;
        if !request.admin.is_authority(admin_authority)? {
            return Err(CryptoError::AuthFailed);
        }
        Ok(request)
    }
}

/// A managed member's master key, sealed to the organization key.
pub struct EscrowV1;

/// What an opened escrow gives: the master key, of this generation.
pub struct Escrowed {
    pub master_key: Zeroizing<[u8; 32]>,
    pub generation: MasterKeyGeneration,
}

impl EscrowV1 {
    fn header(
        organization_id: &[u8; 16],
        key_id: &KeyId,
        member: &Party,
        generation: MasterKeyGeneration,
    ) -> Result<Vec<u8>> {
        let mut out = header(ESCROW_MAGIC);
        out.extend_from_slice(organization_id);
        out.extend_from_slice(key_id);
        member.put(&mut out)?;
        out.extend_from_slice(&generation.get().to_be_bytes());
        Ok(out)
    }

    /// Seals `master_key` (of `generation`, the member's) to the
    /// organization key of `certificate`, verified by the member's client
    /// (the admin pinned, and the rest of §3's consent checks).
    pub fn seal(
        master_key: &[u8; 32],
        generation: MasterKeyGeneration,
        certificate: &VerifiedKeyCertificate,
        member: &Party,
    ) -> Result<Vec<u8>> {
        let mut out = Self::header(
            &certificate.organization_id,
            &certificate.key_id,
            member,
            generation,
        )?;
        let sealed = hpke_seal(
            Suite::V1,
            &certificate.public_key,
            labels::ORG_MEMBER_ESCROW_V1,
            &out,
            master_key,
        )?;
        out.extend_from_slice(&sealed.encapsulated);
        put(&mut out, &sealed.ciphertext)?;
        Ok(out)
    }

    /// Opens an escrow of `member` with the organization key's seed: the
    /// master key, if the authority and incarnation it derives are the
    /// member's (`member_authority`, their published account authority).
    /// The generation only labels which master key it is: a downgrade is
    /// refused because rotation gives a new authority (W6 rotation
    /// checklist).
    pub fn open(
        bytes: &[u8],
        organization_id: &str,
        organization_seed: &[u8; 32],
        member: &Party,
        member_authority: &[u8; 32],
    ) -> Result<Escrowed> {
        let mut reader = Reader::new(bytes, ESCROW_MAGIC)?;
        let organization: [u8; 16] = reader.array()?;
        let key: KeyId = reader.array()?;
        let named_member = Party::take(&mut reader)?;
        let generation = MasterKeyGeneration::new(u32::from_be_bytes(reader.array()?))?;
        let header_len = reader.at;
        let encapsulated: [u8; ENCAPSULATED_LEN] = reader.array()?;
        let ciphertext = reader.prefixed()?;
        reader.end()?;
        if organization != uuid_bytes(organization_id)?
            || key != key_id(&public_key(organization_seed))
            || &named_member != member
        {
            return Err(CryptoError::AuthFailed);
        }
        let opened = hpke_open(
            Suite::V1,
            organization_seed,
            &encapsulated,
            labels::ORG_MEMBER_ESCROW_V1,
            &bytes[..header_len],
            ciphertext,
        )?;
        let master_key: [u8; 32] = opened
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::AuthFailed)?;
        let master_key = Zeroizing::new(master_key);
        // A server can't plant an escrow: the master key must be the member's.
        let keys = AccountIdentityKeysV1::derive(&master_key)?;
        if &keys.authority_public_key() != member_authority
            || !member.is_authority(member_authority)?
        {
            return Err(CryptoError::AuthFailed);
        }
        Ok(Escrowed {
            master_key,
            generation,
        })
    }
}

#[cfg(test)]
mod tests;
