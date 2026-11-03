//! An organization's key and what admins and members exchange with it
//! (docs/plans/organizations.md §3, following Proton's organization keys).
//!
//! - The **organization key** is an X-Wing key pair from a random 32-byte
//!   seed; its id is a hash of the public key (`kutup/org/key-id/v1`).
//! - [`KeyCertificateV1`]: the admin who made it vouches for it, signed with
//!   their account authority (Proton's fingerprint signature).
//! - [`KeyShareV1`]: the seed sealed to a new admin's Drive X-Wing key, bound
//!   to the organization, the key, the recipient and the granting admin, and
//!   signed by the granting admin (Proton's `OrganizationKeyInvitation`).
//! - [`AccessRequestV1`]: an admin's signed request that a private member
//!   become managed (Proton's signed `InvitationData`).
//! - [`EscrowV1`]: a managed member's master key sealed to the organization
//!   key, bound to the member, their incarnation and the master key's
//!   generation. Unsigned: whoever opens it derives the authority from the
//!   master key and checks it is the member's, so a server can't plant one.
//!
//! Each format is an 8-byte magic, a suite, then length-prefixed fields; a
//! signature covers its label then every byte before it. Nothing binds a
//! username, an address or the organization's name.

use zeroize::Zeroizing;

use crate::account_envelope::MasterKeyGeneration;
use crate::account_ref::AccountRef;
use crate::error::{CryptoError, Result};
use crate::identity::{authority_key_id_from_public, AccountIdentityKeysV1};
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

    fn put(&self, out: &mut Vec<u8>) {
        put(out, &self.account.bytes());
        out.extend_from_slice(&self.incarnation_id);
    }

    fn take(reader: &mut Reader<'_>) -> Result<Self> {
        let (account, _) = AccountRef::read(reader.prefixed()?)
            .map_err(|_| CryptoError::InvalidInput("organization document: account".into()))?;
        Ok(Self {
            account,
            incarnation_id: reader.array()?,
        })
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

fn put(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
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
        if public_key.len() != crate::hpke_xwing::PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidInput(
                "organization public key length".into(),
            ));
        }
        let mut body = header(CERTIFICATE_MAGIC);
        body.extend_from_slice(&uuid_bytes(organization_id)?);
        body.extend_from_slice(&key_id(public_key));
        put(&mut body, public_key);
        body.extend_from_slice(&issued_at.to_be_bytes());
        admin.put(&mut body);
        put(&mut body, admin_keys.authority_key_id().as_bytes());
        Ok(sign(
            labels::ORG_KEY_CERTIFICATE_V1,
            body,
            admin_keys.authority_signing_key(),
        ))
    }

    /// The certificate, if `admin_authority` (the admin's published account
    /// authority) signed it and its key id is its public key's.
    pub fn verify(bytes: &[u8], admin_authority: &[u8; 32]) -> Result<Self> {
        let mut reader = Reader::new(bytes, CERTIFICATE_MAGIC)?;
        let organization_id = reader.array()?;
        let key_id_read: KeyId = reader.array()?;
        let public_key = reader.prefixed()?.to_vec();
        let issued_at = u64::from_be_bytes(reader.array()?);
        let admin = Party::take(&mut reader)?;
        let admin_authority_key_id = String::from_utf8(reader.prefixed()?.to_vec())
            .map_err(|_| CryptoError::InvalidInput("authority key id".into()))?;
        let (body, signature) = reader.signed()?;
        verify(
            labels::ORG_KEY_CERTIFICATE_V1,
            body,
            &signature,
            admin_authority,
        )?;
        if key_id(&public_key) != key_id_read
            || authority_key_id_from_public(admin_authority) != admin_authority_key_id
        {
            return Err(CryptoError::AuthFailed);
        }
        Ok(Self {
            organization_id,
            key_id: key_id_read,
            public_key,
            issued_at,
            admin,
            admin_authority_key_id,
        })
    }
}

/// The organization key's seed for one admin.
pub struct KeyShareV1;

impl KeyShareV1 {
    fn header(
        organization_id: &[u8; 16],
        key_id: &KeyId,
        recipient: &Party,
        granter: &Party,
    ) -> Vec<u8> {
        let mut out = header(SHARE_MAGIC);
        out.extend_from_slice(organization_id);
        out.extend_from_slice(key_id);
        recipient.put(&mut out);
        granter.put(&mut out);
        out
    }

    /// Seals `seed` (the organization key whose public key is `public_key`)
    /// to `recipient_hpke_public_key` (their Drive X-Wing key), signed by
    /// the granting admin.
    pub fn seal(
        seed: &[u8; 32],
        organization_id: &str,
        recipient: &Party,
        recipient_hpke_public_key: &[u8],
        granter: &Party,
        granter_keys: &AccountIdentityKeysV1,
    ) -> Result<Vec<u8>> {
        let key_id = key_id(&public_key(seed));
        let mut body = Self::header(&uuid_bytes(organization_id)?, &key_id, recipient, granter);
        let sealed = hpke_seal(
            Suite::V1,
            recipient_hpke_public_key,
            labels::ORG_KEY_SHARE_V1,
            &body,
            seed,
        )?;
        body.extend_from_slice(&sealed.encapsulated);
        put(&mut body, &sealed.ciphertext);
        Ok(sign(
            labels::ORG_KEY_SHARE_SIGNATURE_V1,
            body,
            granter_keys.authority_signing_key(),
        ))
    }

    /// Opens a share for `recipient` with their Drive X-Wing seed, if
    /// `granter_authority` signed it for this organization and key: the
    /// organization key's seed, checked against `key_id`.
    pub fn open(
        bytes: &[u8],
        organization_id: &str,
        key_id_expected: &KeyId,
        recipient: &Party,
        recipient_hpke_seed: &[u8],
        granter_authority: &[u8; 32],
    ) -> Result<(Zeroizing<[u8; 32]>, Party)> {
        let mut reader = Reader::new(bytes, SHARE_MAGIC)?;
        let organization: [u8; 16] = reader.array()?;
        let key: KeyId = reader.array()?;
        let named_recipient = Party::take(&mut reader)?;
        let granter = Party::take(&mut reader)?;
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
    pub fn sign(&self, admin_keys: &AccountIdentityKeysV1) -> Vec<u8> {
        let mut body = header(REQUEST_MAGIC);
        body.extend_from_slice(&self.organization_id);
        body.extend_from_slice(&self.key_id);
        self.member.put(&mut body);
        self.admin.put(&mut body);
        body.extend_from_slice(&self.issued_at.to_be_bytes());
        sign(
            labels::ORG_ACCESS_REQUEST_V1,
            body,
            admin_keys.authority_signing_key(),
        )
    }

    /// The request, if `admin_authority` signed it.
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
    ) -> Vec<u8> {
        let mut out = header(ESCROW_MAGIC);
        out.extend_from_slice(organization_id);
        out.extend_from_slice(key_id);
        member.put(&mut out);
        out.extend_from_slice(&generation.get().to_be_bytes());
        out
    }

    /// Seals `master_key` (of `generation`, the member's) to the
    /// organization key `organization_public_key`.
    pub fn seal(
        master_key: &[u8; 32],
        generation: MasterKeyGeneration,
        organization_id: &str,
        organization_public_key: &[u8],
        member: &Party,
    ) -> Result<Vec<u8>> {
        let mut out = Self::header(
            &uuid_bytes(organization_id)?,
            &key_id(organization_public_key),
            member,
            generation,
        );
        let sealed = hpke_seal(
            Suite::V1,
            organization_public_key,
            labels::ORG_MEMBER_ESCROW_V1,
            &out,
            master_key,
        )?;
        out.extend_from_slice(&sealed.encapsulated);
        put(&mut out, &sealed.ciphertext);
        Ok(out)
    }

    /// Opens an escrow of `member` with the organization key's seed: the
    /// master key, if the authority and incarnation it derives are the
    /// member's (`member_authority`, their published account authority).
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
            || hex_32(&keys.incarnation_id(), "incarnation")? != member.incarnation_id
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
