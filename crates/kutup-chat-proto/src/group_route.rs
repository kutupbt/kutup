//! The anonymous route to a group's home (docs/plans/pairwise-groups.md §3,
//! "The anonymous route"): the gateway key config the home signs with its
//! federation identity, the request a client seals to it (RFC 9458's
//! encapsulation, `kutup_crypto::oblivious`), the answer, and the home's
//! notary signature over every change it accepts.
//!
//! The group's state and change formats, and the acceptance checks, live in
//! `group`; this module only carries them (as canonical bytes) and
//! authenticates who sent them.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use kutup_federation_proto::FederationIdentityDocumentV1;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const GROUP_ROUTE_VERSION: u16 = 1;

/// How far a request's clock may be from the home's, either way.
pub const MAX_CLOCK_SKEW_SECS: i64 = 5 * 60;
/// How long the home remembers a nonce: twice the skew, so a request can't be
/// replayed at either edge of the window.
pub const NONCE_MEMORY_SECS: i64 = 2 * MAX_CLOCK_SKEW_SECS;
/// How long a key config is valid after it is signed; clients refetch before.
pub const MAX_KEY_CONFIG_LIFETIME_SECS: i64 = 7 * 24 * 60 * 60;
/// How long the home keeps accepting a key after rotating to the next.
pub const KEY_OVERLAP_SECS: i64 = 24 * 60 * 60;

const GROUP_ID_LEN: usize = 32;
const NONCE_LEN: usize = 16;
const KEY_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;
const HASH_LEN: usize = 32;
/// The largest operation body a request carries: a change is capped at this
/// (`group::MAX_CHANGE_BYTES`), so with the envelope's base64 and fields a
/// request always fits the 64 KiB padded size. Answers (a whole state) may
/// take the 256 KiB size.
pub const MAX_REQUEST_BODY: usize = 48 * 1024;

const KEY_CONFIG_DOMAIN: &[u8] = b"kutup/chat-group/gateway-key-config/v1\0";
const REQUEST_DOMAIN: &[u8] = b"kutup/chat-group/request/v1\0";
const LINK_PROOF_DOMAIN: &[u8] = b"kutup/chat-group/link-request/v1\0";
const NOTARY_DOMAIN: &[u8] = b"kutup/chat-group/notary/v1\0";
const BODY_HASH_DOMAIN: &[u8] = b"kutup/chat-group/request-body/v1\0";

// --- encoding ----------------------------------------------------------------

fn decode_fixed<const N: usize>(name: &str, value: &str) -> Result<[u8; N], String> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| format!("{name} must be canonical padded base64"))?;
    if STANDARD.encode(&bytes) != value {
        return Err(format!("{name} must be canonical padded base64"));
    }
    bytes
        .try_into()
        .map_err(|_| format!("{name} must be {N} bytes"))
}

fn decode_bounded(name: &str, value: &str, maximum: usize) -> Result<Vec<u8>, String> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| format!("{name} must be canonical padded base64"))?;
    if bytes.len() > maximum || STANDARD.encode(&bytes) != value {
        return Err(format!(
            "{name} must be canonical padded base64 within its size limit"
        ));
    }
    Ok(bytes)
}

/// A group id on the wire: 32 bytes, base64url without padding.
pub fn decode_group_id(value: &str) -> Result<[u8; GROUP_ID_LEN], String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "groupId must be base64url without padding".to_string())?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err("groupId must be canonical base64url".into());
    }
    bytes
        .try_into()
        .map_err(|_| "groupId must be 32 bytes".to_string())
}

pub fn encode_group_id(group_id: &[u8; GROUP_ID_LEN]) -> String {
    URL_SAFE_NO_PAD.encode(group_id)
}

fn verifying_key(name: &str, encoded: &str) -> Result<VerifyingKey, String> {
    let bytes = decode_fixed::<KEY_LEN>(name, encoded)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| format!("{name} is not an Ed25519 key"))
}

fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|error| error.to_string())
}

fn from_canonical<T>(bytes: &[u8], maximum: usize, name: &str) -> Result<T, String>
where
    T: Serialize + for<'de> Deserialize<'de>,
{
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(format!("{name} length is invalid"));
    }
    let value: T =
        serde_json::from_slice(bytes).map_err(|error| format!("invalid {name}: {error}"))?;
    if canonical(&value)? != bytes {
        return Err(format!("{name} is not canonical JSON"));
    }
    Ok(value)
}

fn require_version(version: u16) -> Result<(), String> {
    if version != GROUP_ROUTE_VERSION {
        return Err("unsupported group route version".into());
    }
    Ok(())
}

// --- the home's identity, pinned in the group -----------------------------------

/// The home server's federation identity as a group pins it at genesis (and
/// every invitation and link carries it): the document by sequence and hash.
/// A later key config must be signed by this document's key, or by a
/// successor reached from it through the signed identity history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupHomePinV1 {
    pub server: String,
    pub identity_sequence: u64,
    pub identity_document_hash: String,
}

impl GroupHomePinV1 {
    pub fn of(document: &FederationIdentityDocumentV1) -> Result<Self, String> {
        Ok(Self {
            server: document.server.clone(),
            identity_sequence: document.sequence,
            identity_document_hash: document.document_hash().map_err(|e| e.to_string())?,
        })
    }

    /// The identity current at the end of `documents`, which must start at
    /// the pinned document and continue through valid successors only.
    pub fn follow<'a>(
        &self,
        documents: &'a [FederationIdentityDocumentV1],
    ) -> Result<&'a FederationIdentityDocumentV1, String> {
        let (first, rest) = documents
            .split_first()
            .ok_or_else(|| "identity history is empty".to_string())?;
        if first.server != self.server
            || first.sequence != self.identity_sequence
            || first.document_hash().map_err(|e| e.to_string())? != self.identity_document_hash
        {
            return Err("identity history does not start at the pinned document".into());
        }
        first.verify_current().map_err(|e| e.to_string())?;
        let mut previous = first;
        for current in rest {
            current
                .verify_successor(previous, &self.server)
                .map_err(|e| e.to_string())?;
            previous = current;
        }
        Ok(previous)
    }
}

// --- the gateway key config ------------------------------------------------------

/// The HPKE key a home's gateway takes requests under, signed by the home's
/// federation identity, so a relay (the client's own server, which fetches it)
/// can't substitute its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupGatewayKeyConfigV1 {
    pub version: u16,
    pub server: String,
    pub key_id: u8,
    pub kem_id: u16,
    pub kdf_id: u16,
    pub aead_id: u16,
    pub public_key: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub identity_sequence: u64,
    pub signature: String,
}

impl GroupGatewayKeyConfigV1 {
    fn signing_input(&self) -> Result<Vec<u8>, String> {
        let mut unsigned = self.clone();
        unsigned.signature = String::new();
        let mut input = KEY_CONFIG_DOMAIN.to_vec();
        input.extend_from_slice(&canonical(&unsigned)?);
        Ok(input)
    }

    /// Signs a config for `public_key` with the identity `document`'s key.
    pub fn sign(
        document: &FederationIdentityDocumentV1,
        signing_key: &SigningKey,
        key_id: u8,
        public_key: &[u8; KEY_LEN],
        issued_at: i64,
        expires_at: i64,
    ) -> Result<Self, String> {
        if document.key.public_key_bytes().map_err(|e| e.to_string())?
            != signing_key.verifying_key().to_bytes()
        {
            return Err("signing key is not the identity document's key".into());
        }
        let mut config = Self {
            version: GROUP_ROUTE_VERSION,
            server: document.server.clone(),
            key_id,
            kem_id: kutup_crypto::oblivious::KEM_X25519_HKDF_SHA256,
            kdf_id: kutup_crypto::oblivious::KDF_HKDF_SHA256,
            aead_id: kutup_crypto::oblivious::AEAD_CHACHA20_POLY1305,
            public_key: STANDARD.encode(public_key),
            issued_at,
            expires_at,
            identity_sequence: document.sequence,
            signature: String::new(),
        };
        config.validate_shape()?;
        let signature = signing_key.sign(&config.signing_input()?);
        config.signature = STANDARD.encode(signature.to_bytes());
        Ok(config)
    }

    fn validate_shape(&self) -> Result<(), String> {
        require_version(self.version)?;
        if self.kem_id != kutup_crypto::oblivious::KEM_X25519_HKDF_SHA256
            || self.kdf_id != kutup_crypto::oblivious::KDF_HKDF_SHA256
            || self.aead_id != kutup_crypto::oblivious::AEAD_CHACHA20_POLY1305
        {
            return Err("gateway key config names an unsupported suite".into());
        }
        if self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > MAX_KEY_CONFIG_LIFETIME_SECS
        {
            return Err("gateway key config lifetime is invalid".into());
        }
        decode_fixed::<KEY_LEN>("publicKey", &self.public_key)?;
        Ok(())
    }

    /// The config's key, after checking it is `identity`'s (the document the
    /// client reached from its pin, [`GroupHomePinV1::follow`]) and current.
    pub fn verify(
        &self,
        identity: &FederationIdentityDocumentV1,
        now: i64,
    ) -> Result<(u8, [u8; KEY_LEN]), String> {
        self.validate_shape()?;
        if self.server != identity.server || self.identity_sequence != identity.sequence {
            return Err("gateway key config is not signed by this identity".into());
        }
        if now >= self.expires_at || now + MAX_CLOCK_SKEW_SECS < self.issued_at {
            return Err("gateway key config is not current".into());
        }
        let key = identity.key.verifying_key().map_err(|e| e.to_string())?;
        let signature = Signature::from_bytes(&decode_fixed::<SIGNATURE_LEN>(
            "signature",
            &self.signature,
        )?);
        key.verify_strict(&self.signing_input()?, &signature)
            .map_err(|_| "gateway key config signature is invalid".to_string())?;
        Ok((
            self.key_id,
            decode_fixed::<KEY_LEN>("publicKey", &self.public_key)?,
        ))
    }
}

// --- the request ------------------------------------------------------------------

/// What a request asks of the home.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GroupOperationV1 {
    /// A new group: the body is its genesis change.
    Create,
    /// The current state: no body.
    GetState,
    /// Changes from a revision on: the body is a [`GroupLogQueryV1`].
    GetLogs,
    /// A change at `current + 1` (also a claim, a join or a join request):
    /// the body is the change.
    SubmitChange,
    /// What a link shows before joining: no body; link-authorised.
    GetJoinInfo,
    /// A call token for the group's SFU: no body.
    CallToken,
    /// The encrypted avatar: no body.
    GetAvatar,
    /// A new encrypted avatar: the body is the ciphertext.
    PutAvatar,
}

impl GroupOperationV1 {
    fn tag(self) -> u8 {
        match self {
            Self::Create => 1,
            Self::GetState => 2,
            Self::GetLogs => 3,
            Self::SubmitChange => 4,
            Self::GetJoinInfo => 5,
            Self::CallToken => 6,
            Self::GetAvatar => 7,
            Self::PutAvatar => 8,
        }
    }

    /// Whether a link's password, not a member pseudonym, authorises it.
    pub fn is_link_authorised(self) -> bool {
        matches!(self, Self::GetJoinInfo)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupLogQueryV1 {
    pub from_revision: u64,
    pub limit: u16,
}

/// Who a request is from: a pseudonym's signature, or for a link's join
/// info, a proof of the link's password.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind", deny_unknown_fields)]
pub enum GroupRequestAuthV1 {
    #[serde(rename_all = "camelCase")]
    Pseudonym {
        pseudonym: String,
        signature: String,
    },
    #[serde(rename_all = "camelCase")]
    LinkPassword { proof: String },
}

/// The request inside the oblivious encapsulation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupRequestV1 {
    pub version: u16,
    pub group_id: String,
    pub operation: GroupOperationV1,
    pub timestamp: i64,
    pub nonce: String,
    pub body: String,
    pub auth: GroupRequestAuthV1,
}

/// The fields a request's authorisation covers.
struct RequestDigest([u8; HASH_LEN]);

impl GroupRequestV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate_shape()?;
        canonical(self)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        let value: Self =
            from_canonical(bytes, kutup_crypto::oblivious::MAX_BODY, "group request")?;
        value.validate_shape()?;
        Ok(value)
    }

    fn validate_shape(&self) -> Result<(), String> {
        require_version(self.version)?;
        decode_group_id(&self.group_id)?;
        decode_fixed::<NONCE_LEN>("nonce", &self.nonce)?;
        let body = decode_bounded("body", &self.body, MAX_REQUEST_BODY)?;
        let needs_body = matches!(
            self.operation,
            GroupOperationV1::Create
                | GroupOperationV1::GetLogs
                | GroupOperationV1::SubmitChange
                | GroupOperationV1::PutAvatar
        );
        if needs_body == body.is_empty() {
            return Err("request body does not fit its operation".into());
        }
        match (&self.auth, self.operation.is_link_authorised()) {
            (
                GroupRequestAuthV1::Pseudonym {
                    pseudonym,
                    signature,
                },
                false,
            ) => {
                verifying_key("pseudonym", pseudonym)?;
                decode_fixed::<SIGNATURE_LEN>("signature", signature)?;
            }
            (GroupRequestAuthV1::LinkPassword { proof }, true) => {
                decode_fixed::<HASH_LEN>("proof", proof)?;
            }
            _ => return Err("request authorisation does not fit its operation".into()),
        }
        Ok(())
    }

    pub fn group_id(&self) -> Result<[u8; GROUP_ID_LEN], String> {
        decode_group_id(&self.group_id)
    }

    pub fn body(&self) -> Result<Vec<u8>, String> {
        decode_bounded("body", &self.body, MAX_REQUEST_BODY)
    }

    fn digest(&self) -> Result<RequestDigest, String> {
        let body = self.body()?;
        let body_hash = Sha256::new()
            .chain_update(BODY_HASH_DOMAIN)
            .chain_update(&body)
            .finalize();
        let mut hasher = Sha256::new();
        hasher.update(self.group_id()?);
        hasher.update([self.operation.tag()]);
        hasher.update(self.timestamp.to_be_bytes());
        hasher.update(decode_fixed::<NONCE_LEN>("nonce", &self.nonce)?);
        hasher.update(body_hash);
        Ok(RequestDigest(hasher.finalize().into()))
    }

    fn pseudonym_input(&self, pseudonym: &[u8; KEY_LEN]) -> Result<Vec<u8>, String> {
        let mut input = REQUEST_DOMAIN.to_vec();
        input.extend_from_slice(pseudonym);
        input.extend_from_slice(&self.digest()?.0);
        Ok(input)
    }

    /// A request signed by a pseudonym.
    pub fn sign_with_pseudonym(
        group_id: &[u8; GROUP_ID_LEN],
        operation: GroupOperationV1,
        timestamp: i64,
        nonce: &[u8; NONCE_LEN],
        body: &[u8],
        pseudonym: &SigningKey,
    ) -> Result<Self, String> {
        let public = pseudonym.verifying_key().to_bytes();
        let mut request = Self {
            version: GROUP_ROUTE_VERSION,
            group_id: encode_group_id(group_id),
            operation,
            timestamp,
            nonce: STANDARD.encode(nonce),
            body: STANDARD.encode(body),
            auth: GroupRequestAuthV1::Pseudonym {
                pseudonym: STANDARD.encode(public),
                signature: STANDARD.encode([0u8; SIGNATURE_LEN]),
            },
        };
        let signature = pseudonym.sign(&request.pseudonym_input(&public)?);
        request.auth = GroupRequestAuthV1::Pseudonym {
            pseudonym: STANDARD.encode(public),
            signature: STANDARD.encode(signature.to_bytes()),
        };
        request.validate_shape()?;
        Ok(request)
    }

    /// A link-authorised request, proving the link's password.
    pub fn with_link_password(
        group_id: &[u8; GROUP_ID_LEN],
        operation: GroupOperationV1,
        timestamp: i64,
        nonce: &[u8; NONCE_LEN],
        link_password: &[u8],
    ) -> Result<Self, String> {
        let mut request = Self {
            version: GROUP_ROUTE_VERSION,
            group_id: encode_group_id(group_id),
            operation,
            timestamp,
            nonce: STANDARD.encode(nonce),
            body: String::new(),
            auth: GroupRequestAuthV1::LinkPassword {
                proof: STANDARD.encode([0u8; HASH_LEN]),
            },
        };
        let proof = request.link_proof(link_password)?;
        request.auth = GroupRequestAuthV1::LinkPassword {
            proof: STANDARD.encode(proof),
        };
        request.validate_shape()?;
        Ok(request)
    }

    fn link_proof(&self, link_password: &[u8]) -> Result<[u8; HASH_LEN], String> {
        let mut mac = Hmac::<Sha256>::new_from_slice(link_password)
            .map_err(|_| "link password is invalid".to_string())?;
        mac.update(LINK_PROOF_DOMAIN);
        mac.update(&self.digest()?.0);
        Ok(mac.finalize().into_bytes().into())
    }

    /// The pseudonym that signed the request, after checking its signature.
    /// The caller then checks the pseudonym is a member with the right role.
    pub fn verify_pseudonym(&self) -> Result<[u8; KEY_LEN], String> {
        self.validate_shape()?;
        let GroupRequestAuthV1::Pseudonym {
            pseudonym,
            signature,
        } = &self.auth
        else {
            return Err("request is not pseudonym-signed".into());
        };
        let key = verifying_key("pseudonym", pseudonym)?;
        let signature =
            Signature::from_bytes(&decode_fixed::<SIGNATURE_LEN>("signature", signature)?);
        key.verify_strict(&self.pseudonym_input(&key.to_bytes())?, &signature)
            .map_err(|_| "request signature is invalid".to_string())?;
        Ok(key.to_bytes())
    }

    /// Whether the request proves `link_password` (constant time).
    pub fn verify_link_password(&self, link_password: &[u8]) -> Result<bool, String> {
        self.validate_shape()?;
        let GroupRequestAuthV1::LinkPassword { proof } = &self.auth else {
            return Err("request is not link-authorised".into());
        };
        let proof = decode_fixed::<HASH_LEN>("proof", proof)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(link_password)
            .map_err(|_| "link password is invalid".to_string())?;
        mac.update(LINK_PROOF_DOMAIN);
        mac.update(&self.digest()?.0);
        Ok(mac.verify_slice(&proof).is_ok())
    }

    /// The nonce, as the home remembers it.
    pub fn nonce(&self) -> Result<[u8; NONCE_LEN], String> {
        decode_fixed::<NONCE_LEN>("nonce", &self.nonce)
    }

    /// Whether the request's clock is within the window of `now`.
    pub fn is_timely(&self, now: i64) -> bool {
        (self.timestamp - now).abs() <= MAX_CLOCK_SKEW_SECS
    }
}

// --- the answer ---------------------------------------------------------------------

/// What the home answers. `NotFound` is the one answer for an unknown group,
/// a pseudonym that isn't a member and a signature that doesn't verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GroupResponseStatusV1 {
    Ok,
    NotFound,
    /// The change wasn't at `current + 1`: refetch and verify again.
    Conflict,
    /// The change failed an acceptance check; `code` says which.
    Refused,
    /// The request's clock is off; `serverTime` is the home's.
    ClockSkew,
    Replayed,
    RateLimited,
    TooLarge,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupResponseV1 {
    pub version: u16,
    pub status: GroupResponseStatusV1,
    /// A stable check code with `Refused` (the `group` checks' error code).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    pub server_time: i64,
    /// The operation's answer as canonical bytes (state, a log page, a token).
    pub body: String,
}

impl GroupResponseV1 {
    pub fn new(status: GroupResponseStatusV1, server_time: i64, body: &[u8]) -> Self {
        Self {
            version: GROUP_ROUTE_VERSION,
            status,
            code: None,
            server_time,
            body: STANDARD.encode(body),
        }
    }

    pub fn refused(code: impl Into<String>, server_time: i64) -> Self {
        Self {
            code: Some(code.into()),
            ..Self::new(GroupResponseStatusV1::Refused, server_time, b"")
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        require_version(self.version)?;
        if self.code.is_some() != (self.status == GroupResponseStatusV1::Refused) {
            return Err("only a refusal carries a code".into());
        }
        decode_bounded("body", &self.body, kutup_crypto::oblivious::MAX_BODY)?;
        canonical(self)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        let value: Self =
            from_canonical(bytes, kutup_crypto::oblivious::MAX_BODY, "group response")?;
        value.canonical_bytes()?;
        Ok(value)
    }

    pub fn body(&self) -> Result<Vec<u8>, String> {
        decode_bounded("body", &self.body, kutup_crypto::oblivious::MAX_BODY)
    }
}

// --- the home's notary signature ------------------------------------------------------

/// The home's signature over a change it accepted: the group, the revision,
/// the change's hash and the resulting state's hash, by its federation
/// identity. Clients apply only changes that carry one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupNotaryV1 {
    pub identity_sequence: u64,
    pub signature: String,
}

fn notary_input(
    group_id: &[u8; GROUP_ID_LEN],
    revision: u64,
    change_hash: &[u8; HASH_LEN],
    state_hash: &[u8; HASH_LEN],
) -> Vec<u8> {
    let mut input = NOTARY_DOMAIN.to_vec();
    input.extend_from_slice(group_id);
    input.extend_from_slice(&revision.to_be_bytes());
    input.extend_from_slice(change_hash);
    input.extend_from_slice(state_hash);
    input
}

impl GroupNotaryV1 {
    pub fn sign(
        document: &FederationIdentityDocumentV1,
        signing_key: &SigningKey,
        group_id: &[u8; GROUP_ID_LEN],
        revision: u64,
        change_hash: &[u8; HASH_LEN],
        state_hash: &[u8; HASH_LEN],
    ) -> Result<Self, String> {
        if document.key.public_key_bytes().map_err(|e| e.to_string())?
            != signing_key.verifying_key().to_bytes()
        {
            return Err("signing key is not the identity document's key".into());
        }
        let signature =
            signing_key.sign(&notary_input(group_id, revision, change_hash, state_hash));
        Ok(Self {
            identity_sequence: document.sequence,
            signature: STANDARD.encode(signature.to_bytes()),
        })
    }

    /// Checks the signature by `identity`, the document of
    /// `identity_sequence` (reached from the group's pin).
    pub fn verify(
        &self,
        identity: &FederationIdentityDocumentV1,
        group_id: &[u8; GROUP_ID_LEN],
        revision: u64,
        change_hash: &[u8; HASH_LEN],
        state_hash: &[u8; HASH_LEN],
    ) -> Result<(), String> {
        if identity.sequence != self.identity_sequence {
            return Err("notary is signed by another identity document".into());
        }
        let key = identity.key.verifying_key().map_err(|e| e.to_string())?;
        let signature = Signature::from_bytes(&decode_fixed::<SIGNATURE_LEN>(
            "signature",
            &self.signature,
        )?);
        key.verify_strict(
            &notary_input(group_id, revision, change_hash, state_hash),
            &signature,
        )
        .map_err(|_| "notary signature is invalid".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(byte: u8) -> (FederationIdentityDocumentV1, SigningKey) {
        let key = SigningKey::from_bytes(&[byte; 32]);
        (
            FederationIdentityDocumentV1::genesis("home.example", 10, &key).unwrap(),
            key,
        )
    }

    const GROUP: [u8; 32] = [5; 32];
    const NONCE: [u8; 16] = [6; 16];

    #[test]
    fn a_key_config_verifies_only_from_its_pinned_identity() {
        let (genesis, key) = identity(1);
        let pin = GroupHomePinV1::of(&genesis).unwrap();
        let config = GroupGatewayKeyConfigV1::sign(&genesis, &key, 3, &[9; 32], 100, 200).unwrap();
        let current = pin.follow(std::slice::from_ref(&genesis)).unwrap();
        assert_eq!(config.verify(current, 150).unwrap(), (3, [9; 32]));
        assert!(config.verify(current, 200).is_err(), "expired");

        // A relay's own identity can't stand in for the pinned one.
        let (other, other_key) = identity(2);
        let forged =
            GroupGatewayKeyConfigV1::sign(&other, &other_key, 3, &[8; 32], 100, 200).unwrap();
        assert!(pin.follow(std::slice::from_ref(&other)).is_err());
        assert!(forged.verify(current, 150).is_err());

        let mut swapped = config.clone();
        swapped.public_key = STANDARD.encode([8u8; 32]);
        assert!(swapped.verify(current, 150).is_err());
    }

    #[test]
    fn a_rotated_identity_is_followed_from_the_pin() {
        let (genesis, first_key) = identity(1);
        let second_key = SigningKey::from_bytes(&[3; 32]);
        let second =
            FederationIdentityDocumentV1::rotate(&genesis, 20, &first_key, &second_key).unwrap();
        let pin = GroupHomePinV1::of(&genesis).unwrap();
        let history = [genesis.clone(), second.clone()];
        let current = pin.follow(&history).unwrap();
        assert_eq!(current.sequence, second.sequence);
        let config =
            GroupGatewayKeyConfigV1::sign(&second, &second_key, 4, &[7; 32], 100, 200).unwrap();
        assert!(config.verify(current, 150).is_ok());
        assert!(config.verify(&genesis, 150).is_err());
        // A history that skips the pinned document is refused.
        assert!(pin.follow(std::slice::from_ref(&second)).is_err());
    }

    #[test]
    fn a_pseudonym_signed_request_round_trips_and_binds_every_field() {
        let pseudonym = SigningKey::from_bytes(&[4; 32]);
        let request = GroupRequestV1::sign_with_pseudonym(
            &GROUP,
            GroupOperationV1::SubmitChange,
            1_000,
            &NONCE,
            b"change",
            &pseudonym,
        )
        .unwrap();
        let bytes = request.canonical_bytes().unwrap();
        let back = GroupRequestV1::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(
            back.verify_pseudonym().unwrap(),
            pseudonym.verifying_key().to_bytes()
        );

        let mut other_body = back.clone();
        other_body.body = STANDARD.encode(b"other");
        assert!(other_body.verify_pseudonym().is_err());
        let mut other_time = back.clone();
        other_time.timestamp += 1;
        assert!(other_time.verify_pseudonym().is_err());
        let mut other_group = back.clone();
        other_group.group_id = encode_group_id(&[1; 32]);
        assert!(other_group.verify_pseudonym().is_err());
        let mut other_operation = back;
        other_operation.operation = GroupOperationV1::PutAvatar;
        assert!(other_operation.verify_pseudonym().is_err());
    }

    #[test]
    fn requests_fit_their_operation() {
        let pseudonym = SigningKey::from_bytes(&[4; 32]);
        assert!(GroupRequestV1::sign_with_pseudonym(
            &GROUP,
            GroupOperationV1::GetState,
            1,
            &NONCE,
            b"unexpected",
            &pseudonym
        )
        .is_err());
        assert!(GroupRequestV1::sign_with_pseudonym(
            &GROUP,
            GroupOperationV1::SubmitChange,
            1,
            &NONCE,
            b"",
            &pseudonym
        )
        .is_err());
        // Join info is the one link-authorised operation.
        assert!(GroupRequestV1::sign_with_pseudonym(
            &GROUP,
            GroupOperationV1::GetJoinInfo,
            1,
            &NONCE,
            b"",
            &pseudonym
        )
        .is_err());
        assert!(GroupRequestV1::with_link_password(
            &GROUP,
            GroupOperationV1::GetState,
            1,
            &NONCE,
            b"password"
        )
        .is_err());
    }

    #[test]
    fn a_link_request_proves_the_password_only() {
        let request = GroupRequestV1::with_link_password(
            &GROUP,
            GroupOperationV1::GetJoinInfo,
            7,
            &NONCE,
            b"the link password",
        )
        .unwrap();
        assert!(request.verify_link_password(b"the link password").unwrap());
        assert!(!request.verify_link_password(b"another").unwrap());
        let mut replayed_later = request;
        replayed_later.timestamp += 60;
        assert!(!replayed_later
            .verify_link_password(b"the link password")
            .unwrap());
    }

    #[test]
    fn timeliness_is_the_window_either_way() {
        let pseudonym = SigningKey::from_bytes(&[4; 32]);
        let at = |timestamp| {
            GroupRequestV1::sign_with_pseudonym(
                &GROUP,
                GroupOperationV1::GetState,
                timestamp,
                &NONCE,
                b"",
                &pseudonym,
            )
            .unwrap()
        };
        assert!(at(1_000).is_timely(1_000 + MAX_CLOCK_SKEW_SECS));
        assert!(!at(1_000).is_timely(1_000 + MAX_CLOCK_SKEW_SECS + 1));
        assert!(at(1_000).is_timely(1_000 - MAX_CLOCK_SKEW_SECS));
    }

    #[test]
    fn responses_are_canonical_and_only_refusals_carry_a_code() {
        let ok = GroupResponseV1::new(GroupResponseStatusV1::Ok, 5, b"state");
        let back = GroupResponseV1::from_canonical_bytes(&ok.canonical_bytes().unwrap()).unwrap();
        assert_eq!(back.body().unwrap(), b"state");
        let refused = GroupResponseV1::refused("notAdministrator", 5);
        assert!(refused.canonical_bytes().is_ok());
        let mut coded_ok = ok;
        coded_ok.code = Some("x".into());
        assert!(coded_ok.canonical_bytes().is_err());
    }

    #[test]
    fn the_notary_signs_the_group_revision_and_both_hashes() {
        let (genesis, key) = identity(1);
        let notary = GroupNotaryV1::sign(&genesis, &key, &GROUP, 7, &[1; 32], &[2; 32]).unwrap();
        assert!(notary
            .verify(&genesis, &GROUP, 7, &[1; 32], &[2; 32])
            .is_ok());
        assert!(notary
            .verify(&genesis, &GROUP, 8, &[1; 32], &[2; 32])
            .is_err());
        assert!(notary
            .verify(&genesis, &GROUP, 7, &[3; 32], &[2; 32])
            .is_err());
        assert!(notary
            .verify(&genesis, &GROUP, 7, &[1; 32], &[3; 32])
            .is_err());
        assert!(notary
            .verify(&genesis, &[0; 32], 7, &[1; 32], &[2; 32])
            .is_err());
        let (other, other_key) = identity(2);
        assert!(GroupNotaryV1::sign(&genesis, &other_key, &GROUP, 7, &[1; 32], &[2; 32]).is_err());
        let forged =
            GroupNotaryV1::sign(&other, &other_key, &GROUP, 7, &[1; 32], &[2; 32]).unwrap();
        assert!(forged
            .verify(&genesis, &GROUP, 7, &[1; 32], &[2; 32])
            .is_err());
    }
}
