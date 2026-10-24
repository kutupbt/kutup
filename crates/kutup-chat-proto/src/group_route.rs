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
use ed25519_dalek::{Signature, VerifyingKey};
use hmac::{Hmac, Mac};
use kutup_crypto::primitives::SigningKey;
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
/// The home's refusal of a newcomer's claim, join or request whose pseudonym
/// the group has seen before (as a member or a requester): valid in every
/// other way, so the client
/// derives the pseudonym of the next join epoch and tries again. Only the
/// pseudonym's own signer ever gets it.
pub const PSEUDONYM_USED: &str = "pseudonymUsed";

const GROUP_ID_LEN: usize = 32;
const NONCE_LEN: usize = 16;
const KEY_LEN: usize = 32;
/// A gateway's X-Wing encapsulation key.
const GATEWAY_KEY_LEN: usize = kutup_crypto::oblivious::PUBLIC_KEY_LEN;
const SIGNATURE_LEN: usize = 64;
const HASH_LEN: usize = 32;
/// The largest operation body a request carries: a change is capped at this
/// (`group::MAX_CHANGE_BYTES`). Base64 makes 46 KiB about 62.8 KiB, which
/// with the envelope's other fields keeps every request within the 64 KiB
/// padded size. Answers (a whole state) may take the 256 KiB size.
pub const MAX_REQUEST_BODY: usize = 46 * 1024;

/// The lengths a group's sealed avatar blob may have
/// (docs/plans/pairwise-groups.md, "Avatar"): a version byte, a 24-byte
/// nonce, the image padded to 8, 16, 32 or 40 KiB, and a 16-byte tag. The
/// home refuses any other length.
pub const GROUP_AVATAR_BLOB_LENGTHS: [usize; 4] = [8_233, 16_425, 32_809, 41_001];
/// The largest avatar blob.
pub const MAX_GROUP_AVATAR_BLOB: usize = 41_001;
/// An avatar blob as `PutAvatar` carries it and `GetAvatar` answers it: its
/// length (u32, big-endian), the blob, and zeros to this one size, so the
/// sealed request and answer don't show the relay which size it is.
pub const GROUP_AVATAR_BODY_LEN: usize = 4 + MAX_GROUP_AVATAR_BLOB;
// An upload's padded body fits a request.
const _: () = assert!(GROUP_AVATAR_BODY_LEN <= MAX_REQUEST_BODY);

/// An avatar blob padded for the route ([`GROUP_AVATAR_BODY_LEN`]).
pub fn pad_group_avatar(blob: &[u8]) -> Result<Vec<u8>, String> {
    if !GROUP_AVATAR_BLOB_LENGTHS.contains(&blob.len()) {
        return Err("an avatar blob has one of the avatar lengths".into());
    }
    let mut body = Vec::with_capacity(GROUP_AVATAR_BODY_LEN);
    body.extend_from_slice(&(blob.len() as u32).to_be_bytes());
    body.extend_from_slice(blob);
    body.resize(GROUP_AVATAR_BODY_LEN, 0);
    Ok(body)
}

/// The avatar blob in a padded body: its length one of the avatar lengths,
/// the rest zeros.
pub fn unpad_group_avatar(body: &[u8]) -> Result<Vec<u8>, String> {
    let malformed = || "malformed avatar body".to_string();
    if body.len() != GROUP_AVATAR_BODY_LEN {
        return Err(malformed());
    }
    let (length, rest) = body.split_at(4);
    let length = u32::from_be_bytes(length.try_into().map_err(|_| malformed())?) as usize;
    if !GROUP_AVATAR_BLOB_LENGTHS.contains(&length) {
        return Err(malformed());
    }
    let (blob, fill) = rest.split_at(length);
    if fill.iter().any(|byte| *byte != 0) {
        return Err(malformed());
    }
    Ok(blob.to_vec())
}

const KEY_CONFIG_DOMAIN: &[u8] = b"kutup/chat-group/gateway-key-config/v1\0";
const REQUEST_DOMAIN: &[u8] = b"kutup/chat-group/request/v1\0";
const LINK_PROOF_DOMAIN: &[u8] = b"kutup/chat-group/link-request/v1\0";
const NOTARY_DOMAIN: &[u8] = b"kutup/chat-group/notary/v1\0";
const BODY_HASH_DOMAIN: &[u8] = b"kutup/chat-group/request-body/v1\0";
const KEY_CONFIG_HASH_DOMAIN: &[u8] = b"kutup/chat-group/gateway-key-config-hash/v1\0";

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

/// The document of `sequence` in a history already followed from the pin
/// ([`GroupHomePinV1::follow`]), and its successor there, if any.
fn signer_in(
    history: &[FederationIdentityDocumentV1],
    sequence: u64,
) -> Result<
    (
        &FederationIdentityDocumentV1,
        Option<&FederationIdentityDocumentV1>,
    ),
    String,
> {
    let index = history
        .iter()
        .position(|document| document.sequence == sequence)
        .ok_or_else(|| "signed by an identity document the history lacks".to_string())?;
    Ok((&history[index], history.get(index + 1)))
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
        public_key: &[u8; GATEWAY_KEY_LEN],
        issued_at: i64,
        expires_at: i64,
    ) -> Result<Self, String> {
        if document.key.public_key_bytes().map_err(|e| e.to_string())?
            != signing_key.verifying_key().to_array::<32>()
        {
            return Err("signing key is not the identity document's key".into());
        }
        let mut config = Self {
            version: GROUP_ROUTE_VERSION,
            server: document.server.clone(),
            key_id,
            kem_id: kutup_crypto::oblivious::KEM_XWING,
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
        config.signature = STANDARD.encode(signature);
        Ok(config)
    }

    fn validate_shape(&self) -> Result<(), String> {
        require_version(self.version)?;
        if self.kem_id != kutup_crypto::oblivious::KEM_XWING
            || self.kdf_id != kutup_crypto::oblivious::KDF_HKDF_SHA256
            || self.aead_id != kutup_crypto::oblivious::AEAD_CHACHA20_POLY1305
        {
            return Err("gateway key config names an unsupported suite".into());
        }
        match self.expires_at.checked_sub(self.issued_at) {
            Some(lifetime) if lifetime > 0 && lifetime <= MAX_KEY_CONFIG_LIFETIME_SECS => {}
            _ => return Err("gateway key config lifetime is invalid".into()),
        }
        decode_fixed::<GATEWAY_KEY_LEN>("publicKey", &self.public_key)?;
        Ok(())
    }

    /// What the home's notary names, so members can compare the config each
    /// of them was given ([`GroupNotaryV1::names`]).
    pub fn hash(&self) -> Result<[u8; HASH_LEN], String> {
        self.validate_shape()?;
        Ok(Sha256::new()
            .chain_update(KEY_CONFIG_HASH_DOMAIN)
            .chain_update(canonical(self)?)
            .finalize()
            .into())
    }

    /// The config's key, after checking it is signed by a document of
    /// `history` (followed from the group's pin, [`GroupHomePinV1::follow`])
    /// and current. A config signed by a document that has a successor in
    /// `history` is a retired key's: accepted only until the overlap after the
    /// successor was issued. A relay that truncates the history can hide a
    /// rotation from this check; [`GroupNotaryV1::names`] and
    /// [`Self::accept_after`] catch that.
    pub fn verify(
        &self,
        history: &[FederationIdentityDocumentV1],
        now: i64,
    ) -> Result<(u8, [u8; GATEWAY_KEY_LEN]), String> {
        self.validate_shape()?;
        let (identity, successor) = signer_in(history, self.identity_sequence)?;
        if self.server != identity.server {
            return Err("gateway key config is not signed by this identity".into());
        }
        let not_before = self.issued_at.saturating_sub(MAX_CLOCK_SKEW_SECS);
        if now >= self.expires_at || now < not_before {
            return Err("gateway key config is not current".into());
        }
        if let Some(successor) = successor {
            let retired_after = successor.issued_at.saturating_add(KEY_OVERLAP_SECS);
            if now >= retired_after || self.issued_at >= successor.issued_at {
                return Err("gateway key config is signed by a retired identity key".into());
            }
        }
        let key = identity.key.verifying_key().map_err(|e| e.to_string())?;
        let signature = decode_fixed::<SIGNATURE_LEN>("signature", &self.signature)?;
        key.verify(&self.signing_input()?, &signature)
            .map_err(|_| "gateway key config signature is invalid".to_string())?;
        Ok((
            self.key_id,
            decode_fixed::<GATEWAY_KEY_LEN>("publicKey", &self.public_key)?,
        ))
    }

    /// The newest config wins: a client keeps the newest config it has seen
    /// per home and takes a config only if it isn't older. Two different
    /// configs of the same identity and time are an equivocation, and a newer
    /// config may not reuse the key id of one still live.
    pub fn accept_after(&self, seen: Option<&Self>, now: i64) -> Result<(), String> {
        let Some(seen) = seen else {
            return Ok(());
        };
        if self.server != seen.server {
            return Err("gateway key configs of different homes".into());
        }
        let order =
            (self.identity_sequence, self.issued_at).cmp(&(seen.identity_sequence, seen.issued_at));
        match order {
            std::cmp::Ordering::Less => {
                Err("gateway key config is older than one already seen".into())
            }
            std::cmp::Ordering::Equal if self != seen => {
                Err("the home signed two different gateway key configs for one time".into())
            }
            std::cmp::Ordering::Equal => Ok(()),
            std::cmp::Ordering::Greater => {
                if self.key_id == seen.key_id && now < seen.expires_at {
                    return Err("gateway key config reuses the id of a live key".into());
                }
                Ok(())
            }
        }
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
    /// What a newcomer needs before joining: no body. With a link's
    /// password, a [`GroupJoinInfoV1`] with everything a link shows; signed
    /// by a pending slot's claim key, only the revision and head to claim at.
    GetJoinInfo,
    /// A call token for the group's SFU: no body.
    CallToken,
    /// The group's current avatar blob: no body, signed by a member or with
    /// the link's password; the answer is the blob as
    /// [`pad_group_avatar`] pads it.
    GetAvatar,
    /// A new avatar blob, padded by [`pad_group_avatar`]: it waits as the
    /// group's one pending upload until a change names its hash.
    PutAvatar,
    /// Where the signer's own request to join stands: no body, signed by
    /// the requesting pseudonym; the answer is a [`GroupRequestStatusV1`].
    GetRequestStatus,
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
            Self::GetRequestStatus => 9,
        }
    }

    /// Whether a link's password may authorise it (otherwise only a
    /// signature: a member's pseudonym, or a slot's claim key for join info):
    /// join info, and the avatar a link shows.
    pub fn allows_link_password(self) -> bool {
        matches!(self, Self::GetJoinInfo | Self::GetAvatar)
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
    /// The home server it is sealed to; another home refuses it.
    pub home: String,
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
        if !kutup_crypto::account_ref::valid_server(&self.home) {
            return Err("home is not a valid server name".into());
        }
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
        match &self.auth {
            GroupRequestAuthV1::Pseudonym {
                pseudonym,
                signature,
            } => {
                verifying_key("pseudonym", pseudonym)?;
                decode_fixed::<SIGNATURE_LEN>("signature", signature)?;
            }
            GroupRequestAuthV1::LinkPassword { proof } => {
                if !self.operation.allows_link_password() {
                    return Err("request authorisation does not fit its operation".into());
                }
                decode_fixed::<HASH_LEN>("proof", proof)?;
            }
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
        let home = self.home.as_bytes();
        hasher.update(
            u16::try_from(home.len())
                .map_err(|_| "home is too long")?
                .to_be_bytes(),
        );
        hasher.update(home);
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
        home: &str,
        group_id: &[u8; GROUP_ID_LEN],
        operation: GroupOperationV1,
        timestamp: i64,
        nonce: &[u8; NONCE_LEN],
        body: &[u8],
        pseudonym: &SigningKey,
    ) -> Result<Self, String> {
        let public = pseudonym.verifying_key().to_array::<32>();
        let mut request = Self {
            version: GROUP_ROUTE_VERSION,
            home: home.to_owned(),
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
            signature: STANDARD.encode(signature),
        };
        request.validate_shape()?;
        Ok(request)
    }

    /// A link-authorised request, proving the link's password.
    pub fn with_link_password(
        home: &str,
        group_id: &[u8; GROUP_ID_LEN],
        operation: GroupOperationV1,
        timestamp: i64,
        nonce: &[u8; NONCE_LEN],
        link_password: &[u8],
    ) -> Result<Self, String> {
        let mut request = Self {
            version: GROUP_ROUTE_VERSION,
            home: home.to_owned(),
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
        self.timestamp.abs_diff(now) <= MAX_CLOCK_SKEW_SECS.unsigned_abs()
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
/// the change's hash, the resulting state's hash, and the hash of the gateway
/// key config the home was serving, by its federation identity. Clients
/// apply only changes that carry one. Naming the key config lets members
/// compare, through the signed chain, the config each was given: a relay that
/// hands a client an older or another config is seen there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupNotaryV1 {
    pub identity_sequence: u64,
    pub key_config_hash: String,
    pub signature: String,
}

fn notary_input(
    group_id: &[u8; GROUP_ID_LEN],
    revision: u64,
    change_hash: &[u8; HASH_LEN],
    state_hash: &[u8; HASH_LEN],
    key_config_hash: &[u8; HASH_LEN],
) -> Vec<u8> {
    let mut input = NOTARY_DOMAIN.to_vec();
    input.extend_from_slice(group_id);
    input.extend_from_slice(&revision.to_be_bytes());
    input.extend_from_slice(change_hash);
    input.extend_from_slice(state_hash);
    input.extend_from_slice(key_config_hash);
    input
}

impl GroupNotaryV1 {
    /// Signs with `document`'s key, naming `config`, which the same document
    /// must have signed.
    pub fn sign(
        document: &FederationIdentityDocumentV1,
        signing_key: &SigningKey,
        config: &GroupGatewayKeyConfigV1,
        group_id: &[u8; GROUP_ID_LEN],
        revision: u64,
        change_hash: &[u8; HASH_LEN],
        state_hash: &[u8; HASH_LEN],
    ) -> Result<Self, String> {
        if document.key.public_key_bytes().map_err(|e| e.to_string())?
            != signing_key.verifying_key().to_array::<32>()
        {
            return Err("signing key is not the identity document's key".into());
        }
        if config.identity_sequence != document.sequence || config.server != document.server {
            return Err("the key config is not this identity document's".into());
        }
        let key_config_hash = config.hash()?;
        let signature = signing_key.sign(&notary_input(
            group_id,
            revision,
            change_hash,
            state_hash,
            &key_config_hash,
        ));
        Ok(Self {
            identity_sequence: document.sequence,
            key_config_hash: STANDARD.encode(key_config_hash),
            signature: STANDARD.encode(signature),
        })
    }

    /// Checks the signature by the document of `identity_sequence` in
    /// `history` (followed from the group's pin). Identity sequences only
    /// move forward along a group's chain: `previous_sequence` is the
    /// previous revision's notary's, and a notary by an older document than
    /// that is refused. A notary by a document the history lacks means the
    /// history was cut short: refetch it, never skip the check.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        history: &[FederationIdentityDocumentV1],
        previous_sequence: Option<u64>,
        group_id: &[u8; GROUP_ID_LEN],
        revision: u64,
        change_hash: &[u8; HASH_LEN],
        state_hash: &[u8; HASH_LEN],
    ) -> Result<(), String> {
        if previous_sequence.is_some_and(|previous| self.identity_sequence < previous) {
            return Err("notary is by an identity older than the previous revision's".into());
        }
        let (identity, _) = signer_in(history, self.identity_sequence)?;
        let key = identity.key.verifying_key().map_err(|e| e.to_string())?;
        let key_config_hash = decode_fixed::<HASH_LEN>("keyConfigHash", &self.key_config_hash)?;
        let signature = decode_fixed::<SIGNATURE_LEN>("signature", &self.signature)?;
        key.verify(
            &notary_input(
                group_id,
                revision,
                change_hash,
                state_hash,
                &key_config_hash,
            ),
            &signature,
        )
        .map_err(|_| "notary signature is invalid".to_string())
    }

    /// Whether this (verified) notary names `config`: the config the home was
    /// serving when it accepted the change. A client whose config isn't the
    /// one the newest notary names refetches; if what it gets still isn't, a
    /// relay is showing it another config, and the client stops using it.
    pub fn names(&self, config: &GroupGatewayKeyConfigV1) -> Result<bool, String> {
        Ok(decode_fixed::<HASH_LEN>("keyConfigHash", &self.key_config_hash)? == config.hash()?)
    }
}

// --- answers ---------------------------------------------------------------------------

/// A state as the home serves it: the state's canonical bytes with the change
/// that produced it and that change's notary, so a client verifies the state
/// in one step (the notary binds the change's hash and the state's hash).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupStateAnswerV1 {
    pub state: String,
    pub change: String,
    pub notary: GroupNotaryV1,
}

/// One change of a log page with its notary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupLogEntryV1 {
    pub change: String,
    pub notary: GroupNotaryV1,
}

/// Changes in revision order from the asked revision; `more` when the page
/// stopped before the head (it is cut to fit the largest padded size).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupLogPageV1 {
    pub entries: Vec<GroupLogEntryV1>,
    pub more: bool,
}

macro_rules! canonical_answer {
    ($type:ty, $name:literal) => {
        impl $type {
            pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
                canonical(self)
            }

            pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
                from_canonical(bytes, kutup_crypto::oblivious::MAX_BODY, $name)
            }
        }
    };
}

/// What a newcomer learns before joining (Signal's `GroupJoinInfo`, plus
/// the revision and head a newcomer's change names). With a link's password
/// it carries the sealed title, description and avatar reference (as the
/// state holds them) and whether joining needs approval; to a slot's claim
/// key only the revision, head and member count. Never a member entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupJoinInfoV1 {
    pub revision: u64,
    pub head: String,
    pub member_count: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_approval: Option<bool>,
}

/// Where a request to join stands, as its own pseudonym asks
/// ([`GroupOperationV1::GetRequestStatus`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GroupRequestStateV1 {
    /// Still requesting: the answer carries the revision and head a cancel
    /// names.
    Pending,
    /// Banned, or no longer requesting nor a member (denied, or once in and
    /// now out).
    Denied,
    /// A member now (approved).
    Member,
    /// A pseudonym the group never saw (or no such group): never `NotFound`,
    /// so a requester whose change was lost can tell.
    Unknown,
}

/// The answer to [`GroupOperationV1::GetRequestStatus`]: `revision` and
/// `head` only when pending.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupRequestStatusV1 {
    pub status: GroupRequestStateV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
}

impl GroupRequestStatusV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        canonical(self)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        let value: Self = from_canonical(
            bytes,
            kutup_crypto::oblivious::MAX_BODY,
            "group request status",
        )?;
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), String> {
        let pending = self.status == GroupRequestStateV1::Pending;
        if pending != (self.revision.is_some() && self.head.is_some())
            || pending != (self.revision.is_some() || self.head.is_some())
        {
            return Err("a request status names its revision and head only when pending".into());
        }
        if let Some(head) = &self.head {
            decode_fixed::<HASH_LEN>("head", head)?;
        }
        Ok(())
    }
}

canonical_answer!(GroupJoinInfoV1, "group join info");
canonical_answer!(GroupStateAnswerV1, "group state answer");
canonical_answer!(GroupLogPageV1, "group log page");

#[cfg(test)]
mod tests {
    use super::*;
    use kutup_crypto::primitives::Suite;

    const HOME: &str = "home.example";
    const GROUP: [u8; 32] = [5; 32];
    const NONCE: [u8; 16] = [6; 16];

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_seed(Suite::V1, &[byte; 32])
    }

    fn genesis() -> FederationIdentityDocumentV1 {
        FederationIdentityDocumentV1::genesis(HOME, 10, &key(1)).unwrap()
    }

    /// genesis (key 1, issued 10) → rotated (key 2, issued 1_000_000).
    fn rotated() -> FederationIdentityDocumentV1 {
        FederationIdentityDocumentV1::rotate(&genesis(), 1_000_000, &key(1), &key(2)).unwrap()
    }

    fn config(
        document: &FederationIdentityDocumentV1,
        signer: u8,
        key_id: u8,
        issued_at: i64,
    ) -> GroupGatewayKeyConfigV1 {
        GroupGatewayKeyConfigV1::sign(
            document,
            &key(signer),
            key_id,
            &[key_id; GATEWAY_KEY_LEN],
            issued_at,
            issued_at + MAX_KEY_CONFIG_LIFETIME_SECS,
        )
        .unwrap()
    }

    #[test]
    fn a_key_config_verifies_only_from_the_pinned_history() {
        let pin = GroupHomePinV1::of(&genesis()).unwrap();
        let history = [genesis()];
        pin.follow(&history).unwrap();
        let config = config(&genesis(), 1, 3, 100);
        assert_eq!(
            config.verify(&history, 150).unwrap(),
            (3, [3; GATEWAY_KEY_LEN])
        );
        assert!(config
            .verify(&history, 100 + MAX_KEY_CONFIG_LIFETIME_SECS)
            .is_err());

        // A relay's own identity can't stand in for the pinned one.
        let other = FederationIdentityDocumentV1::genesis(HOME, 10, &key(9)).unwrap();
        assert!(pin.follow(std::slice::from_ref(&other)).is_err());
        let forged =
            GroupGatewayKeyConfigV1::sign(&other, &key(9), 3, &[8; GATEWAY_KEY_LEN], 100, 200)
                .unwrap();
        assert!(forged.verify(&history, 150).is_err());

        let mut swapped = config.clone();
        swapped.public_key = STANDARD.encode([8u8; GATEWAY_KEY_LEN]);
        assert!(swapped.verify(&history, 150).is_err());
    }

    #[test]
    fn hostile_integers_are_refused_not_wrapped() {
        let mut config = config(&genesis(), 1, 3, 100);
        config.issued_at = i64::MIN;
        config.expires_at = i64::MAX;
        assert!(config.verify(&[genesis()], 150).is_err());
        let request = GroupRequestV1::sign_with_pseudonym(
            HOME,
            &GROUP,
            GroupOperationV1::GetState,
            i64::MIN + 1_000,
            &NONCE,
            b"",
            &key(4),
        )
        .unwrap();
        assert!(!request.is_timely(1_000));
        assert!(!request.is_timely(i64::MAX));
    }

    #[test]
    fn a_retired_identitys_config_lasts_only_through_the_overlap() {
        let history = [genesis(), rotated()];
        let old = config(&genesis(), 1, 3, 900_000);
        assert!(old
            .verify(&history, 1_000_000 + KEY_OVERLAP_SECS - 1)
            .is_ok());
        assert!(old.verify(&history, 1_000_000 + KEY_OVERLAP_SECS).is_err());
        // Signed by the old key after the rotation: never.
        let late = config(&genesis(), 1, 4, 1_000_001);
        assert!(late.verify(&history, 1_000_002).is_err());
        let new = config(&rotated(), 2, 5, 1_000_001);
        assert!(new.verify(&history, 1_000_002).is_ok());
        // The history must reach the signer.
        assert!(new.verify(&[genesis()], 1_000_002).is_err());
    }

    #[test]
    fn the_newest_config_wins() {
        let first = config(&genesis(), 1, 3, 100);
        let second = config(&genesis(), 1, 4, 200);
        assert!(second.accept_after(Some(&first), 250).is_ok());
        assert!(first.accept_after(Some(&second), 250).is_err(), "older");
        assert!(first.accept_after(Some(&first), 250).is_ok());
        let equivocation = config(&genesis(), 1, 9, 100);
        assert!(equivocation.accept_after(Some(&first), 250).is_err());
        // A newer config may not reuse a live key's id.
        let reused = config(&genesis(), 1, 3, 200);
        assert!(reused.accept_after(Some(&first), 250).is_err());
        assert!(reused
            .accept_after(Some(&first), 100 + MAX_KEY_CONFIG_LIFETIME_SECS)
            .is_ok());
    }

    fn notary(
        document: &FederationIdentityDocumentV1,
        signer: u8,
        config: &GroupGatewayKeyConfigV1,
        revision: u64,
    ) -> GroupNotaryV1 {
        GroupNotaryV1::sign(
            document,
            &key(signer),
            config,
            &GROUP,
            revision,
            &[1; 32],
            &[2; 32],
        )
        .unwrap()
    }

    #[test]
    fn the_notary_signs_the_group_revision_both_hashes_and_the_config() {
        let config = config(&genesis(), 1, 3, 100);
        let signed = notary(&genesis(), 1, &config, 7);
        let history = [genesis()];
        let check = |n: &GroupNotaryV1, revision, change: [u8; 32], state: [u8; 32]| {
            n.verify(&history, None, &GROUP, revision, &change, &state)
        };
        assert!(check(&signed, 7, [1; 32], [2; 32]).is_ok());
        assert!(check(&signed, 8, [1; 32], [2; 32]).is_err());
        assert!(check(&signed, 7, [3; 32], [2; 32]).is_err());
        assert!(check(&signed, 7, [1; 32], [3; 32]).is_err());
        let mut renamed = signed.clone();
        renamed.key_config_hash = STANDARD.encode([0u8; 32]);
        assert!(check(&renamed, 7, [1; 32], [2; 32]).is_err());
        assert!(signed.names(&config).unwrap());
        // Another document's key can't notarise, nor name another's config.
        assert!(
            GroupNotaryV1::sign(&genesis(), &key(2), &config, &GROUP, 7, &[1; 32], &[2; 32])
                .is_err()
        );
        assert!(
            GroupNotaryV1::sign(&rotated(), &key(2), &config, &GROUP, 7, &[1; 32], &[2; 32])
                .is_err()
        );
    }

    #[test]
    fn notaries_move_forward_through_identities() {
        let history = [genesis(), rotated()];
        let old = notary(&genesis(), 1, &config(&genesis(), 1, 3, 100), 7);
        let new = notary(&rotated(), 2, &config(&rotated(), 2, 4, 1_000_001), 8);
        assert!(new
            .verify(&history, Some(1), &GROUP, 8, &[1; 32], &[2; 32])
            .is_ok());
        // Once a group's chain reached the new identity, the old one is done.
        assert!(old
            .verify(&history, Some(2), &GROUP, 7, &[1; 32], &[2; 32])
            .is_err());
    }

    #[test]
    fn a_truncated_history_or_another_clients_config_is_detected() {
        // The home rotated its identity and serves config B; a relay keeps a
        // client on the pre-rotation history and config A.
        let full = [genesis(), rotated()];
        let truncated = [genesis()];
        let a = config(&genesis(), 1, 3, 900_000);
        let b = config(&rotated(), 2, 4, 1_000_001);
        let latest = notary(&rotated(), 2, &b, 9);
        // A alone looks fine from the truncated history...
        assert!(a.verify(&truncated, 1_000_002).is_ok());
        // ...but the newest notary is by a document that history lacks, so
        // the client must refetch it rather than trust A,
        assert!(latest
            .verify(&truncated, Some(1), &GROUP, 9, &[1; 32], &[2; 32])
            .is_err());
        // and with the full history, the notary names B, not A.
        latest
            .verify(&full, Some(1), &GROUP, 9, &[1; 32], &[2; 32])
            .unwrap();
        assert!(!latest.names(&a).unwrap());
        assert!(latest.names(&b).unwrap());

        // Two clients given different configs of one identity: the notary
        // shows which one the home serves.
        let c = config(&rotated(), 2, 5, 1_000_500);
        assert!(c.verify(&full, 1_000_600).is_ok());
        assert!(!latest.names(&c).unwrap());
    }

    #[test]
    fn a_pseudonym_signed_request_round_trips_and_binds_every_field() {
        let pseudonym = key(4);
        let request = GroupRequestV1::sign_with_pseudonym(
            HOME,
            &GROUP,
            GroupOperationV1::SubmitChange,
            1_000,
            &NONCE,
            b"change",
            &pseudonym,
        )
        .unwrap();
        let back =
            GroupRequestV1::from_canonical_bytes(&request.canonical_bytes().unwrap()).unwrap();
        assert_eq!(
            back.verify_pseudonym().unwrap(),
            pseudonym.verifying_key().to_array::<32>()
        );
        let tampered: Vec<GroupRequestV1> = vec![
            GroupRequestV1 {
                body: STANDARD.encode(b"other"),
                ..back.clone()
            },
            GroupRequestV1 {
                timestamp: 1_001,
                ..back.clone()
            },
            GroupRequestV1 {
                group_id: encode_group_id(&[1; 32]),
                ..back.clone()
            },
            GroupRequestV1 {
                operation: GroupOperationV1::PutAvatar,
                ..back.clone()
            },
            GroupRequestV1 {
                home: "other.example".into(),
                ..back.clone()
            },
            GroupRequestV1 {
                nonce: STANDARD.encode([7u8; 16]),
                ..back.clone()
            },
        ];
        for request in tampered {
            assert!(request.verify_pseudonym().is_err(), "{request:?}");
        }
    }

    #[test]
    fn requests_fit_their_operation() {
        let pseudonym = key(4);
        let sign = |operation, body: &[u8]| {
            GroupRequestV1::sign_with_pseudonym(
                HOME, &GROUP, operation, 1, &NONCE, body, &pseudonym,
            )
        };
        assert!(sign(GroupOperationV1::GetState, b"unexpected").is_err());
        assert!(sign(GroupOperationV1::SubmitChange, b"").is_err());
        // Join info also takes a signature (a slot's claim key).
        assert!(sign(GroupOperationV1::GetJoinInfo, b"").is_ok());
        assert!(sign(
            GroupOperationV1::SubmitChange,
            &vec![0; MAX_REQUEST_BODY + 1]
        )
        .is_err());
        assert!(GroupRequestV1::with_link_password(
            HOME,
            &GROUP,
            GroupOperationV1::GetState,
            1,
            &NONCE,
            b"password"
        )
        .is_err());
    }

    #[test]
    fn the_largest_request_fits_the_64_kib_padded_size() {
        let request = GroupRequestV1::sign_with_pseudonym(
            "a-rather-long-home-server-name.example.org",
            &GROUP,
            GroupOperationV1::SubmitChange,
            i64::MAX,
            &NONCE,
            &vec![0xff; MAX_REQUEST_BODY],
            &key(4),
        )
        .unwrap();
        let bytes = request.canonical_bytes().unwrap();
        assert!(
            bytes.len() < kutup_crypto::oblivious::SIZES[3],
            "{}",
            bytes.len()
        );
    }

    #[test]
    fn a_link_request_proves_the_password_only() {
        let request = GroupRequestV1::with_link_password(
            HOME,
            &GROUP,
            GroupOperationV1::GetJoinInfo,
            7,
            &NONCE,
            b"the link password",
        )
        .unwrap();
        assert!(request.verify_link_password(b"the link password").unwrap());
        assert!(!request.verify_link_password(b"another").unwrap());
        let later = GroupRequestV1 {
            timestamp: 67,
            ..request
        };
        assert!(!later.verify_link_password(b"the link password").unwrap());
    }

    #[test]
    fn timeliness_is_the_window_either_way() {
        let at = |timestamp| {
            GroupRequestV1::sign_with_pseudonym(
                HOME,
                &GROUP,
                GroupOperationV1::GetState,
                timestamp,
                &NONCE,
                b"",
                &key(4),
            )
            .unwrap()
        };
        assert!(at(1_000).is_timely(1_000 + MAX_CLOCK_SKEW_SECS));
        assert!(!at(1_000).is_timely(1_000 + MAX_CLOCK_SKEW_SECS + 1));
        assert!(at(1_000).is_timely(1_000 - MAX_CLOCK_SKEW_SECS));
        assert!(!at(1_000).is_timely(1_000 - MAX_CLOCK_SKEW_SECS - 1));
    }

    #[test]
    fn responses_and_answers_are_canonical() {
        let ok = GroupResponseV1::new(GroupResponseStatusV1::Ok, 5, b"state");
        let back = GroupResponseV1::from_canonical_bytes(&ok.canonical_bytes().unwrap()).unwrap();
        assert_eq!(back.body().unwrap(), b"state");
        assert!(GroupResponseV1::refused("notAllowed", 5)
            .canonical_bytes()
            .is_ok());
        assert!(GroupResponseV1 {
            code: Some("x".into()),
            ..ok
        }
        .canonical_bytes()
        .is_err());

        let config = config(&genesis(), 1, 3, 100);
        let page = GroupLogPageV1 {
            entries: vec![GroupLogEntryV1 {
                change: STANDARD.encode(b"change"),
                notary: notary(&genesis(), 1, &config, 1),
            }],
            more: false,
        };
        let bytes = page.canonical_bytes().unwrap();
        assert_eq!(GroupLogPageV1::from_canonical_bytes(&bytes).unwrap(), page);
    }

    /// X-Wing only: a config naming the X25519-only KEM, or a key of its
    /// size, is refused, never used as a fallback.
    #[test]
    fn a_key_config_for_any_kem_but_x_wing_is_refused() {
        let mut classical = config(&genesis(), 1, 3, 100);
        classical.kem_id = 0x0020;
        assert!(classical.verify(&[genesis()], 150).is_err());
        assert!(classical.hash().is_err());
        let mut short = config(&genesis(), 1, 3, 100);
        short.public_key = STANDARD.encode([3u8; 32]);
        assert!(short.verify(&[genesis()], 150).is_err());
    }

    /// Fixed signing inputs and signatures: a change to any domain, field
    /// order or encoding fails here first (Ed25519 is deterministic).
    #[test]
    fn golden_signing_inputs() {
        let config = config(&genesis(), 1, 3, 100);
        let config_input = hex::encode(config.signing_input().unwrap());
        assert_eq!(
            config_input,
            include_str!("../tests/vectors/group-route-v1/key-config-input.hex").trim()
        );
        assert_eq!(
            config.signature,
            include_str!("../tests/vectors/group-route-v1/key-config-signature.b64").trim()
        );
        let request = GroupRequestV1::sign_with_pseudonym(
            HOME,
            &GROUP,
            GroupOperationV1::SubmitChange,
            1_700_000_000,
            &NONCE,
            b"change",
            &key(4),
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(request.canonical_bytes().unwrap()).unwrap(),
            include_str!("../tests/vectors/group-route-v1/request.json").trim()
        );
        assert_eq!(
            hex::encode(
                request
                    .pseudonym_input(&key(4).verifying_key().to_array::<32>())
                    .unwrap()
            ),
            include_str!("../tests/vectors/group-route-v1/request-input.hex").trim()
        );
        let notary = notary(&genesis(), 1, &config, 7);
        assert_eq!(
            String::from_utf8(canonical(&notary).unwrap()).unwrap(),
            include_str!("../tests/vectors/group-route-v1/notary.json").trim()
        );
    }

    #[test]
    fn join_info_for_a_claim_carries_no_sealed_fields() {
        let for_claim = GroupJoinInfoV1 {
            revision: 4,
            head: STANDARD.encode([9u8; 32]),
            member_count: 3,
            title: None,
            description: None,
            avatar: None,
            requires_approval: None,
        };
        let bytes = for_claim.canonical_bytes().unwrap();
        assert_eq!(
            String::from_utf8(bytes.clone()).unwrap(),
            r#"{"revision":4,"head":"CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=","memberCount":3}"#
        );
        assert_eq!(
            GroupJoinInfoV1::from_canonical_bytes(&bytes).unwrap(),
            for_claim
        );
    }

    #[test]
    fn a_request_status_names_revision_and_head_only_when_pending() {
        let pending = GroupRequestStatusV1 {
            status: GroupRequestStateV1::Pending,
            revision: Some(4),
            head: Some(STANDARD.encode([9u8; 32])),
        };
        let bytes = pending.canonical_bytes().unwrap();
        assert_eq!(
            String::from_utf8(bytes.clone()).unwrap(),
            r#"{"status":"pending","revision":4,"head":"CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk="}"#
        );
        assert_eq!(
            GroupRequestStatusV1::from_canonical_bytes(&bytes).unwrap(),
            pending
        );
        for status in [
            GroupRequestStateV1::Denied,
            GroupRequestStateV1::Member,
            GroupRequestStateV1::Unknown,
        ] {
            let bare = GroupRequestStatusV1 {
                status,
                revision: None,
                head: None,
            };
            let bytes = bare.canonical_bytes().unwrap();
            assert_eq!(
                GroupRequestStatusV1::from_canonical_bytes(&bytes).unwrap(),
                bare
            );
            let with_revision = GroupRequestStatusV1 {
                revision: Some(4),
                ..bare.clone()
            };
            assert!(with_revision.canonical_bytes().is_err());
        }
        assert_eq!(
            String::from_utf8(
                GroupRequestStatusV1 {
                    status: GroupRequestStateV1::Unknown,
                    revision: None,
                    head: None,
                }
                .canonical_bytes()
                .unwrap()
            )
            .unwrap(),
            r#"{"status":"unknown"}"#
        );
        let half = GroupRequestStatusV1 {
            head: None,
            ..pending.clone()
        };
        assert!(half.canonical_bytes().is_err());
        assert!(
            GroupRequestStatusV1::from_canonical_bytes(br#"{"status":"denied","revision":4}"#)
                .is_err()
        );
        let short = GroupRequestStatusV1 {
            head: Some(STANDARD.encode([9u8; 31])),
            ..pending
        };
        assert!(short.canonical_bytes().is_err());
    }

    #[test]
    fn a_request_status_request_has_no_body_and_a_pseudonym_signature() {
        let request = GroupRequestV1::sign_with_pseudonym(
            HOME,
            &GROUP,
            GroupOperationV1::GetRequestStatus,
            1_700_000_000,
            &NONCE,
            b"",
            &key(4),
        )
        .unwrap();
        let bytes = request.canonical_bytes().unwrap();
        assert!(String::from_utf8(bytes.clone())
            .unwrap()
            .contains(r#""operation":"getRequestStatus""#));
        let parsed = GroupRequestV1::from_canonical_bytes(&bytes).unwrap();
        assert!(parsed.verify_pseudonym().is_ok());
        assert!(GroupRequestV1::sign_with_pseudonym(
            HOME,
            &GROUP,
            GroupOperationV1::GetRequestStatus,
            1_700_000_000,
            &NONCE,
            b"body",
            &key(4),
        )
        .is_err());
    }

    #[test]
    fn an_avatar_body_is_one_size_whatever_the_blob() {
        for length in GROUP_AVATAR_BLOB_LENGTHS {
            let blob = vec![0xa5; length];
            let body = pad_group_avatar(&blob).unwrap();
            assert_eq!(body.len(), GROUP_AVATAR_BODY_LEN);
            assert_eq!(unpad_group_avatar(&body).unwrap(), blob);
        }
        assert!(pad_group_avatar(&[1; 8_232]).is_err());
        assert!(pad_group_avatar(&[1; 41_002]).is_err());
        let mut body = pad_group_avatar(&[7; 8_233]).unwrap();
        body[GROUP_AVATAR_BODY_LEN - 1] = 1;
        assert!(unpad_group_avatar(&body).is_err(), "fill must be zeros");
        let mut body = pad_group_avatar(&[7; 8_233]).unwrap();
        body[..4].copy_from_slice(&8_234u32.to_be_bytes());
        assert!(
            unpad_group_avatar(&body).is_err(),
            "length must be an avatar length"
        );
        assert!(unpad_group_avatar(&body[..GROUP_AVATAR_BODY_LEN - 1]).is_err());
    }

    #[test]
    fn an_avatar_may_be_read_with_the_links_password() {
        let read = GroupRequestV1::with_link_password(
            HOME,
            &GROUP,
            GroupOperationV1::GetAvatar,
            1_700_000_000,
            &NONCE,
            b"password",
        )
        .unwrap();
        assert!(read.verify_link_password(b"password").unwrap());
        assert!(GroupRequestV1::with_link_password(
            HOME,
            &GROUP,
            GroupOperationV1::PutAvatar,
            1_700_000_000,
            &NONCE,
            b"password",
        )
        .is_err());
    }
}
