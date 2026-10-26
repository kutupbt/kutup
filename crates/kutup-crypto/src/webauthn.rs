//! Security keys as a second factor (docs/plans/security-keys.md): the
//! relying party's checks, W3C Web Authentication Level 3. The one module
//! that calls `webauthn_rp` (decision D1); the server stores what it hands
//! back as opaque bytes and passes them back in.
//!
//! - **Registration:** non-discoverable credentials (not passkeys),
//!   attestation `none`, ES256, EdDSA, ES384 and RS256, user verification
//!   `discouraged` unless the account asks for it.
//! - **Authentication:** the account's own credentials only; the origin, the
//!   RP id hash, user presence (and verification when asked for), the
//!   signature, and the counter.
//! - **Counter:** a key whose counter does not move on (both non-zero) is
//!   refused and reported as cloned: [`AuthenticationRefusal::CounterWentBack`]
//!   (the server marks it compromised). Keys that always report 0 pass.
//! - **Ceremony state** (the challenge and the options it went out with) is
//!   encoded for the server's database, not kept in memory, so any instance
//!   can finish a ceremony another started.

use webauthn_rp::bin::{Decode, Encode};
use webauthn_rp::request::auth::{
    AllowedCredentials, AuthenticationVerificationOptions, NonDiscoverableCredentialRequestOptions,
    SignatureCounterEnforcement,
};
use webauthn_rp::request::register::{
    PublicKeyCredentialCreationOptions, PublicKeyCredentialUserEntity,
    RegistrationVerificationOptions, UserHandle,
};
use webauthn_rp::request::{
    AsciiDomain, Credentials as _, PublicKeyCredentialDescriptor, RpId, UserVerificationRequirement,
};
use webauthn_rp::response::auth::error::AuthCeremonyErr;
use webauthn_rp::response::auth::ser_relaxed::NonDiscoverableAuthenticationRelaxed16;
use webauthn_rp::response::register::ser_relaxed::RegistrationRelaxed;
use webauthn_rp::response::register::{CompressedPubKey, DynamicState, StaticState};
use webauthn_rp::response::{AuthTransports, CredentialId};
use webauthn_rp::{
    AuthenticatedCredential, NonDiscoverableAuthentication16,
    NonDiscoverableAuthenticationServerState, Registration, RegistrationServerState,
};

use crate::error::{CryptoError, Result};

/// The user handle's length: the account's permanent id.
const USER_LEN: usize = 16;

/// A stored key's public key and what came with it, decoded.
type StoredStaticState = StaticState<CompressedPubKey<[u8; 32], [u8; 32], [u8; 48], Vec<u8>>>;

/// Where keys work: the registrable domain (`kutup.dev`, so one key serves
/// every app's host) and the app origins that may ask.
pub struct RelyingParty {
    rp_id: RpId,
    origins: Vec<String>,
}

impl RelyingParty {
    /// `rp_id` must be a lowercase domain name, and each origin an
    /// `https://` origin on it or a subdomain (WebAuthn's rule), or
    /// `http://localhost` with a port for a development stack.
    pub fn new(rp_id: &str, origins: Vec<String>) -> Result<Self> {
        let label_ok = |label: &str| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        };
        if rp_id.len() > 253 || !rp_id.split('.').all(label_ok) {
            return Err(CryptoError::InvalidInput(
                "WebAuthn RP id is not a lowercase domain name".into(),
            ));
        }
        let domain = AsciiDomain::try_from(rp_id.to_owned())
            .map_err(|_| CryptoError::InvalidInput("WebAuthn RP id is not a domain".into()))?;
        if origins.is_empty() {
            return Err(CryptoError::InvalidInput(
                "WebAuthn needs the origins that may use it".into(),
            ));
        }
        for origin in &origins {
            let host = origin
                .strip_prefix("https://")
                .or_else(|| {
                    (rp_id == "localhost")
                        .then(|| origin.strip_prefix("http://"))
                        .flatten()
                })
                .map(|rest| rest.split(':').next().unwrap_or(rest))
                .filter(|_| !origin.ends_with('/'));
            let on_rp = host.is_some_and(|host| {
                host == rp_id
                    || host
                        .strip_suffix(rp_id)
                        .is_some_and(|sub| sub.ends_with('.'))
            });
            if !on_rp {
                return Err(CryptoError::InvalidInput(format!(
                    "WebAuthn origin {origin} is not on {rp_id}"
                )));
            }
        }
        Ok(Self {
            rp_id: RpId::Domain(domain),
            origins,
        })
    }

    pub fn rp_id(&self) -> &str {
        self.rp_id.as_ref()
    }
}

/// A stored key as the options name it: its credential id and transports
/// (as encoded by [`NewKey::transports`]).
pub struct KeyRef<'a> {
    pub credential_id: &'a [u8],
    pub transports: &'a [u8],
}

/// What a ceremony start gives: the options for the browser
/// (`PublicKeyCredential{Creation,Request}Options` as JSON) and the state to
/// keep server side until the ceremony finishes.
pub struct Started {
    pub options_json: String,
    pub state: Vec<u8>,
    /// The challenge, for the state's row: a finish names it.
    pub challenge: Vec<u8>,
}

/// A key just registered: everything later sign-ins need, encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewKey {
    pub credential_id: Vec<u8>,
    pub transports: Vec<u8>,
    /// The public key and what came with it (`StaticState`).
    pub static_state: Vec<u8>,
    /// The counter and flags that change at each use (`DynamicState`).
    pub dynamic_state: Vec<u8>,
    pub sign_count: u32,
    /// The authenticator's model id; shown nowhere, kept so a known-bad
    /// model can be flagged later.
    pub aaguid: [u8; 16],
}

fn user_handle(account: [u8; USER_LEN]) -> UserHandle<USER_LEN> {
    UserHandle::decode(account).expect("decoding a user handle can't fail")
}

fn descriptors(keys: &[KeyRef<'_>]) -> Result<Vec<PublicKeyCredentialDescriptor<Vec<u8>>>> {
    keys.iter()
        .map(|key| {
            Ok(PublicKeyCredentialDescriptor {
                id: CredentialId::decode(key.credential_id.to_vec())
                    .map_err(|_| CryptoError::InvalidInput("stored credential id".into()))?,
                transports: AuthTransports::decode(*key.transports.first().unwrap_or(&0))
                    .map_err(|_| CryptoError::InvalidInput("stored transports".into()))?,
            })
        })
        .collect()
}

fn verification(require_uv: bool) -> UserVerificationRequirement {
    if require_uv {
        UserVerificationRequirement::Required
    } else {
        UserVerificationRequirement::Discouraged
    }
}

fn json_error(error: impl std::fmt::Display) -> CryptoError {
    CryptoError::InvalidInput(format!("WebAuthn response: {error}"))
}

/// Starts adding a key for `account` (shown to the authenticator as
/// `user_name`), none of `exclude` again.
pub fn start_registration(
    rp: &RelyingParty,
    account: [u8; USER_LEN],
    user_name: &str,
    exclude: &[KeyRef<'_>],
    require_uv: bool,
    timeout_ms: u32,
) -> Result<Started> {
    let handle = user_handle(account);
    let user = PublicKeyCredentialUserEntity {
        name: user_name
            .try_into()
            .map_err(|_| CryptoError::InvalidInput("WebAuthn user name".into()))?,
        id: &handle,
        display_name: None,
    };
    let mut options =
        PublicKeyCredentialCreationOptions::second_factor(&rp.rp_id, user, descriptors(exclude)?);
    options.authenticator_selection.user_verification = verification(require_uv);
    options.timeout = std::num::NonZeroU32::new(timeout_ms)
        .ok_or_else(|| CryptoError::InvalidInput("WebAuthn timeout".into()))?;
    let (server, client) = options
        .start_ceremony()
        .map_err(|error| CryptoError::InvalidInput(format!("WebAuthn options: {error}")))?;
    let challenge = challenge_bytes(&server)?;
    Ok(Started {
        options_json: serde_json::to_string(&client).map_err(json_error)?,
        state: server
            .encode()
            .map_err(|error| CryptoError::InvalidInput(format!("WebAuthn state: {error}")))?,
        challenge,
    })
}

fn challenge_bytes<C: webauthn_rp::request::TimedCeremony>(ceremony: &C) -> Result<Vec<u8>> {
    ceremony
        .sent_challenge()
        .encode()
        .map(|challenge| challenge.to_le_bytes().to_vec())
        .map_err(|_| CryptoError::InvalidInput("WebAuthn challenge".into()))
}

/// The challenge a browser's registration response answers, to find its
/// ceremony.
pub fn registration_challenge(response_json: &[u8]) -> Result<Vec<u8>> {
    let registration: Registration = serde_json::from_slice::<RegistrationRelaxed>(response_json)
        .map_err(json_error)?
        .0;
    registration
        .challenge_relaxed()
        .map_err(json_error)?
        .encode()
        .map(|challenge| challenge.to_le_bytes().to_vec())
        .map_err(|_| CryptoError::InvalidInput("WebAuthn challenge".into()))
}

/// Finishes adding a key: the browser's response checked against the
/// ceremony's `state`.
pub fn finish_registration(
    rp: &RelyingParty,
    state: &[u8],
    response_json: &[u8],
) -> Result<NewKey> {
    let server = RegistrationServerState::<USER_LEN>::decode(state)
        .map_err(|_| CryptoError::InvalidInput("WebAuthn registration state".into()))?;
    let registration: Registration = serde_json::from_slice::<RegistrationRelaxed>(response_json)
        .map_err(json_error)?
        .0;
    let options = RegistrationVerificationOptions::<String, String> {
        allowed_origins: &rp.origins,
        ..Default::default()
    };
    let credential = server
        .verify(&rp.rp_id, &registration, &options)
        .map_err(|error| CryptoError::InvalidInput(format!("WebAuthn registration: {error}")))?;
    let encode_error = |what: &str| CryptoError::InvalidInput(format!("encode {what}"));
    let dynamic = credential.dynamic_state();
    Ok(NewKey {
        credential_id: credential.id().as_ref().to_vec(),
        transports: vec![credential
            .transports()
            .encode()
            .map_err(|_| encode_error("transports"))?],
        static_state: credential
            .static_state()
            .encode()
            .map_err(|_| encode_error("key"))?,
        dynamic_state: dynamic
            .encode()
            .map_err(|_| encode_error("state"))?
            .to_vec(),
        sign_count: dynamic.sign_count,
        aaguid: credential
            .metadata()
            .aaguid
            .data()
            .try_into()
            .map_err(|_| encode_error("AAGUID"))?,
    })
}

/// Starts a sign-in's second step with one of `keys`.
pub fn start_authentication(
    rp: &RelyingParty,
    keys: &[KeyRef<'_>],
    require_uv: bool,
    timeout_ms: u32,
) -> Result<Started> {
    let mut allowed = AllowedCredentials::with_capacity(keys.len());
    for descriptor in descriptors(keys)? {
        allowed.push(descriptor.into());
    }
    let mut options = NonDiscoverableCredentialRequestOptions::second_factor(&rp.rp_id, allowed)
        .map_err(|_| CryptoError::InvalidInput("no security keys".into()))?;
    options.options().user_verification = verification(require_uv);
    options.options().timeout = std::num::NonZeroU32::new(timeout_ms)
        .ok_or_else(|| CryptoError::InvalidInput("WebAuthn timeout".into()))?;
    let (server, client) = options
        .start_ceremony()
        .map_err(|error| CryptoError::InvalidInput(format!("WebAuthn options: {error}")))?;
    let challenge = challenge_bytes(&server)?;
    Ok(Started {
        options_json: serde_json::to_string(&client).map_err(json_error)?,
        state: server
            .encode()
            .map_err(|error| CryptoError::InvalidInput(format!("WebAuthn state: {error}")))?,
        challenge,
    })
}

/// A browser's sign-in response, parsed: which key answered and which
/// challenge.
pub struct AssertionResponse {
    authentication: NonDiscoverableAuthentication16,
}

impl AssertionResponse {
    pub fn parse(response_json: &[u8]) -> Result<Self> {
        Ok(Self {
            authentication: serde_json::from_slice::<NonDiscoverableAuthenticationRelaxed16>(
                response_json,
            )
            .map_err(json_error)?
            .0,
        })
    }

    pub fn credential_id(&self) -> Vec<u8> {
        self.authentication.raw_id().as_ref().to_vec()
    }

    pub fn challenge(&self) -> Result<Vec<u8>> {
        self.authentication
            .challenge_relaxed()
            .map_err(json_error)?
            .encode()
            .map(|challenge| challenge.to_le_bytes().to_vec())
            .map_err(|_| CryptoError::InvalidInput("WebAuthn challenge".into()))
    }
}

/// A stored key, as [`NewKey`] encoded it, for checking a sign-in.
pub struct StoredKey<'a> {
    pub credential_id: &'a [u8],
    pub account: [u8; USER_LEN],
    pub static_state: &'a [u8],
    pub dynamic_state: &'a [u8],
}

/// Why a sign-in's key was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthenticationRefusal {
    /// The counter did not move on: the key may have been cloned. The
    /// server marks it compromised.
    CounterWentBack,
    /// Anything else: another origin or RP, no user presence (or
    /// verification when required), a bad signature, another challenge.
    Invalid(String),
}

/// A sign-in's key checked: its new dynamic state to store.
#[derive(Debug)]
pub struct Asserted {
    pub dynamic_state: Vec<u8>,
    pub sign_count: u32,
}

/// Finishes a sign-in's second step: `response` checked against the
/// ceremony's `state` and the key that answered.
pub fn finish_authentication(
    rp: &RelyingParty,
    state: &[u8],
    response: &AssertionResponse,
    key: StoredKey<'_>,
) -> std::result::Result<Asserted, AuthenticationRefusal> {
    let invalid = |what: &str| AuthenticationRefusal::Invalid(what.to_owned());
    let server = NonDiscoverableAuthenticationServerState::decode(state)
        .map_err(|_| invalid("authentication state"))?;
    let handle = user_handle(key.account);
    let static_state =
        StoredStaticState::decode(key.static_state).map_err(|_| invalid("stored key"))?;
    let dynamic = DynamicState::decode(
        key.dynamic_state
            .try_into()
            .map_err(|_| invalid("stored key state"))?,
    )
    .map_err(|_| invalid("stored key state"))?;
    let id = CredentialId::decode(key.credential_id).map_err(|_| invalid("stored key id"))?;
    let mut credential = AuthenticatedCredential::new(id, &handle, static_state, dynamic)
        .map_err(|_| invalid("stored key"))?;
    let options = AuthenticationVerificationOptions::<String, String> {
        allowed_origins: &rp.origins,
        update_uv: true,
        sig_counter_enforcement: SignatureCounterEnforcement::Fail,
        ..Default::default()
    };
    match server.verify(
        &rp.rp_id,
        &response.authentication,
        &mut credential,
        &options,
    ) {
        Ok(_) => {
            let dynamic = credential.dynamic_state();
            Ok(Asserted {
                dynamic_state: dynamic.encode().map_err(|_| invalid("key state"))?.to_vec(),
                sign_count: dynamic.sign_count,
            })
        }
        Err(AuthCeremonyErr::SignatureCounter) => Err(AuthenticationRefusal::CounterWentBack),
        Err(error) => Err(AuthenticationRefusal::Invalid(error.to_string())),
    }
}

/// Which ceremony a [`Started`] belongs to.
#[cfg(any(test, feature = "test-vectors"))]
#[derive(Clone, Copy)]
pub enum Ceremony {
    Registration,
    Authentication,
}

/// Gives a fresh ceremony the challenge of a recorded one, so a recorded
/// browser's or security key's answer can be checked again (the state's
/// expiry is the fresh one's). For vectors only: the challenge sits after
/// one mediation byte in a registration's state and first in an
/// authentication's (`webauthn_rp` 0.3's encoding, pinned).
#[cfg(any(test, feature = "test-vectors"))]
pub fn with_recorded_challenge(started: &mut Started, ceremony: Ceremony, challenge: [u8; 16]) {
    let at = match ceremony {
        Ceremony::Registration => 1,
        Ceremony::Authentication => 0,
    };
    assert_eq!(
        started.state[at..at + 16],
        started.challenge[..],
        "state layout"
    );
    started.state[at..at + 16].copy_from_slice(&challenge);
    started.challenge = challenge.to_vec();
}

/// A software authenticator for tests (and the server's live tests): an
/// Ed25519 key, attestation `none`, answering the options this module
/// makes the way a browser would hand its answer on.
#[cfg(any(test, feature = "test-vectors"))]
pub mod soft {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use serde_json::{json, Value};

    use crate::primitives::{hash, SigningKey, Suite};

    /// User present, user verified, attested credential data included.
    const UP: u8 = 0x01;
    const UV: u8 = 0x04;
    const AT: u8 = 0x40;

    pub struct Authenticator {
        key: SigningKey,
        pub credential_id: Vec<u8>,
        pub counter: u32,
        /// Whether it verifies the user (a PIN or a fingerprint).
        pub verifies_user: bool,
    }

    fn cbor_head(major: u8, value: u64, out: &mut Vec<u8>) {
        let major = major << 5;
        match value {
            0..=23 => out.push(major | value as u8),
            24..=0xff => out.extend_from_slice(&[major | 24, value as u8]),
            0x100..=0xffff => {
                out.push(major | 25);
                out.extend_from_slice(&(value as u16).to_be_bytes());
            }
            _ => {
                out.push(major | 26);
                out.extend_from_slice(&(value as u32).to_be_bytes());
            }
        }
    }

    fn cbor_int(value: i64, out: &mut Vec<u8>) {
        if value >= 0 {
            cbor_head(0, value as u64, out);
        } else {
            cbor_head(1, (-1 - value) as u64, out);
        }
    }

    fn cbor_bytes(value: &[u8], out: &mut Vec<u8>) {
        cbor_head(2, value.len() as u64, out);
        out.extend_from_slice(value);
    }

    fn cbor_text(value: &str, out: &mut Vec<u8>) {
        cbor_head(3, value.len() as u64, out);
        out.extend_from_slice(value.as_bytes());
    }

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// The challenge of options this module made (`options_json`).
    pub fn challenge_of(options_json: &str) -> String {
        let options: Value = serde_json::from_str(options_json).expect("options are JSON");
        let options = options.get("publicKey").unwrap_or(&options);
        options["challenge"]
            .as_str()
            .expect("options carry a challenge")
            .to_owned()
    }

    impl Authenticator {
        pub fn new(seed: [u8; 32], credential_id: Vec<u8>) -> Self {
            Self {
                key: SigningKey::from_seed(Suite::V1, &seed),
                credential_id,
                counter: 0,
                verifies_user: false,
            }
        }

        fn client_data(kind: &str, challenge: &str, origin: &str) -> Vec<u8> {
            serde_json::to_vec(&json!({
                "type": kind,
                "challenge": challenge,
                "origin": origin,
                "crossOrigin": false,
            }))
            .expect("client data is JSON")
        }

        fn flags(&self, extra: u8) -> u8 {
            UP | extra | if self.verifies_user { UV } else { 0 }
        }

        /// The browser's answer to `create()` with these options.
        pub fn register(&self, options_json: &str, rp_id: &str, origin: &str) -> Vec<u8> {
            let client_data =
                Self::client_data("webauthn.create", &challenge_of(options_json), origin);
            let mut auth_data = hash(Suite::V1, rp_id.as_bytes()).as_bytes().to_vec();
            auth_data.push(self.flags(AT));
            auth_data.extend_from_slice(&self.counter.to_be_bytes());
            auth_data.extend_from_slice(&[0; 16]);
            auth_data.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
            auth_data.extend_from_slice(&self.credential_id);
            // COSE_Key: OKP, EdDSA, Ed25519, the public key.
            cbor_head(5, 4, &mut auth_data);
            cbor_int(1, &mut auth_data);
            cbor_int(1, &mut auth_data);
            cbor_int(3, &mut auth_data);
            cbor_int(-8, &mut auth_data);
            cbor_int(-1, &mut auth_data);
            cbor_int(6, &mut auth_data);
            cbor_int(-2, &mut auth_data);
            cbor_bytes(&self.key.verifying_key().to_bytes(), &mut auth_data);
            let mut attestation = Vec::new();
            cbor_head(5, 3, &mut attestation);
            cbor_text("fmt", &mut attestation);
            cbor_text("none", &mut attestation);
            cbor_text("attStmt", &mut attestation);
            cbor_head(5, 0, &mut attestation);
            cbor_text("authData", &mut attestation);
            cbor_bytes(&auth_data, &mut attestation);
            serde_json::to_vec(&json!({
                "id": b64(&self.credential_id),
                "rawId": b64(&self.credential_id),
                "type": "public-key",
                "response": {
                    "clientDataJSON": b64(&client_data),
                    "attestationObject": b64(&attestation),
                    "transports": ["usb"],
                },
                "clientExtensionResults": {},
                "authenticatorAttachment": "cross-platform",
            }))
            .expect("registration is JSON")
        }

        /// The browser's answer to `get()` with these options; the counter
        /// moves on first.
        pub fn assert(&mut self, options_json: &str, rp_id: &str, origin: &str) -> Vec<u8> {
            self.counter += 1;
            self.assert_at(options_json, rp_id, origin)
        }

        /// [`Self::assert`] without moving the counter (a cloned key).
        pub fn assert_at(&self, options_json: &str, rp_id: &str, origin: &str) -> Vec<u8> {
            let client_data =
                Self::client_data("webauthn.get", &challenge_of(options_json), origin);
            let mut auth_data = hash(Suite::V1, rp_id.as_bytes()).as_bytes().to_vec();
            auth_data.push(self.flags(0));
            auth_data.extend_from_slice(&self.counter.to_be_bytes());
            let mut signed = auth_data.clone();
            signed.extend_from_slice(hash(Suite::V1, &client_data).as_bytes());
            let signature: [u8; 64] = self.key.sign_array(&signed);
            serde_json::to_vec(&json!({
                "id": b64(&self.credential_id),
                "rawId": b64(&self.credential_id),
                "type": "public-key",
                "response": {
                    "clientDataJSON": b64(&client_data),
                    "authenticatorData": b64(&auth_data),
                    "signature": b64(&signature),
                },
                "clientExtensionResults": {},
                "authenticatorAttachment": "cross-platform",
            }))
            .expect("assertion is JSON")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::soft::Authenticator;
    use super::*;

    const RP: &str = "kutup.test";
    const ORIGIN: &str = "https://account.kutup.test";
    const ACCOUNT: [u8; 16] = [7; 16];

    fn rp() -> RelyingParty {
        RelyingParty::new(RP, vec![ORIGIN.to_owned()]).unwrap()
    }

    fn registered(authenticator: &Authenticator, require_uv: bool) -> NewKey {
        let started = start_registration(&rp(), ACCOUNT, "ada", &[], require_uv, 60_000).unwrap();
        let response = authenticator.register(&started.options_json, RP, ORIGIN);
        assert_eq!(
            registration_challenge(&response).unwrap(),
            started.challenge
        );
        finish_registration(&rp(), &started.state, &response).unwrap()
    }

    fn sign_in(
        authenticator: &mut Authenticator,
        key: &NewKey,
        require_uv: bool,
        origin: &str,
        move_counter: bool,
    ) -> std::result::Result<Asserted, AuthenticationRefusal> {
        let started = start_authentication(
            &rp(),
            &[KeyRef {
                credential_id: &key.credential_id,
                transports: &key.transports,
            }],
            require_uv,
            60_000,
        )
        .unwrap();
        let response = if move_counter {
            authenticator.assert(&started.options_json, RP, origin)
        } else {
            authenticator.assert_at(&started.options_json, RP, origin)
        };
        let response = AssertionResponse::parse(&response).unwrap();
        assert_eq!(response.challenge().unwrap(), started.challenge);
        assert_eq!(response.credential_id(), key.credential_id);
        finish_authentication(
            &rp(),
            &started.state,
            &response,
            StoredKey {
                credential_id: &key.credential_id,
                account: ACCOUNT,
                static_state: &key.static_state,
                dynamic_state: &key.dynamic_state,
            },
        )
    }

    #[test]
    fn a_key_registers_and_signs_in_and_its_counter_moves_on() {
        let mut authenticator = Authenticator::new([1; 32], vec![9; 32]);
        let mut key = registered(&authenticator, false);
        assert_eq!(key.credential_id, vec![9; 32]);
        assert_eq!(key.sign_count, 0);
        for expected in 1..=3 {
            let asserted = sign_in(&mut authenticator, &key, false, ORIGIN, true).unwrap();
            assert_eq!(asserted.sign_count, expected);
            key.dynamic_state = asserted.dynamic_state;
        }
        // The same counter again: a cloned key.
        assert_eq!(
            sign_in(&mut authenticator, &key, false, ORIGIN, false).unwrap_err(),
            AuthenticationRefusal::CounterWentBack
        );
    }

    #[test]
    fn another_origin_is_refused() {
        let authenticator = Authenticator::new([1; 32], vec![9; 32]);
        let started = start_registration(&rp(), ACCOUNT, "ada", &[], false, 60_000).unwrap();
        let response = authenticator.register(&started.options_json, RP, "https://evil.test");
        assert!(finish_registration(&rp(), &started.state, &response).is_err());
        let mut authenticator = Authenticator::new([1; 32], vec![9; 32]);
        let key = registered(&authenticator, false);
        assert!(matches!(
            sign_in(&mut authenticator, &key, false, "https://evil.test", true),
            Err(AuthenticationRefusal::Invalid(_))
        ));
        // Another RP id signed over.
        let started = start_registration(&rp(), ACCOUNT, "ada", &[], false, 60_000).unwrap();
        let response = authenticator.register(&started.options_json, "evil.test", ORIGIN);
        assert!(finish_registration(&rp(), &started.state, &response).is_err());
    }

    #[test]
    fn user_verification_is_required_only_when_asked() {
        let mut authenticator = Authenticator::new([1; 32], vec![9; 32]);
        let started = start_registration(&rp(), ACCOUNT, "ada", &[], true, 60_000).unwrap();
        let response = authenticator.register(&started.options_json, RP, ORIGIN);
        assert!(finish_registration(&rp(), &started.state, &response).is_err());
        let key = registered(&authenticator, false);
        assert!(sign_in(&mut authenticator, &key, true, ORIGIN, true).is_err());
        authenticator.verifies_user = true;
        assert!(sign_in(&mut authenticator, &key, true, ORIGIN, true).is_ok());
    }

    #[test]
    fn another_key_or_ceremony_is_refused() {
        let mut authenticator = Authenticator::new([1; 32], vec![9; 32]);
        let key = registered(&authenticator, false);
        let other = Authenticator::new([2; 32], vec![9; 32]);
        let other_key = registered(&other, false);
        // The answer of one key checked against another's public key.
        assert!(sign_in(&mut authenticator, &other_key, false, ORIGIN, true).is_err());
        // An answer to another ceremony's challenge.
        let keys = [KeyRef {
            credential_id: &key.credential_id,
            transports: &key.transports,
        }];
        let first = start_authentication(&rp(), &keys, false, 60_000).unwrap();
        let second = start_authentication(&rp(), &keys, false, 60_000).unwrap();
        assert_ne!(first.challenge, second.challenge);
        let response = authenticator.assert(&first.options_json, RP, ORIGIN);
        let response = AssertionResponse::parse(&response).unwrap();
        assert!(finish_authentication(
            &rp(),
            &second.state,
            &response,
            StoredKey {
                credential_id: &key.credential_id,
                account: ACCOUNT,
                static_state: &key.static_state,
                dynamic_state: &key.dynamic_state,
            },
        )
        .is_err());
    }

    #[test]
    fn the_options_challenge_is_the_states() {
        let started = start_registration(&rp(), ACCOUNT, "ada", &[], false, 60_000).unwrap();
        let shown = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            super::soft::challenge_of(&started.options_json),
        )
        .unwrap();
        assert_eq!(shown, started.challenge);
        // A recorded challenge put into a fresh ceremony is the one checked.
        let authenticator = Authenticator::new([1; 32], vec![9; 32]);
        let recorded = start_registration(&rp(), ACCOUNT, "ada", &[], false, 60_000).unwrap();
        let response = authenticator.register(&recorded.options_json, RP, ORIGIN);
        let mut fresh = start_registration(&rp(), ACCOUNT, "ada", &[], false, 60_000).unwrap();
        assert!(finish_registration(&rp(), &fresh.state, &response).is_err());
        with_recorded_challenge(
            &mut fresh,
            Ceremony::Registration,
            recorded.challenge.clone().try_into().unwrap(),
        );
        let key = finish_registration(&rp(), &fresh.state, &response).unwrap();
        let keys = [KeyRef {
            credential_id: &key.credential_id,
            transports: &key.transports,
        }];
        let recorded = start_authentication(&rp(), &keys, false, 60_000).unwrap();
        let mut authenticator = authenticator;
        let response = authenticator.assert(&recorded.options_json, RP, ORIGIN);
        let mut fresh = start_authentication(&rp(), &keys, false, 60_000).unwrap();
        with_recorded_challenge(
            &mut fresh,
            Ceremony::Authentication,
            recorded.challenge.try_into().unwrap(),
        );
        let stored = StoredKey {
            credential_id: &key.credential_id,
            account: ACCOUNT,
            static_state: &key.static_state,
            dynamic_state: &key.dynamic_state,
        };
        assert!(finish_authentication(
            &rp(),
            &fresh.state,
            &AssertionResponse::parse(&response).unwrap(),
            stored,
        )
        .is_ok());
    }

    #[test]
    fn options_name_the_accounts_keys() {
        let authenticator = Authenticator::new([1; 32], vec![9; 32]);
        let key = registered(&authenticator, false);
        let keys = [KeyRef {
            credential_id: &key.credential_id,
            transports: &key.transports,
        }];
        let id = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &key.credential_id,
        );
        let creation = start_registration(&rp(), ACCOUNT, "ada", &keys, false, 60_000).unwrap();
        assert!(creation.options_json.contains(&id), "excluded");
        assert!(creation.options_json.contains("\"discouraged\""));
        let request = start_authentication(&rp(), &keys, false, 60_000).unwrap();
        assert!(request.options_json.contains(&id), "allowed");
        assert!(start_authentication(&rp(), &[], false, 60_000).is_err());
        for (rp_id, origin) in [
            ("not a domain!", ORIGIN),
            ("Kutup.test", ORIGIN),
            (RP, "https://kutup.test.evil"),
            (RP, "https://evilkutup.test"),
            (RP, "http://account.kutup.test"),
            (RP, "https://account.kutup.test/"),
        ] {
            assert!(
                RelyingParty::new(rp_id, vec![origin.to_owned()]).is_err(),
                "{rp_id} {origin}"
            );
        }
        for origin in ["https://kutup.test", "https://mail.kutup.test:8443"] {
            assert!(
                RelyingParty::new(RP, vec![origin.to_owned()]).is_ok(),
                "{origin}"
            );
        }
        assert!(RelyingParty::new("localhost", vec!["http://localhost:39643".to_owned()]).is_ok());
    }
}
