//! OPAQUE sign-in (RFC 9807; docs/plans/opaque.md), suite 1.
//!
//! The password never leaves the client, and the server keeps a record that
//! is useless without an online exchange with it: no offline dictionary attack
//! on a database dump. The client's one output is the export key, from which
//! it derives the key that seals the account master key
//! ([`ExportKey::master_key_kek`]); the server never sees it.
//!
//! Suite 1, fixed for every client and server:
//! - OPRF ristretto255-SHA512, key exchange 3DH over ristretto255 with SHA-512;
//! - KSF Argon2id at the account-protection V1 cost (64 MiB, 3 passes, 1 lane),
//!   with no salt input, as the RFC's KSF has none (the OPRF output is already
//!   unique per account and server);
//! - identities left to their defaults (the two public keys): no name is bound,
//!   so a rename never breaks sign-in;
//! - the context [`CONTEXT`], so no message of another protocol or version is
//!   accepted as one of these.
//!
//! The server is pinned by OPAQUE itself: its public key is part of the
//! credentials the client's envelope authenticates, so a server answering with
//! another key fails the client's finish.
//!
//! The server's setup (OPRF seed and key pairs) is kept sealed under a key that
//! is not in the database ([`seal_server_setup`]).

use crate::primitives::{Aead, Kdf, Suite};
use opaque_ke::errors::{InternalError, ProtocolError};
use opaque_ke::generic_array::{ArrayLength, GenericArray};
use opaque_ke::ksf::Ksf;
use opaque_ke::rand::{CryptoRng, RngCore};
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, RegistrationRequest, RegistrationResponse, RegistrationUpload,
    Ristretto255, ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup, TripleDh,
};
// Adapter: OPAQUE's key exchange hash (RFC 9807 ciphersuite).
#[allow(clippy::disallowed_types)]
use sha2::Sha512;
use zeroize::{Zeroize, Zeroizing};

use crate::account_envelope::{self, AccountEnvelopePurpose};
use crate::error::{CryptoError, Result};

/// The suite number stored with each account's record.
pub const SUITE: u16 = 1;
/// Bound into every sign-in's transcript.
pub const CONTEXT: &[u8] = b"kutup/opaque/v1";
const EXPORT_SALT: &[u8] = b"kutup/opaque/export/v1\0";
const MASTER_KEY_KEK_INFO: &[u8] = b"kutup/opaque/master-key-kek/v1\0";
const CREDENTIAL_PREFIX: &[u8] = b"kutup/opaque/credential/v1\0";
const UNKNOWN_PREFIX: &[u8] = b"unknown:";
const SETUP_AAD: &[u8] = b"kutup/opaque-setup/v1\0";
const SETUP_MAGIC: &[u8; 8] = b"KUTOPS1\0";
const NONCE_LEN: usize = 24;

/// Suite 1's Argon2id passes. Its own constants: a change to the account
/// protection elsewhere must never change suite 1.
const KSF_PASSES: u64 = 3;
/// Suite 1's Argon2id memory: 64 MiB (one lane).
const KSF_MEMORY_BYTES: usize = 64 * 1024 * 1024;

/// Argon2id at 64 MiB, 3 passes, 1 lane: the suite's KSF.
#[derive(Default)]
pub struct Argon2idV1;

impl Ksf for Argon2idV1 {
    fn hash<L: ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> std::result::Result<GenericArray<u8, L>, InternalError> {
        let mut output = GenericArray::default();
        crate::primitives::pwhash(
            &crate::primitives::PwhashParams {
                operations: KSF_PASSES,
                memory: KSF_MEMORY_BYTES,
            },
            input.as_slice(),
            &[0u8; 16],
            output.as_mut_slice(),
        )
        .map_err(|_| InternalError::KsfError)?;
        Ok(output)
    }
}

/// Suite 1.
pub struct Suite1;

// Adapter: OPAQUE's key exchange hash (RFC 9807 ciphersuite).
#[allow(clippy::disallowed_types)]
impl opaque_ke::CipherSuite for Suite1 {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, Sha512>;
    type Ksf = Argon2idV1;
}

fn protocol(error: ProtocolError) -> CryptoError {
    match error {
        // A wrong password, or a server that is not the one registered with.
        ProtocolError::InvalidLoginError => CryptoError::AuthFailed,
        other => CryptoError::InvalidInput(format!("opaque: {other}")),
    }
}

/// Parses an OPAQUE message or state, and refuses it unless it is exactly the
/// canonical encoding (opaque-ke's parsers ignore trailing bytes): every message,
/// record and stored state has one byte string only.
macro_rules! exact {
    ($ty:ty, $bytes:expr) => {{
        let bytes: &[u8] = $bytes;
        let value = <$ty>::deserialize(bytes).map_err(protocol)?;
        if value.serialize().as_slice() != bytes {
            return Err(CryptoError::InvalidInput(
                "opaque: not a canonical message".into(),
            ));
        }
        value
    }};
}

fn client_finish_params(ksf: &Argon2idV1) -> ClientLoginFinishParameters<'_, '_, '_, Suite1> {
    ClientLoginFinishParameters::new(Some(CONTEXT), Default::default(), Some(ksf))
}

fn server_params() -> ServerLoginParameters<'static, 'static> {
    ServerLoginParameters {
        context: Some(CONTEXT),
        identifiers: Default::default(),
    }
}

// --- the export key ----------------------------------------------------------

/// The key a sign-in or registration gives the client, and only the client.
pub struct ExportKey(Zeroizing<Vec<u8>>);

impl ExportKey {
    /// Takes the key out of opaque-ke's result, wiping the original.
    fn take(source: &mut [u8]) -> Self {
        let key = Self(Zeroizing::new(source.to_vec()));
        source.zeroize();
        key
    }

    /// The key that seals the account's master key (the password envelope),
    /// bound to the account's key binding.
    pub fn master_key_kek(&self, key_binding: &str) -> Result<Zeroizing<[u8; 32]>> {
        crate::key_binding::check(key_binding)?;
        let mut info = Vec::with_capacity(MASTER_KEY_KEK_INFO.len() + key_binding.len());
        info.extend_from_slice(MASTER_KEY_KEK_INFO);
        info.extend_from_slice(key_binding.as_bytes());
        let mut kek = Zeroizing::new([0u8; 32]);
        Kdf::new(Suite::V1, EXPORT_SALT, &self.0)
            .expand(&info, kek.as_mut_slice())
            .map_err(|_| CryptoError::Backend("opaque export key HKDF".into()))?;
        Ok(kek)
    }

    /// Seals `master_key` (of `generation`) as the account's password
    /// envelope.
    pub fn seal_master_key(
        &self,
        master_key: &[u8; 32],
        generation: account_envelope::MasterKeyGeneration,
        key_binding: &str,
    ) -> Result<String> {
        account_envelope::seal_b64(
            master_key,
            self.master_key_kek(key_binding)?.as_slice(),
            AccountEnvelopePurpose::PasswordMasterKey,
            generation,
            key_binding,
        )
    }

    /// Opens the account's password envelope.
    pub fn open_master_key(
        &self,
        envelope: &str,
        key_binding: &str,
    ) -> Result<Zeroizing<[u8; 32]>> {
        let opened = Zeroizing::new(account_envelope::open_b64(
            envelope,
            self.master_key_kek(key_binding)?.as_slice(),
            AccountEnvelopePurpose::PasswordMasterKey,
            key_binding,
        )?);
        let key: [u8; 32] =
            opened
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::InvalidLength {
                    expected: 32,
                    got: opened.len(),
                })?;
        Ok(Zeroizing::new(key))
    }

    #[cfg(any(test, feature = "test-vectors"))]
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

// --- client: registration ----------------------------------------------------

/// A registration in progress on the client.
pub struct ClientRegistering {
    state: ClientRegistration<Suite1>,
    password: Zeroizing<Vec<u8>>,
}

/// A finished registration: the record for the server, and the export key.
pub struct Registered {
    /// `RegistrationUpload`, sent to the server as the account's record.
    pub record: Vec<u8>,
    pub export_key: ExportKey,
}

/// Starts registering `password`: the state, and the request for the server.
pub fn client_registration_start(password: &str) -> Result<(ClientRegistering, Vec<u8>)> {
    client_registration_start_with(&mut crate::primitives::Rng, password)
}

pub fn client_registration_start_with<R: RngCore + CryptoRng>(
    rng: &mut R,
    password: &str,
) -> Result<(ClientRegistering, Vec<u8>)> {
    let started =
        ClientRegistration::<Suite1>::start(rng, password.as_bytes()).map_err(protocol)?;
    Ok((
        ClientRegistering {
            state: started.state,
            password: Zeroizing::new(password.as_bytes().to_vec()),
        },
        started.message.serialize().to_vec(),
    ))
}

impl ClientRegistering {
    /// Finishes with the server's response: the record and the export key.
    pub fn finish(self, response: &[u8]) -> Result<Registered> {
        self.finish_with(&mut crate::primitives::Rng, response)
    }

    pub fn finish_with<R: RngCore + CryptoRng>(
        self,
        rng: &mut R,
        response: &[u8],
    ) -> Result<Registered> {
        let response = exact!(RegistrationResponse::<Suite1>, response);
        let ksf = Argon2idV1;
        let mut finished = self
            .state
            .finish(
                rng,
                &self.password,
                response,
                ClientRegistrationFinishParameters::new(Default::default(), Some(&ksf)),
            )
            .map_err(protocol)?;
        Ok(Registered {
            record: finished.message.serialize().to_vec(),
            export_key: ExportKey::take(&mut finished.export_key),
        })
    }
}

// --- client: sign-in ---------------------------------------------------------

/// A sign-in in progress on the client.
pub struct ClientSigningIn {
    state: ClientLogin<Suite1>,
    password: Zeroizing<Vec<u8>>,
}

/// A finished sign-in: the message that completes it, and the export key.
pub struct SignedIn {
    /// `CredentialFinalization`, sent to the server.
    pub finalization: Vec<u8>,
    pub export_key: ExportKey,
}

/// Starts signing in with `password`: the state, and the request for the server.
pub fn client_login_start(password: &str) -> Result<(ClientSigningIn, Vec<u8>)> {
    client_login_start_with(&mut crate::primitives::Rng, password)
}

pub fn client_login_start_with<R: RngCore + CryptoRng>(
    rng: &mut R,
    password: &str,
) -> Result<(ClientSigningIn, Vec<u8>)> {
    let started = ClientLogin::<Suite1>::start(rng, password.as_bytes()).map_err(protocol)?;
    Ok((
        ClientSigningIn {
            state: started.state,
            password: Zeroizing::new(password.as_bytes().to_vec()),
        },
        started.message.serialize().to_vec(),
    ))
}

impl ClientSigningIn {
    /// Finishes with the server's response. [`CryptoError::AuthFailed`] for a
    /// wrong password (or a server other than the one registered with); the
    /// server's answer to an unknown name fails the same way.
    pub fn finish(self, response: &[u8]) -> Result<SignedIn> {
        self.finish_with(&mut crate::primitives::Rng, response)
    }

    pub fn finish_with<R: RngCore + CryptoRng>(
        self,
        rng: &mut R,
        response: &[u8],
    ) -> Result<SignedIn> {
        let response = exact!(CredentialResponse::<Suite1>, response);
        let ksf = Argon2idV1;
        let mut finished = self
            .state
            .finish(rng, &self.password, response, client_finish_params(&ksf))
            .map_err(protocol)?;
        Ok(SignedIn {
            finalization: finished.message.serialize().to_vec(),
            export_key: ExportKey::take(&mut finished.export_key),
        })
    }
}

// --- server ------------------------------------------------------------------

/// What the server derives an account's OPRF key from: its key binding, fixed
/// for the account's life (never its name, which may change).
pub fn credential_identifier(key_binding: &str) -> Result<Vec<u8>> {
    crate::key_binding::check(key_binding)?;
    Ok([CREDENTIAL_PREFIX, key_binding.as_bytes()].concat())
}

/// A sign-in name in its one form: lowercase, trimmed, a username or a
/// `username@server` address. Two spellings of one name are one name, so
/// they get one fake answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalName(String);

impl CanonicalName {
    pub fn parse(name: &str) -> Result<Self> {
        let name = name.trim().to_ascii_lowercase();
        let (user, server) = match name.split_once('@') {
            Some((user, server)) => (user, Some(server)),
            None => (name.as_str(), None),
        };
        let user_ok = (1..=64).contains(&user.len())
            && user.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-' || b == b'.'
            });
        let server_ok = server.is_none_or(|server| {
            (1..=253).contains(&server.len())
                && server.bytes().all(|b| {
                    b.is_ascii_lowercase()
                        || b.is_ascii_digit()
                        || b == b'.'
                        || b == b'-'
                        || b == b':'
                })
        });
        if !user_ok || !server_ok {
            return Err(CryptoError::InvalidInput("not a sign-in name".into()));
        }
        Ok(Self(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The identifier of a name that is no account (or a name held after a
/// rename): its fake answer is the same each time.
pub fn unknown_credential_identifier(name: &CanonicalName) -> Vec<u8> {
    [CREDENTIAL_PREFIX, UNKNOWN_PREFIX, name.as_str().as_bytes()].concat()
}

/// A server's OPAQUE secrets, as stored (sealed).
pub struct ServerSecrets(ServerSetup<Suite1>);

impl ServerSecrets {
    /// New secrets, made once per setup key id.
    pub fn generate() -> Self {
        Self(ServerSetup::<Suite1>::new(&mut crate::primitives::Rng))
    }

    pub fn generate_with<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(ServerSetup::<Suite1>::new(rng))
    }

    /// The server's long-term public key (what clients' envelopes pin).
    pub fn public_key(&self) -> Vec<u8> {
        self.0.keypair().public().serialize().to_vec()
    }
}

/// Seals `secrets` under `key` (from `OPAQUE_SETUP_KEYS`, never in the
/// database) for setup `key_id`: `magic ‖ key id ‖ nonce ‖ ciphertext`.
pub fn seal_server_setup(secrets: &ServerSecrets, key: &[u8; 32], key_id: u16) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    crate::primitives::random(&mut nonce);
    seal_server_setup_with_nonce(secrets, key, key_id, &nonce)
}

/// [`seal_server_setup`] with a fixed nonce, for checked-in vectors only.
#[cfg(any(test, feature = "test-vectors"))]
pub fn seal_server_setup_for_vectors(
    secrets: &ServerSecrets,
    key: &[u8; 32],
    key_id: u16,
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    seal_server_setup_with_nonce(secrets, key, key_id, nonce)
}

fn seal_server_setup_with_nonce(
    secrets: &ServerSecrets,
    key: &[u8; 32],
    key_id: u16,
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    let mut serialized = secrets.0.serialize();
    let plain = Zeroizing::new(serialized.to_vec());
    serialized.as_mut_slice().zeroize();
    let aad = [SETUP_AAD, &key_id.to_be_bytes()].concat();
    let ciphertext = Aead::new(Suite::V1, key.as_ref())?
        .seal_with_nonce(nonce, &aad, &plain)
        .map_err(|_| CryptoError::Backend("opaque setup seal".into()))?;
    Ok([
        SETUP_MAGIC.as_slice(),
        &key_id.to_be_bytes(),
        nonce,
        &ciphertext,
    ]
    .concat())
}

/// Opens a sealed setup for `key_id`.
pub fn open_server_setup(sealed: &[u8], key: &[u8; 32], key_id: u16) -> Result<ServerSecrets> {
    let header = SETUP_MAGIC.len() + 2 + NONCE_LEN;
    if sealed.len() <= header || &sealed[..SETUP_MAGIC.len()] != SETUP_MAGIC {
        return Err(CryptoError::InvalidInput(
            "not a sealed OPAQUE setup".into(),
        ));
    }
    if sealed[SETUP_MAGIC.len()..SETUP_MAGIC.len() + 2] != key_id.to_be_bytes() {
        return Err(CryptoError::InvalidInput(
            "sealed for another setup key".into(),
        ));
    }
    let aad = [SETUP_AAD, &key_id.to_be_bytes()].concat();
    let plain = Zeroizing::new(
        Aead::new(Suite::V1, key.as_ref())?
            .open_with_nonce(
                &sealed[SETUP_MAGIC.len() + 2..header],
                &aad,
                &sealed[header..],
            )
            .map_err(|_| CryptoError::AuthFailed)?,
    );
    let setup = ServerSetup::<Suite1>::deserialize(&plain)
        .map_err(|_| CryptoError::InvalidInput("the sealed OPAQUE setup is malformed".into()))?;
    let mut again = setup.serialize();
    let canonical = again.as_slice() == plain.as_slice();
    again.as_mut_slice().zeroize();
    if !canonical {
        return Err(CryptoError::InvalidInput(
            "the sealed OPAQUE setup is malformed".into(),
        ));
    }
    Ok(ServerSecrets(setup))
}

/// The server's answer to a registration request for `key_binding`. Stateless:
/// derived from the secrets and the key binding only.
pub fn server_registration_response(
    secrets: &ServerSecrets,
    request: &[u8],
    key_binding: &str,
) -> Result<Vec<u8>> {
    let request = exact!(RegistrationRequest::<Suite1>, request);
    let started = ServerRegistration::<Suite1>::start(
        &secrets.0,
        request,
        &credential_identifier(key_binding)?,
    )
    .map_err(protocol)?;
    Ok(started.message.serialize().to_vec())
}

/// Checks a record a client uploaded, and returns it as stored.
pub fn server_registration_record(upload: &[u8]) -> Result<Vec<u8>> {
    let upload = exact!(RegistrationUpload::<Suite1>, upload);
    Ok(ServerRegistration::<Suite1>::finish(upload)
        .serialize()
        .to_vec())
}

/// The server's half of a sign-in in progress (kept server-side, used once).
pub struct ServerSigningIn {
    /// Serialized `ServerLogin` state.
    pub state: Vec<u8>,
    /// `CredentialResponse`, sent to the client.
    pub response: Vec<u8>,
}

/// Answers a sign-in request. `record` is the account's stored record, or
/// `None` for a name that is no account: then the answer is OPAQUE's fake one,
/// the same each time for that `credential` ([`unknown_credential_identifier`]),
/// and the finish fails.
pub fn server_login_start(
    secrets: &ServerSecrets,
    record: Option<&[u8]>,
    request: &[u8],
    credential: &[u8],
) -> Result<ServerSigningIn> {
    server_login_start_with(
        &mut crate::primitives::Rng,
        secrets,
        record,
        request,
        credential,
    )
}

pub fn server_login_start_with<R: RngCore + CryptoRng>(
    rng: &mut R,
    secrets: &ServerSecrets,
    record: Option<&[u8]>,
    request: &[u8],
    credential: &[u8],
) -> Result<ServerSigningIn> {
    let record = match record {
        Some(record) => Some(exact!(ServerRegistration::<Suite1>, record)),
        None => None,
    };
    let request = exact!(CredentialRequest::<Suite1>, request);
    let started = ServerLogin::start(
        rng,
        &secrets.0,
        record,
        request,
        credential,
        server_params(),
    )
    .map_err(protocol)?;
    Ok(ServerSigningIn {
        state: started.state.serialize().to_vec(),
        response: started.message.serialize().to_vec(),
    })
}

/// Checks the client's finalization against the kept state:
/// [`CryptoError::AuthFailed`] for a wrong password or an unknown name.
pub fn server_login_finish(state: &[u8], finalization: &[u8]) -> Result<()> {
    let state = exact!(ServerLogin::<Suite1>, state);
    let finalization = exact!(CredentialFinalization::<Suite1>, finalization);
    state
        .finish(finalization, server_params())
        .map_err(protocol)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BINDING: &str = "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b";

    fn register(secrets: &ServerSecrets, password: &str, binding: &str) -> (Vec<u8>, ExportKey) {
        let (client, request) = client_registration_start(password).unwrap();
        let response = server_registration_response(secrets, &request, binding).unwrap();
        let done = client.finish(&response).unwrap();
        (
            server_registration_record(&done.record).unwrap(),
            done.export_key,
        )
    }

    fn sign_in(
        secrets: &ServerSecrets,
        record: Option<&[u8]>,
        credential: &[u8],
        password: &str,
    ) -> Result<ExportKey> {
        let (client, request) = client_login_start(password)?;
        let server = server_login_start(secrets, record, &request, credential)?;
        let done = client.finish(&server.response)?;
        server_login_finish(&server.state, &done.finalization)?;
        Ok(done.export_key)
    }

    #[test]
    fn a_password_signs_in_and_opens_the_master_key() {
        let secrets = ServerSecrets::generate();
        let (record, export) = register(&secrets, "correct horse", BINDING);
        let envelope = export
            .seal_master_key(
                &[9u8; 32],
                crate::account_envelope::MasterKeyGeneration::FIRST,
                BINDING,
            )
            .unwrap();
        let credential = credential_identifier(BINDING).unwrap();
        let again = sign_in(&secrets, Some(&record), &credential, "correct horse").unwrap();
        assert_eq!(
            *again.open_master_key(&envelope, BINDING).unwrap(),
            [9u8; 32]
        );
        assert_eq!(
            again.bytes(),
            export.bytes(),
            "the same export key every time"
        );
        // Another key binding: another key, which does not open it.
        let other = "7d3f1a2b-9c4e-4f6a-8b1d-2e5c7a9f0b3d";
        assert!(again.open_master_key(&envelope, other).is_err());
    }

    #[test]
    fn a_wrong_password_an_unknown_name_and_another_server_all_fail() {
        let secrets = ServerSecrets::generate();
        let (record, _) = register(&secrets, "correct horse", BINDING);
        let credential = credential_identifier(BINDING).unwrap();
        assert!(matches!(
            sign_in(&secrets, Some(&record), &credential, "wrong horse"),
            Err(CryptoError::AuthFailed)
        ));
        let unknown = unknown_credential_identifier(&CanonicalName::parse("nobody").unwrap());
        assert!(matches!(
            sign_in(&secrets, None, &unknown, "correct horse"),
            Err(CryptoError::AuthFailed)
        ));
        // A server with other secrets cannot pass for the one registered with.
        let other = ServerSecrets::generate();
        assert!(sign_in(&other, Some(&record), &credential, "correct horse").is_err());
    }

    #[test]
    fn an_unknown_name_gets_the_same_shaped_answer_each_time() {
        let secrets = ServerSecrets::generate();
        let (record, _) = register(&secrets, "pw", BINDING);
        let (_, request) = client_login_start("pw").unwrap();
        let real = server_login_start(
            &secrets,
            Some(&record),
            &request,
            &credential_identifier(BINDING).unwrap(),
        )
        .unwrap();
        let fake = server_login_start(
            &secrets,
            None,
            &request,
            &unknown_credential_identifier(&CanonicalName::parse("nobody").unwrap()),
        )
        .unwrap();
        assert_eq!(real.response.len(), fake.response.len());
        assert_eq!(real.state.len(), fake.state.len());
    }

    #[test]
    fn the_setup_is_sealed_outside_the_database() {
        let secrets = ServerSecrets::generate();
        let key = [7u8; 32];
        let sealed = seal_server_setup(&secrets, &key, 3).unwrap();
        let opened = open_server_setup(&sealed, &key, 3).unwrap();
        assert_eq!(opened.public_key(), secrets.public_key());
        assert!(
            open_server_setup(&sealed, &[8u8; 32], 3).is_err(),
            "another key"
        );
        assert!(
            open_server_setup(&sealed, &key, 4).is_err(),
            "another key id"
        );
        let mut relabelled = sealed.clone();
        relabelled[8..10].copy_from_slice(&4u16.to_be_bytes());
        assert!(
            open_server_setup(&relabelled, &key, 4).is_err(),
            "relabelled"
        );
    }

    #[test]
    fn a_new_password_replaces_the_old_one() {
        let secrets = ServerSecrets::generate();
        let (_, old) = register(&secrets, "old password", BINDING);
        let old_envelope = old
            .seal_master_key(
                &[5u8; 32],
                crate::account_envelope::MasterKeyGeneration::FIRST,
                BINDING,
            )
            .unwrap();
        let master = old.open_master_key(&old_envelope, BINDING).unwrap();
        let (record, new) = register(&secrets, "new password", BINDING);
        let envelope = new
            .seal_master_key(
                &master,
                crate::account_envelope::MasterKeyGeneration::FIRST,
                BINDING,
            )
            .unwrap();
        let credential = credential_identifier(BINDING).unwrap();
        assert!(sign_in(&secrets, Some(&record), &credential, "old password").is_err());
        let signed = sign_in(&secrets, Some(&record), &credential, "new password").unwrap();
        assert_eq!(
            *signed.open_master_key(&envelope, BINDING).unwrap(),
            [5u8; 32]
        );
        assert!(
            old.open_master_key(&envelope, BINDING).is_err(),
            "the old export key no longer opens it"
        );
    }

    #[test]
    fn only_canonical_messages_are_accepted() {
        let secrets = ServerSecrets::generate();
        let junk = |bytes: &[u8]| [bytes, &[0u8]].concat();
        let (client, request) = client_registration_start("pw").unwrap();
        assert!(server_registration_response(&secrets, &junk(&request), BINDING).is_err());
        let response = server_registration_response(&secrets, &request, BINDING).unwrap();
        let (again, _) = client_registration_start("pw").unwrap();
        assert!(again.finish(&junk(&response)).is_err());
        let upload = client.finish(&response).unwrap().record;
        assert!(server_registration_record(&junk(&upload)).is_err());
        let record = server_registration_record(&upload).unwrap();
        let credential = credential_identifier(BINDING).unwrap();
        let (client, request) = client_login_start("pw").unwrap();
        assert!(server_login_start(&secrets, Some(&junk(&record)), &request, &credential).is_err());
        assert!(server_login_start(&secrets, Some(&record), &junk(&request), &credential).is_err());
        let server = server_login_start(&secrets, Some(&record), &request, &credential).unwrap();
        let (other, _) = client_login_start("pw").unwrap();
        assert!(other.finish(&junk(&server.response)).is_err());
        let done = client.finish(&server.response).unwrap();
        assert!(server_login_finish(&junk(&server.state), &done.finalization).is_err());
        assert!(server_login_finish(&server.state, &junk(&done.finalization)).is_err());
        server_login_finish(&server.state, &done.finalization).unwrap();
        // The sealed setup's plaintext too.
        let key = [3u8; 32];
        let mut serialized = secrets.0.serialize().to_vec();
        serialized.push(0);
        let mut nonce = [0u8; NONCE_LEN];
        nonce[0] = 1;
        let aad = [SETUP_AAD, &1u16.to_be_bytes()].concat();
        let ciphertext = Aead::new(Suite::V1, key.as_ref())
            .unwrap()
            .seal_with_nonce(&nonce, &aad, &serialized)
            .unwrap();
        let sealed = [
            SETUP_MAGIC.as_slice(),
            &1u16.to_be_bytes(),
            &nonce,
            &ciphertext,
        ]
        .concat();
        assert!(open_server_setup(&sealed, &key, 1).is_err());
    }

    #[test]
    fn a_name_has_one_form() {
        assert_eq!(
            CanonicalName::parse(" Alice ").unwrap(),
            CanonicalName::parse("alice").unwrap()
        );
        assert_eq!(
            unknown_credential_identifier(&CanonicalName::parse("Bob@Kutup.dev").unwrap()),
            unknown_credential_identifier(&CanonicalName::parse("bob@kutup.dev").unwrap())
        );
        for bad in ["", "a b", "ali\u{0131}", "x@", "@y", "a@b@c"] {
            assert!(CanonicalName::parse(bad).is_err(), "{bad}");
        }
    }
}
