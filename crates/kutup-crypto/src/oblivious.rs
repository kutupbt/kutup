//! Oblivious requests: RFC 9458's encapsulation (Oblivious HTTP), carrying
//! Kutup's own request bodies instead of Binary HTTP. A client seals a request
//! to a gateway's published HPKE key; a relay that passes it on sees neither
//! the request nor the answer, and the answer is sealed to that request alone
//! (docs/plans/pairwise-groups.md, "The anonymous route").
//!
//! The construction is RFC 9458 §4.3 and §4.4 unchanged, with Kutup's own
//! media labels and one HPKE suite only: the X-Wing KEM (X25519 + ML-KEM-768,
//! draft-connolly-cfrg-xwing-kem-06, HPKE codepoint 0x647a), HKDF-SHA256 and
//! ChaCha20-Poly1305. Post-quantum from the start: a request recorded today
//! can't be opened by a quantum computer later. There is no other KEM, no
//! fallback and no negotiation; a request or key config naming another suite
//! is refused. Both directions are padded to one of [`SIZES`], so a relay
//! can't tell operations apart by length.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
// Adapter: RFC 9458's response AEAD.
#[allow(clippy::disallowed_types)]
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
// Adapter: RFC 9458's response key derivation.
#[allow(clippy::disallowed_types)]
use hkdf::Hkdf;
use hpke_rs::{HpkePrivateKey, HpkePublicKey};
// Adapter: RFC 9458's response key derivation.
#[allow(clippy::disallowed_types)]
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::padding::Length;

/// The HPKE suite's identifiers (RFC 9180 §7), written into every request.
/// X-Wing's is the HPKE registry's 0x647a (not the draft's earlier 0x004D).
pub const KEM_XWING: u16 = crate::hpke_xwing::KEM_ID;
pub const KDF_HKDF_SHA256: u16 = 0x0001;
pub const AEAD_CHACHA20_POLY1305: u16 = 0x0003;

/// RFC 9458 names the content with a media label; Kutup's bodies are its own.
pub const REQUEST_LABEL: &[u8] = b"application/kutup-oblivious-request";
pub const RESPONSE_LABEL: &[u8] = b"application/kutup-oblivious-response";

/// The padded sizes of a request or response body: 1, 4, 16, 64 and 256 KiB
/// (a whole group's state, up to 256 members, fits the largest).
pub const SIZES: [usize; 5] = [1024, 4096, 16 * 1024, 64 * 1024, 256 * 1024];

const HEADER_LEN: usize = 7;
const ENC_LEN: usize = crate::hpke_xwing::ENCAPSULATED_KEY_LEN;
pub const PUBLIC_KEY_LEN: usize = crate::hpke_xwing::PUBLIC_KEY_LEN;
pub const PRIVATE_KEY_LEN: usize = crate::hpke_xwing::SEED_LEN;
const AEAD_KEY_LEN: usize = 32;
const AEAD_NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// RFC 9458 §4.4: max(Nn, Nk).
const RESPONSE_NONCE_LEN: usize = 32;

/// The largest body that fits the largest size (one byte of padding marker).
pub const MAX_BODY: usize = SIZES[SIZES.len() - 1] - 1;

/// The largest sealed request (header, encapsulated key, the largest padded
/// size and the tag); an answer (response nonce, size, tag) is smaller.
pub const MAX_SEALED: usize = HEADER_LEN + ENC_LEN + SIZES[SIZES.len() - 1] + TAG_LEN;

// Adapter: RFC 9458 drives HPKE's context API.
#[allow(clippy::disallowed_types)]
fn hpke_suite() -> hpke_rs::Hpke<hpke_rs_rust_crypto::HpkeRustCrypto> {
    crate::hpke_xwing::suite()
}

fn header(key_id: u8) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    header[0] = key_id;
    header[1..3].copy_from_slice(&KEM_XWING.to_be_bytes());
    header[3..5].copy_from_slice(&KDF_HKDF_SHA256.to_be_bytes());
    header[5..7].copy_from_slice(&AEAD_CHACHA20_POLY1305.to_be_bytes());
    header
}

fn request_info(header: &[u8; HEADER_LEN]) -> Vec<u8> {
    let mut info = Vec::with_capacity(REQUEST_LABEL.len() + 1 + HEADER_LEN);
    info.extend_from_slice(REQUEST_LABEL);
    info.push(0);
    info.extend_from_slice(header);
    info
}

fn pad(body: &[u8]) -> Result<Vec<u8>> {
    let size = SIZES
        .iter()
        .copied()
        .find(|size| body.len() < *size)
        .ok_or_else(|| CryptoError::InvalidInput("oblivious body is too large".into()))?;
    Length::Fixed(size).pad(body)
}

fn unpad(padded: Vec<u8>) -> Result<Vec<u8>> {
    if !SIZES.contains(&padded.len()) {
        return Err(CryptoError::InvalidInput(
            "oblivious body has a size outside the padding sizes".into(),
        ));
    }
    Length::Fixed(padded.len()).unpad(padded)
}

fn backend(error: impl std::fmt::Debug) -> CryptoError {
    CryptoError::Backend(format!("{error:?}"))
}

/// A gateway's HPKE key pair, with the one-byte key id clients name it by.
pub struct GatewayKey {
    key_id: u8,
    private_key: Zeroizing<[u8; PRIVATE_KEY_LEN]>,
    public_key: [u8; PUBLIC_KEY_LEN],
}

impl GatewayKey {
    /// A new random key pair.
    pub fn generate(key_id: u8) -> Result<Self> {
        let mut private_key = Zeroizing::new([0u8; PRIVATE_KEY_LEN]);
        crate::primitives::random(private_key.as_mut());
        Self::from_private_key(key_id, private_key.as_ref())
    }

    /// A stored key pair from its 32-byte seed (the X-Wing decapsulation
    /// key); the public key is derived from it.
    pub fn from_private_key(key_id: u8, private_key: &[u8]) -> Result<Self> {
        let seed: [u8; PRIVATE_KEY_LEN] =
            private_key
                .try_into()
                .map_err(|_| CryptoError::InvalidLength {
                    expected: PRIVATE_KEY_LEN,
                    got: private_key.len(),
                })?;
        let public_key = xwing_public_key(&seed)?;
        Ok(Self {
            key_id,
            private_key: Zeroizing::new(seed),
            public_key,
        })
    }

    pub fn key_id(&self) -> u8 {
        self.key_id
    }

    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.public_key
    }

    pub fn private_key(&self) -> &[u8] {
        self.private_key.as_ref()
    }

    /// The request's body, and the context its answer is sealed with.
    /// Every failure is the same [`CryptoError::AuthFailed`], so a caller can
    /// answer them all alike.
    pub fn open_request(&self, request: &[u8]) -> Result<(Zeroizing<Vec<u8>>, ResponseContext)> {
        if request.len() < HEADER_LEN + ENC_LEN + TAG_LEN {
            return Err(CryptoError::AuthFailed);
        }
        let header: [u8; HEADER_LEN] = request[..HEADER_LEN].try_into().expect("length checked");
        if header != self::header(self.key_id) {
            return Err(CryptoError::AuthFailed);
        }
        let enc = &request[HEADER_LEN..HEADER_LEN + ENC_LEN];
        let ciphertext = &request[HEADER_LEN + ENC_LEN..];
        let hpke = hpke_suite();
        let mut context = hpke
            .setup_receiver(
                enc,
                &HpkePrivateKey::new(self.private_key.to_vec()),
                &request_info(&header),
                None,
                None,
                None,
            )
            .map_err(|_| CryptoError::AuthFailed)?;
        let padded = context
            .open(b"", ciphertext)
            .map_err(|_| CryptoError::AuthFailed)?;
        let body = unpad(padded).map_err(|_| CryptoError::AuthFailed)?;
        let secret = context
            .export(RESPONSE_LABEL, RESPONSE_NONCE_LEN)
            .map_err(|_| CryptoError::AuthFailed)?;
        Ok((
            Zeroizing::new(body),
            ResponseContext(ExchangeSecret {
                enc: enc.to_vec(),
                secret: Zeroizing::new(secret),
            }),
        ))
    }
}

/// X-Wing's GenerateKeyPairDerand: the encapsulation key from the seed.
fn xwing_public_key(seed: &[u8; PRIVATE_KEY_LEN]) -> Result<[u8; PUBLIC_KEY_LEN]> {
    Ok(crate::hpke_xwing::public_key(seed))
}

/// Seals `body` to the gateway key `key_id` / `public_key`: the request bytes
/// to send, and the context that opens the answer.
pub fn seal_request(
    key_id: u8,
    public_key: &[u8],
    body: &[u8],
) -> Result<(Vec<u8>, RequestContext)> {
    if public_key.len() != PUBLIC_KEY_LEN {
        return Err(CryptoError::InvalidLength {
            expected: PUBLIC_KEY_LEN,
            got: public_key.len(),
        });
    }
    let header = header(key_id);
    let padded = Zeroizing::new(pad(body)?);
    let mut hpke = hpke_suite();
    let (enc, mut context) = hpke
        .setup_sender(
            &HpkePublicKey::new(public_key.to_vec()),
            &request_info(&header),
            None,
            None,
            None,
        )
        .map_err(backend)?;
    let ciphertext = context.seal(b"", &padded).map_err(backend)?;
    let secret = context
        .export(RESPONSE_LABEL, RESPONSE_NONCE_LEN)
        .map_err(backend)?;
    let mut request = Vec::with_capacity(HEADER_LEN + enc.len() + ciphertext.len());
    request.extend_from_slice(&header);
    request.extend_from_slice(&enc);
    request.extend_from_slice(&ciphertext);
    Ok((
        request,
        RequestContext(ExchangeSecret {
            enc,
            secret: Zeroizing::new(secret),
        }),
    ))
}

struct ExchangeSecret {
    enc: Vec<u8>,
    secret: Zeroizing<Vec<u8>>,
}

impl ExchangeSecret {
    /// RFC 9458 §4.4: the response key and nonce from the exported secret,
    /// salted with the request's `enc` and the response nonce.
    // Adapter: RFC 9458 §4.4, fixed by the RFC.
    #[allow(clippy::disallowed_types)]
    fn aead(&self, response_nonce: &[u8]) -> Result<(ChaCha20Poly1305, Nonce)> {
        let mut salt = Vec::with_capacity(self.enc.len() + response_nonce.len());
        salt.extend_from_slice(&self.enc);
        salt.extend_from_slice(response_nonce);
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &self.secret);
        let mut key = Zeroizing::new([0u8; AEAD_KEY_LEN]);
        let mut nonce = [0u8; AEAD_NONCE_LEN];
        hkdf.expand(b"key", key.as_mut()).map_err(backend)?;
        hkdf.expand(b"nonce", &mut nonce).map_err(backend)?;
        Ok((
            ChaCha20Poly1305::new(Key::from_slice(key.as_ref())),
            *Nonce::from_slice(&nonce),
        ))
    }
}

/// The client's side of one exchange: opens the gateway's answer.
pub struct RequestContext(ExchangeSecret);

impl RequestContext {
    pub fn open_response(&self, response: &[u8]) -> Result<Vec<u8>> {
        if response.len() < RESPONSE_NONCE_LEN + TAG_LEN {
            return Err(CryptoError::AuthFailed);
        }
        let (response_nonce, ciphertext) = response.split_at(RESPONSE_NONCE_LEN);
        let (aead, nonce) = self.0.aead(response_nonce)?;
        let padded = aead
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: b"",
                },
            )
            .map_err(|_| CryptoError::AuthFailed)?;
        unpad(padded).map_err(|_| CryptoError::AuthFailed)
    }
}

/// The gateway's side of one exchange: seals the answer to that request.
pub struct ResponseContext(ExchangeSecret);

impl ResponseContext {
    pub fn seal_response(&self, body: &[u8]) -> Result<Vec<u8>> {
        let mut response_nonce = [0u8; RESPONSE_NONCE_LEN];
        crate::primitives::random(&mut response_nonce);
        self.seal_response_with_nonce(body, &response_nonce)
    }

    fn seal_response_with_nonce(
        &self,
        body: &[u8],
        response_nonce: &[u8; RESPONSE_NONCE_LEN],
    ) -> Result<Vec<u8>> {
        let padded = Zeroizing::new(pad(body)?);
        let (aead, nonce) = self.0.aead(response_nonce)?;
        let ciphertext = aead
            .encrypt(
                &nonce,
                Payload {
                    msg: &padded,
                    aad: b"",
                },
            )
            .map_err(backend)?;
        let mut response = Vec::with_capacity(RESPONSE_NONCE_LEN + ciphertext.len());
        response.extend_from_slice(response_nonce);
        response.extend_from_slice(&ciphertext);
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_and_its_answer_round_trip() {
        let gateway = GatewayKey::generate(7).unwrap();
        let (request, client) = seal_request(7, &gateway.public_key(), b"get state").unwrap();
        assert_eq!(request.len(), HEADER_LEN + ENC_LEN + SIZES[0] + TAG_LEN);
        let (body, server) = gateway.open_request(&request).unwrap();
        assert_eq!(body.as_slice(), b"get state");
        let response = server.seal_response(b"the state").unwrap();
        assert_eq!(response.len(), RESPONSE_NONCE_LEN + SIZES[0] + TAG_LEN);
        assert_eq!(client.open_response(&response).unwrap(), b"the state");
    }

    #[test]
    fn sizes_hide_lengths_and_cap_bodies() {
        let gateway = GatewayKey::generate(1).unwrap();
        for (len, size) in [
            (0, SIZES[0]),
            (1023, SIZES[0]),
            (1024, SIZES[1]),
            (4096, SIZES[2]),
            (16 * 1024, SIZES[3]),
            (64 * 1024, SIZES[4]),
            (MAX_BODY, SIZES[4]),
        ] {
            let (request, _) = seal_request(1, &gateway.public_key(), &vec![7; len]).unwrap();
            assert_eq!(
                request.len(),
                HEADER_LEN + ENC_LEN + size + TAG_LEN,
                "body of {len}"
            );
            let (body, _) = gateway.open_request(&request).unwrap();
            assert_eq!(body.len(), len);
        }
        assert!(seal_request(1, &gateway.public_key(), &vec![0; MAX_BODY + 1]).is_err());
    }

    #[test]
    fn an_answer_opens_only_for_its_own_request() {
        let gateway = GatewayKey::generate(1).unwrap();
        let (first, first_client) = seal_request(1, &gateway.public_key(), b"one").unwrap();
        let (second, _) = seal_request(1, &gateway.public_key(), b"two").unwrap();
        let (_, first_server) = gateway.open_request(&first).unwrap();
        let (_, second_server) = gateway.open_request(&second).unwrap();
        let answer = second_server.seal_response(b"for two").unwrap();
        assert!(first_client.open_response(&answer).is_err());
        assert!(first_client
            .open_response(&first_server.seal_response(b"for one").unwrap())
            .is_ok());
    }

    #[test]
    fn tampering_another_key_or_another_suite_is_refused_alike() {
        let gateway = GatewayKey::generate(3).unwrap();
        let other = GatewayKey::generate(3).unwrap();
        let (request, _) = seal_request(3, &gateway.public_key(), b"x").unwrap();
        assert!(matches!(
            other.open_request(&request),
            Err(CryptoError::AuthFailed)
        ));
        let mut flipped = request.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert!(matches!(
            gateway.open_request(&flipped),
            Err(CryptoError::AuthFailed)
        ));
        let mut wrong_id = request.clone();
        wrong_id[0] = 4;
        assert!(matches!(
            gateway.open_request(&wrong_id),
            Err(CryptoError::AuthFailed)
        ));
        // The X25519-only suite (DHKEM 0x0020), or any other KEM: refused.
        let mut classical = request.clone();
        classical[1..3].copy_from_slice(&0x0020u16.to_be_bytes());
        assert!(matches!(
            gateway.open_request(&classical),
            Err(CryptoError::AuthFailed)
        ));
        let mut wrong_aead = request;
        wrong_aead[6] = 0x01;
        assert!(matches!(
            gateway.open_request(&wrong_aead),
            Err(CryptoError::AuthFailed)
        ));
        assert!(matches!(
            gateway.open_request(&[0; 10]),
            Err(CryptoError::AuthFailed)
        ));
    }

    #[test]
    fn a_stored_private_key_gives_the_same_public_key() {
        let gateway = GatewayKey::generate(9).unwrap();
        let again = GatewayKey::from_private_key(9, gateway.private_key()).unwrap();
        assert_eq!(again.public_key(), gateway.public_key());
        let (request, _) = seal_request(9, &gateway.public_key(), b"x").unwrap();
        assert!(again.open_request(&request).is_ok());
    }

    #[derive(serde::Deserialize)]
    struct XWingVectors {
        vectors: Vec<XWingVector>,
    }

    #[derive(serde::Deserialize)]
    struct XWingVector {
        seed: String,
        pk: String,
        eseed: String,
        ct: String,
        ss: String,
    }

    /// The KEM against draft-connolly-cfrg-xwing-kem-06's own vectors: the
    /// key pair from its seed, encapsulation with fixed randomness, and
    /// decapsulation.
    #[test]
    fn x_wing_matches_the_drafts_vectors() {
        use x_wing::{Decapsulate as _, Decapsulator as _};
        let file: XWingVectors =
            serde_json::from_str(include_str!("../tests/vectors/xwing-draft06.json")).unwrap();
        assert_eq!(file.vectors.len(), 3);
        for vector in file.vectors {
            let seed: [u8; PRIVATE_KEY_LEN] =
                hex::decode(&vector.seed).unwrap().try_into().unwrap();
            assert_eq!(hex::encode(xwing_public_key(&seed).unwrap()), vector.pk);
            assert_eq!(
                hex::encode(GatewayKey::from_private_key(1, &seed).unwrap().public_key()),
                vector.pk
            );
            let private_key = x_wing::DecapsulationKey::from(seed);
            let eseed = hex::decode(&vector.eseed).unwrap();
            let (ciphertext, shared) = private_key
                .encapsulation_key()
                .encapsulate_deterministic(eseed.as_slice().try_into().unwrap());
            assert_eq!(hex::encode(ciphertext.as_slice()), vector.ct);
            assert_eq!(hex::encode(shared.as_slice()), vector.ss);
            let ciphertext = hex::decode(&vector.ct).unwrap();
            let shared = private_key.decapsulate(ciphertext.as_slice().try_into().unwrap());
            assert_eq!(hex::encode(shared.as_slice()), vector.ss);
        }
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Vector {
        key_id: u8,
        private_key: String,
        request: String,
        request_body: String,
        response_nonce: String,
        response: String,
        response_body: String,
    }

    /// A recorded exchange (RFC 9458 §4.3/§4.4 with this suite and labels):
    /// the gateway must open the fixed request bytes, and seal the fixed
    /// answer to exactly the fixed response bytes.
    #[test]
    fn a_recorded_exchange_still_opens_and_seals_the_same() {
        let vector: Vector =
            serde_json::from_str(include_str!("../tests/vectors/oblivious-v1.json")).unwrap();
        let gateway =
            GatewayKey::from_private_key(vector.key_id, &hex::decode(&vector.private_key).unwrap())
                .unwrap();
        let (body, server) = gateway
            .open_request(&hex::decode(&vector.request).unwrap())
            .unwrap();
        assert_eq!(body.as_slice(), vector.request_body.as_bytes());
        let nonce: [u8; RESPONSE_NONCE_LEN] = hex::decode(&vector.response_nonce)
            .unwrap()
            .try_into()
            .unwrap();
        let response = server
            .seal_response_with_nonce(vector.response_body.as_bytes(), &nonce)
            .unwrap();
        assert_eq!(hex::encode(&response), vector.response);
        // A test shortcut, not the client's path: the client's context is
        // built here from the server's exported secret (the vector records
        // no client randomness), so this checks the response open, not the
        // client's own key schedule (`a_request_and_its_answer_round_trip`
        // does that).
        let client = RequestContext(ExchangeSecret {
            enc: server.0.enc.clone(),
            secret: server.0.secret.clone(),
        });
        assert_eq!(
            client.open_response(&response).unwrap(),
            vector.response_body.as_bytes()
        );
    }

    #[test]
    #[ignore = "writes tests/vectors/oblivious-v1.json; run once by hand"]
    fn write_recorded_exchange() {
        let gateway = GatewayKey::from_private_key(7, &[0x42; 32]).unwrap();
        let request_body = "{\"operation\":\"getState\"}";
        let (request, _) = seal_request(7, &gateway.public_key(), request_body.as_bytes()).unwrap();
        let (_, server) = gateway.open_request(&request).unwrap();
        let nonce = [0x24; RESPONSE_NONCE_LEN];
        let response_body = "{\"status\":\"ok\"}";
        let response = server
            .seal_response_with_nonce(response_body.as_bytes(), &nonce)
            .unwrap();
        let vector = Vector {
            key_id: 7,
            private_key: hex::encode([0x42; 32]),
            request: hex::encode(&request),
            request_body: request_body.into(),
            response_nonce: hex::encode(nonce),
            response: hex::encode(&response),
            response_body: response_body.into(),
        };
        std::fs::write(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/vectors/oblivious-v1.json"
            ),
            serde_json::to_string_pretty(&vector).unwrap() + "\n",
        )
        .unwrap();
    }
}
