//! Oblivious requests: RFC 9458's encapsulation (Oblivious HTTP), carrying
//! Kutup's own request bodies instead of Binary HTTP. A client seals a request
//! to a gateway's published HPKE key; a relay that passes it on sees neither
//! the request nor the answer, and the answer is sealed to that request alone
//! (docs/plans/pairwise-groups.md, "The anonymous route").
//!
//! The construction is RFC 9458 §4.3 and §4.4 unchanged, with the suite
//! DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305 (the one HPKE
//! suite `kutup-crypto` uses) and Kutup's own media labels. Both directions are
//! padded to one of [`SIZES`], so a relay can't tell operations apart by length.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use dryoc::rng::copy_randombytes;
use hkdf::Hkdf;
use hpke_rs::{HpkePrivateKey, HpkePublicKey};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::named_share::hpke_suite;
use crate::padding::Length;

/// The HPKE suite's identifiers (RFC 9180 §7), written into every request.
pub const KEM_X25519_HKDF_SHA256: u16 = 0x0020;
pub const KDF_HKDF_SHA256: u16 = 0x0001;
pub const AEAD_CHACHA20_POLY1305: u16 = 0x0003;

/// RFC 9458 names the content with a media label; Kutup's bodies are its own.
pub const REQUEST_LABEL: &[u8] = b"application/kutup-oblivious-request";
pub const RESPONSE_LABEL: &[u8] = b"application/kutup-oblivious-response";

/// The padded sizes of a request or response body: 1, 4, 16, 64 and 256 KiB
/// (a whole group's state, up to 256 members, fits the largest).
pub const SIZES: [usize; 5] = [1024, 4096, 16 * 1024, 64 * 1024, 256 * 1024];

const HEADER_LEN: usize = 7;
const ENC_LEN: usize = 32;
const KEY_LEN: usize = 32;
const AEAD_KEY_LEN: usize = 32;
const AEAD_NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// RFC 9458 §4.4: max(Nn, Nk).
const RESPONSE_NONCE_LEN: usize = 32;

/// The largest body that fits the largest size (one byte of padding marker).
pub const MAX_BODY: usize = SIZES[SIZES.len() - 1] - 1;

fn header(key_id: u8) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    header[0] = key_id;
    header[1..3].copy_from_slice(&KEM_X25519_HKDF_SHA256.to_be_bytes());
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
    private_key: Zeroizing<Vec<u8>>,
    public_key: [u8; KEY_LEN],
}

impl GatewayKey {
    /// A new random key pair.
    pub fn generate(key_id: u8) -> Result<Self> {
        // An X25519 private key is any 32 random bytes (clamped when used).
        let mut private_key = Zeroizing::new([0u8; KEY_LEN]);
        copy_randombytes(private_key.as_mut());
        Self::from_private_key(key_id, private_key.as_ref())
    }

    /// A stored key pair; the public half must be the private half's.
    pub fn from_private_key(key_id: u8, private_key: &[u8]) -> Result<Self> {
        if private_key.len() != KEY_LEN {
            return Err(CryptoError::InvalidLength {
                expected: KEY_LEN,
                got: private_key.len(),
            });
        }
        let secret: [u8; KEY_LEN] = private_key.try_into().expect("length checked");
        let public_key = x25519_public(&secret);
        Self::from_parts(key_id, private_key, &public_key)
    }

    fn from_parts(key_id: u8, private_key: &[u8], public_key: &[u8]) -> Result<Self> {
        let public_key: [u8; KEY_LEN] =
            public_key
                .try_into()
                .map_err(|_| CryptoError::InvalidLength {
                    expected: KEY_LEN,
                    got: public_key.len(),
                })?;
        Ok(Self {
            key_id,
            private_key: Zeroizing::new(private_key.to_vec()),
            public_key,
        })
    }

    pub fn key_id(&self) -> u8 {
        self.key_id
    }

    pub fn public_key(&self) -> [u8; KEY_LEN] {
        self.public_key
    }

    pub fn private_key(&self) -> &[u8] {
        &self.private_key
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

fn x25519_public(secret: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let mut public = [0u8; KEY_LEN];
    dryoc::classic::crypto_core::crypto_scalarmult_base(&mut public, secret);
    public
}

/// Seals `body` to the gateway key `key_id` / `public_key`: the request bytes
/// to send, and the context that opens the answer.
pub fn seal_request(
    key_id: u8,
    public_key: &[u8],
    body: &[u8],
) -> Result<(Vec<u8>, RequestContext)> {
    if public_key.len() != KEY_LEN {
        return Err(CryptoError::InvalidLength {
            expected: KEY_LEN,
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
        let padded = Zeroizing::new(pad(body)?);
        let mut response_nonce = [0u8; RESPONSE_NONCE_LEN];
        copy_randombytes(&mut response_nonce);
        let (aead, nonce) = self.0.aead(&response_nonce)?;
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
        response.extend_from_slice(&response_nonce);
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
}
