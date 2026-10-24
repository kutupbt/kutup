//! Encrypted Web Push payloads (RFC 8291, `aes128gcm` of RFC 8188): what a
//! calendar reminder push carries, readable only by the browser that
//! subscribed. Chat's pushes stay empty wake-ups (`web_push`).
//!
//! Each message has a fresh ephemeral P-256 key and a fresh 16-byte salt;
//! the browser's public key (`p256dh`) and auth secret come with its
//! subscription. One record: the plaintext, the last-record delimiter, no
//! padding.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
// Adapter: RFC 8291's key derivation is HKDF-SHA256.
#[allow(clippy::disallowed_types)]
use hkdf::Hkdf;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
// Adapter: RFC 8291's key derivation is HKDF-SHA256.
#[allow(clippy::disallowed_types)]
use sha2::Sha256;

/// RFC 8188's record size, as RFC 8291 §4 writes it; a reminder is far
/// smaller.
const RECORD_SIZE: u32 = 4096;
/// The most a payload carries (RFC 8291 §4): a push message is at most 4096
/// octets, less the 86-octet header, the delimiter and the 16-octet tag.
pub const MAX_PLAINTEXT: usize = 3993;

#[derive(Debug, thiserror::Error)]
pub enum PayloadError {
    #[error("the subscription's key is not a P-256 point")]
    BadKey,
    #[error("the subscription's auth secret is not 16 bytes")]
    BadAuth,
    #[error("the payload is too long")]
    TooLong,
}

/// Encrypts `plaintext` to a browser's subscription keys (`p256dh`, the
/// uncompressed point, and the 16-byte `auth`): the message body to POST
/// with `Content-Encoding: aes128gcm`.
pub fn encrypt(p256dh: &[u8], auth: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, PayloadError> {
    let mut salt = [0u8; 16];
    kutup_crypto::primitives::random(&mut salt);
    let ephemeral = SecretKey::random(&mut kutup_crypto::primitives::Rng);
    encrypt_with(&ephemeral, salt, p256dh, auth, plaintext)
}

// Adapter: RFC 8291 (aes128gcm Web Push encryption).
#[allow(clippy::disallowed_types)]
fn encrypt_with(
    ephemeral: &SecretKey,
    salt: [u8; 16],
    p256dh: &[u8],
    auth: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, PayloadError> {
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(PayloadError::TooLong);
    }
    let user_agent = PublicKey::from_sec1_bytes(p256dh).map_err(|_| PayloadError::BadKey)?;
    let auth: [u8; 16] = auth.try_into().map_err(|_| PayloadError::BadAuth)?;
    let ua_public = user_agent.to_encoded_point(false);
    let as_public = ephemeral.public_key().to_encoded_point(false);
    let shared = p256::ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), user_agent.as_affine());

    // RFC 8291 §3.3: the input keying material, bound to both public keys.
    let mut key_info = b"WebPush: info\0".to_vec();
    key_info.extend_from_slice(ua_public.as_bytes());
    key_info.extend_from_slice(as_public.as_bytes());
    let mut ikm = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&auth), shared.raw_secret_bytes())
        .expand(&key_info, &mut ikm)
        .expect("32 bytes is a valid length");
    // RFC 8188 §2.2: the content key and nonce from the salt.
    let prk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut cek = [0u8; 16];
    let mut nonce = [0u8; 12];
    prk.expand(b"Content-Encoding: aes128gcm\0", &mut cek)
        .expect("16 bytes is a valid length");
    prk.expand(b"Content-Encoding: nonce\0", &mut nonce)
        .expect("12 bytes is a valid length");

    let mut record = plaintext.to_vec();
    // The last record's delimiter, no padding.
    record.push(2);
    let ciphertext = Aes128Gcm::new_from_slice(&cek)
        .expect("a 16-byte key")
        .encrypt(Nonce::from_slice(&nonce), record.as_slice())
        .expect("AES-GCM encrypts any length here");

    let mut body = Vec::with_capacity(16 + 4 + 1 + 65 + ciphertext.len());
    body.extend_from_slice(&salt);
    body.extend_from_slice(&RECORD_SIZE.to_be_bytes());
    body.push(as_public.as_bytes().len() as u8);
    body.extend_from_slice(as_public.as_bytes());
    body.extend_from_slice(&ciphertext);
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    fn b64(text: &str) -> Vec<u8> {
        URL_SAFE_NO_PAD.decode(text).unwrap()
    }

    /// RFC 8291 §5 and Appendix A.
    #[test]
    fn rfc_8291_example() {
        let ephemeral =
            SecretKey::from_slice(&b64("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw")).unwrap();
        assert_eq!(
            ephemeral.public_key().to_encoded_point(false).as_bytes(),
            b64("BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8")
        );
        let salt: [u8; 16] = b64("DGv6ra1nlYgDCS1FRnbzlw").try_into().unwrap();
        let body = encrypt_with(
            &ephemeral,
            salt,
            &b64("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"),
            &b64("BTBZMqHH6r4Tts7J_aSIgg"),
            b"When I grow up, I want to be a watermelon",
        )
        .unwrap();
        let mut expected = b64(
            "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8",
        );
        expected.extend(b64(
            "8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ",
        ));
        assert_eq!(body, expected);
    }

    #[test]
    fn every_message_has_its_own_key_and_salt() {
        let browser = SecretKey::random(&mut kutup_crypto::primitives::Rng);
        let p256dh = browser.public_key().to_encoded_point(false);
        let auth = [7u8; 16];
        let one = encrypt(p256dh.as_bytes(), &auth, b"same").unwrap();
        let two = encrypt(p256dh.as_bytes(), &auth, b"same").unwrap();
        // Salt and the ephemeral key (in the header) differ, so the whole body does.
        assert_ne!(one[..16], two[..16]);
        assert_ne!(one[21..86], two[21..86]);
        assert_ne!(one, two);
    }

    #[test]
    fn refuses_bad_keys_and_long_payloads() {
        let browser = SecretKey::random(&mut kutup_crypto::primitives::Rng);
        let p256dh = browser.public_key().to_encoded_point(false);
        assert!(matches!(
            encrypt(&[4; 65], &[0; 16], b"x"),
            Err(PayloadError::BadKey)
        ));
        assert!(matches!(
            encrypt(p256dh.as_bytes(), &[0; 15], b"x"),
            Err(PayloadError::BadAuth)
        ));
        assert!(matches!(
            encrypt(p256dh.as_bytes(), &[0; 16], &vec![0; MAX_PLAINTEXT + 1]),
            Err(PayloadError::TooLong)
        ));
    }
}
