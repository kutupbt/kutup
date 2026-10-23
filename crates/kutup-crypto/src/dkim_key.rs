//! The DKIM keys custom domains are signed with (docs/plans/mail-custom-
//! domains.md §4): RSA-2048, as Proton's. The private key is kept sealed
//! under a server key (`MAIL_DKIM_KEYS`, XChaCha20-Poly1305) bound to the
//! key's id and selector, so a database dump alone signs nothing and a
//! sealed key can't be moved to another selector. Stalwart takes the key as
//! PKCS#8 PEM; DNS publishes it as `v=DKIM1; k=rsa; p=<SPKI>`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rsa::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _, EncodePublicKey as _};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

pub const BITS: usize = 2048;
const SEAL_DOMAIN: &[u8] = b"kutup/dkim-key/v1\0";
const NONCE_LEN: usize = 24;

/// A fresh key: its PKCS#8 private key and SPKI public key, DER.
pub struct DkimKey {
    pub private_pkcs8: Zeroizing<Vec<u8>>,
    pub public_spki: Vec<u8>,
}

pub fn generate() -> Result<DkimKey> {
    let key = rsa::RsaPrivateKey::new(&mut crate::primitives::Rng, BITS)
        .map_err(|e| CryptoError::Backend(format!("RSA key: {e}")))?;
    let private_pkcs8 = Zeroizing::new(
        key.to_pkcs8_der()
            .map_err(|e| CryptoError::Backend(format!("PKCS#8: {e}")))?
            .as_bytes()
            .to_vec(),
    );
    let public_spki = key
        .to_public_key()
        .to_public_key_der()
        .map_err(|e| CryptoError::Backend(format!("SPKI: {e}")))?
        .as_bytes()
        .to_vec();
    Ok(DkimKey {
        private_pkcs8,
        public_spki,
    })
}

/// The DNS TXT value that publishes `public_spki`.
pub fn txt_record(public_spki: &[u8]) -> String {
    format!("v=DKIM1; k=rsa; p={}", STANDARD.encode(public_spki))
}

/// `private_pkcs8` as PEM, checked to be an RSA key first.
pub fn private_pem(private_pkcs8: &[u8]) -> Result<Zeroizing<String>> {
    rsa::RsaPrivateKey::from_pkcs8_der(private_pkcs8)
        .map_err(|_| CryptoError::InvalidInput("not an RSA PKCS#8 key".into()))?;
    let body = Zeroizing::new(STANDARD.encode(private_pkcs8));
    let mut pem = Zeroizing::new(String::from("-----BEGIN PRIVATE KEY-----\n"));
    for line in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    Ok(pem)
}

fn aad(server_key_id: u16, dkim_key_id: &[u8; 16], selector: &str) -> Vec<u8> {
    let selector = selector.as_bytes();
    [
        SEAL_DOMAIN,
        &server_key_id.to_be_bytes(),
        dkim_key_id,
        &(selector.len() as u16).to_be_bytes(),
        selector,
    ]
    .concat()
}

/// Seals a private key under `server_key` (`MAIL_DKIM_KEYS`' entry
/// `server_key_id`) for the key `dkim_key_id` at `selector`.
pub fn seal(
    server_key: &[u8; 32],
    server_key_id: u16,
    dkim_key_id: &[u8; 16],
    selector: &str,
    private_pkcs8: &[u8],
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    crate::primitives::random(&mut nonce);
    let sealed = XChaCha20Poly1305::new(server_key.into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: private_pkcs8,
                aad: &aad(server_key_id, dkim_key_id, selector),
            },
        )
        .map_err(|_| CryptoError::Backend("seal the DKIM key".into()))?;
    Ok([nonce.as_slice(), &sealed].concat())
}

/// Opens what [`seal`] sealed; fails for another server key, key or
/// selector.
pub fn open(
    server_key: &[u8; 32],
    server_key_id: u16,
    dkim_key_id: &[u8; 16],
    selector: &str,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() <= NONCE_LEN {
        return Err(CryptoError::AuthFailed);
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    XChaCha20Poly1305::new(server_key.into())
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad(server_key_id, dkim_key_id, selector),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::AuthFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_seals_to_its_id_and_selector_and_exports_both_ways() {
        let key = generate().unwrap();
        let server = [7u8; 32];
        let id = [1u8; 16];
        let sealed = seal(&server, 3, &id, "kutup1", &key.private_pkcs8).unwrap();
        assert_eq!(
            *open(&server, 3, &id, "kutup1", &sealed).unwrap(),
            *key.private_pkcs8
        );
        assert!(
            open(&server, 3, &id, "kutup2", &sealed).is_err(),
            "selector"
        );
        assert!(
            open(&server, 4, &id, "kutup1", &sealed).is_err(),
            "server key id"
        );
        assert!(
            open(&server, 3, &[2u8; 16], "kutup1", &sealed).is_err(),
            "key id"
        );
        assert!(
            open(&[8u8; 32], 3, &id, "kutup1", &sealed).is_err(),
            "server key"
        );

        let pem = private_pem(&key.private_pkcs8).unwrap();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert!(pem
            .lines()
            .all(|line| line.len() <= 64 || line.starts_with("-----")));
        let txt = txt_record(&key.public_spki);
        assert!(txt.starts_with("v=DKIM1; k=rsa; p=MII"));
        assert!(private_pem(b"not a key").is_err());
    }
}
