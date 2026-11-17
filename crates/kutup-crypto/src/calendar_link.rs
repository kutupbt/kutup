//! Calendar share links (docs/plans/calendar-e3.md §3, D-2; Q-5).
//!
//! A full link carries a random 32-byte **link secret**: in the URL's
//! fragment (the default; the server never decrypts) or its query (for other
//! calendar apps; the server opens it while serving). For each live key
//! generation the server keeps that generation's passphrase sealed under a
//! key derived from the secret: [`seal_link_passphrase`]. Unlike Proton's
//! XOR of the passphrase with the link key, each generation has its own key
//! (HKDF over the calendar, the link and the generation) and an AEAD, so no
//! pad is ever reused and nothing opens under another calendar, link or
//! generation.
//!
//! The calendar's members keep the link secret too, sealed under a key
//! derived from the newest generation's passphrase ([`seal_link_secret`]), as
//! Proton seals its `CacheKey` to the calendar key: the owner can show the
//! URL again and, when the key rotates, re-seal the new passphrase for the
//! link. Busy-only links carry no secret and need none of this.
//!
//! Both envelopes are `version ‖ nonce ‖ ciphertext` (XChaCha20-Poly1305,
//! suite V1), with the context (calendar id, link id, generation) as the
//! HKDF info and the associated data.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use zeroize::Zeroizing;

use crate::calendar::{Passphrase, PASSPHRASE_BYTES};
use crate::error::{CryptoError, Result};
use crate::primitives::{kdf, Aead, Suite};

/// The envelopes' format version.
pub const CALENDAR_LINK_VERSION: u8 = 1;
/// A link secret's size.
pub const LINK_SECRET_BYTES: usize = 32;

/// A full link's secret: what its URL carries.
pub struct LinkSecret(Zeroizing<[u8; LINK_SECRET_BYTES]>);

impl LinkSecret {
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; LINK_SECRET_BYTES]);
        crate::primitives::random(bytes.as_mut());
        Self(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let array: [u8; LINK_SECRET_BYTES] =
            bytes.try_into().map_err(|_| CryptoError::InvalidLength {
                expected: LINK_SECRET_BYTES,
                got: bytes.len(),
            })?;
        Ok(Self(Zeroizing::new(array)))
    }

    /// As a URL carries it: base64url without padding.
    pub fn to_url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0.as_ref())
    }

    pub fn from_url(text: &str) -> Result<Self> {
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(text.trim())
                .map_err(|_| CryptoError::InvalidInput("a link secret is base64url".into()))?,
        );
        Self::from_bytes(&bytes)
    }

    pub fn as_bytes(&self) -> &[u8; LINK_SECRET_BYTES] {
        &self.0
    }
}

/// What an envelope is bound to: the version, the calendar, the link and
/// the key generation, each length-prefixed.
fn context(calendar_id: &str, link_id: &str, generation: u32) -> Result<Vec<u8>> {
    let mut out = vec![CALENDAR_LINK_VERSION];
    for part in [calendar_id, link_id] {
        if part.is_empty() || part.len() > 255 {
            return Err(CryptoError::InvalidInput(
                "a calendar or link id is 1 to 255 bytes".into(),
            ));
        }
        out.push(part.len() as u8);
        out.extend_from_slice(part.as_bytes());
    }
    out.extend_from_slice(&generation.to_be_bytes());
    Ok(out)
}

fn aead(ikm: &[u8], family: &[u8], context: &[u8]) -> Result<Aead> {
    let mut key = Zeroizing::new([0u8; 32]);
    kdf(Suite::V1, ikm, family, context, key.as_mut())?;
    Aead::new(Suite::V1, key.as_ref())
}

fn seal(aead: &Aead, context: &[u8], nonce: Option<&[u8]>, plaintext: &[u8]) -> Result<Vec<u8>> {
    let body = match nonce {
        Some(nonce) => {
            let mut out = nonce.to_vec();
            out.extend(aead.seal_with_nonce(nonce, context, plaintext)?);
            out
        }
        None => aead.seal(context, plaintext)?,
    };
    let mut out = vec![CALENDAR_LINK_VERSION];
    out.extend(body);
    Ok(out)
}

fn open(aead: &Aead, context: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    match sealed.split_first() {
        Some((&CALENDAR_LINK_VERSION, body)) => aead.open(context, body),
        Some((version, _)) if *version > CALENDAR_LINK_VERSION => Err(CryptoError::NewerThanMe(
            format!("calendar link envelope v{version}"),
        )),
        _ => Err(CryptoError::InvalidInput(
            "not a calendar link envelope".into(),
        )),
    }
}

/// Generation `generation`'s passphrase for link `link_id` of calendar
/// `calendar_id`, sealed under the link secret.
pub fn seal_link_passphrase(
    secret: &LinkSecret,
    calendar_id: &str,
    link_id: &str,
    generation: u32,
    passphrase: &Passphrase,
) -> Result<Vec<u8>> {
    seal_link_passphrase_with(secret, calendar_id, link_id, generation, passphrase, None)
}

fn seal_link_passphrase_with(
    secret: &LinkSecret,
    calendar_id: &str,
    link_id: &str,
    generation: u32,
    passphrase: &Passphrase,
    nonce: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let context = context(calendar_id, link_id, generation)?;
    let aead = aead(
        secret.as_bytes(),
        crate::labels::CALENDAR_LINK_PASSPHRASE_V1,
        &context,
    )?;
    seal(&aead, &context, nonce, &passphrase.to_bytes())
}

/// Opens what [`seal_link_passphrase`] sealed; refused under any other
/// secret, calendar, link or generation.
pub fn open_link_passphrase(
    secret: &LinkSecret,
    calendar_id: &str,
    link_id: &str,
    generation: u32,
    sealed: &[u8],
) -> Result<Passphrase> {
    let context = context(calendar_id, link_id, generation)?;
    let aead = aead(
        secret.as_bytes(),
        crate::labels::CALENDAR_LINK_PASSPHRASE_V1,
        &context,
    )?;
    let bytes = open(&aead, &context, sealed)?;
    if bytes.len() != PASSPHRASE_BYTES {
        return Err(CryptoError::InvalidInput(
            "not a calendar passphrase".into(),
        ));
    }
    Passphrase::from_bytes(&bytes)
}

/// The link secret, sealed under generation `generation`'s passphrase, for
/// the calendar's members.
pub fn seal_link_secret(
    passphrase: &Passphrase,
    calendar_id: &str,
    link_id: &str,
    generation: u32,
    secret: &LinkSecret,
) -> Result<Vec<u8>> {
    seal_link_secret_with(passphrase, calendar_id, link_id, generation, secret, None)
}

fn seal_link_secret_with(
    passphrase: &Passphrase,
    calendar_id: &str,
    link_id: &str,
    generation: u32,
    secret: &LinkSecret,
    nonce: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let context = context(calendar_id, link_id, generation)?;
    let aead = aead(
        &passphrase.to_bytes(),
        crate::labels::CALENDAR_LINK_SECRET_V1,
        &context,
    )?;
    seal(&aead, &context, nonce, secret.as_bytes())
}

/// Opens what [`seal_link_secret`] sealed.
pub fn open_link_secret(
    passphrase: &Passphrase,
    calendar_id: &str,
    link_id: &str,
    generation: u32,
    sealed: &[u8],
) -> Result<LinkSecret> {
    let context = context(calendar_id, link_id, generation)?;
    let aead = aead(
        &passphrase.to_bytes(),
        crate::labels::CALENDAR_LINK_SECRET_V1,
        &context,
    )?;
    LinkSecret::from_bytes(&open(&aead, &context, sealed)?)
}

/// Base64 for the wire.
pub fn encode(sealed: &[u8]) -> String {
    STANDARD.encode(sealed)
}

pub fn decode(text: &str) -> Result<Vec<u8>> {
    Ok(STANDARD.decode(text)?)
}

/// Fixed-nonce sealing, for checked-in vectors only.
#[cfg(feature = "test-vectors")]
pub mod vectors {
    use super::*;

    pub fn seal_link_passphrase(
        secret: &LinkSecret,
        calendar_id: &str,
        link_id: &str,
        generation: u32,
        passphrase: &Passphrase,
        nonce: &[u8],
    ) -> Result<Vec<u8>> {
        seal_link_passphrase_with(
            secret,
            calendar_id,
            link_id,
            generation,
            passphrase,
            Some(nonce),
        )
    }

    pub fn seal_link_secret(
        passphrase: &Passphrase,
        calendar_id: &str,
        link_id: &str,
        generation: u32,
        secret: &LinkSecret,
        nonce: &[u8],
    ) -> Result<Vec<u8>> {
        seal_link_secret_with(
            passphrase,
            calendar_id,
            link_id,
            generation,
            secret,
            Some(nonce),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_opens_its_generations_passphrase_and_nothing_else() {
        let secret = LinkSecret::generate();
        let passphrase = Passphrase::generate();
        let sealed = seal_link_passphrase(&secret, "cal", "link", 2, &passphrase).unwrap();
        assert_eq!(
            open_link_passphrase(&secret, "cal", "link", 2, &sealed)
                .unwrap()
                .as_str(),
            passphrase.as_str()
        );
        let other = LinkSecret::generate();
        for (s, cal, link, generation) in [
            (&other, "cal", "link", 2),
            (&secret, "cal2", "link", 2),
            (&secret, "cal", "link2", 2),
            (&secret, "cal", "link", 3),
        ] {
            assert!(open_link_passphrase(s, cal, link, generation, &sealed).is_err());
        }
        // A newer format is said to be newer; nonsense is refused.
        let mut newer = sealed.clone();
        newer[0] = 2;
        assert!(matches!(
            open_link_passphrase(&secret, "cal", "link", 2, &newer),
            Err(CryptoError::NewerThanMe(_))
        ));
        assert!(open_link_passphrase(&secret, "cal", "link", 2, &[]).is_err());
    }

    #[test]
    fn members_keep_the_secret_under_the_passphrase() {
        let secret = LinkSecret::generate();
        let passphrase = Passphrase::generate();
        let sealed = seal_link_secret(&passphrase, "cal", "link", 1, &secret).unwrap();
        let opened = open_link_secret(&passphrase, "cal", "link", 1, &sealed).unwrap();
        assert_eq!(opened.as_bytes(), secret.as_bytes());
        assert!(open_link_secret(&Passphrase::generate(), "cal", "link", 1, &sealed).is_err());
        assert!(open_link_secret(&passphrase, "cal", "link", 2, &sealed).is_err());
        // The URL form round-trips; the wrong length is refused.
        assert_eq!(
            LinkSecret::from_url(&secret.to_url()).unwrap().as_bytes(),
            secret.as_bytes()
        );
        assert!(LinkSecret::from_url("AAAA").is_err());
    }

    #[test]
    fn ids_are_bounded() {
        let secret = LinkSecret::generate();
        let passphrase = Passphrase::generate();
        assert!(seal_link_passphrase(&secret, "", "link", 1, &passphrase).is_err());
        assert!(seal_link_passphrase(&secret, &"x".repeat(256), "link", 1, &passphrase).is_err());
    }
}
