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
//! The owner keeps the link secret, sealed to its own account key
//! ([`seal_owner_link_secret`], a [`CalendarLinkSecretEnvelopeV1`] from the
//! owner to itself), so it can show the URL again and, when the key rotates,
//! seal the new passphrase for the link. Never under the calendar's
//! passphrase: every member holds that, and a removed member's old
//! passphrase would open the secret, and with it every later generation.
//!
//! A keyed link's page proves it holds the secret before the server hands
//! over anything sealed ([`link_access_proof`]); the server keeps only the
//! proof's hash. Busy-only links carry no secret and need none of this.
//!
//! The passphrase envelopes are `version ‖ nonce ‖ ciphertext`
//! (XChaCha20-Poly1305, suite V1), with the context (calendar id, link id,
//! generation) as the HKDF info and the associated data.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use zeroize::Zeroizing;

use crate::account_ref::AccountRef;
use crate::calendar::{Passphrase, PASSPHRASE_BYTES};
use crate::error::{CryptoError, Result};
use crate::identity::AccountIdentityKeysV1;
pub use crate::named_share::CalendarLinkSecretEnvelopeV1;
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

/// The envelope's version (its "number").
pub const OWNER_SECRET_VERSION: u32 = 1;

/// The link secret, sealed by `owner` to itself (its account key), bound to
/// the link.
pub fn seal_owner_link_secret(
    secret: &LinkSecret,
    link_id: &str,
    owner: &AccountRef,
    identity: &AccountIdentityKeysV1,
) -> Result<CalendarLinkSecretEnvelopeV1> {
    let incarnation = identity.incarnation_id();
    CalendarLinkSecretEnvelopeV1::seal(
        secret.as_bytes(),
        link_id,
        OWNER_SECRET_VERSION,
        owner,
        &incarnation,
        identity.drive_signing_key(),
        owner,
        &incarnation,
        &identity.drive_xwing_public_key(),
    )
}

/// Opens what [`seal_owner_link_secret`] sealed: refused unless the owner's
/// own key signed it for this link.
pub fn open_owner_link_secret(
    envelope: &CalendarLinkSecretEnvelopeV1,
    link_id: &str,
    owner: &AccountRef,
    identity: &AccountIdentityKeysV1,
) -> Result<LinkSecret> {
    let incarnation = identity.incarnation_id();
    let bytes = Zeroizing::new(envelope.open(
        link_id,
        OWNER_SECRET_VERSION,
        owner,
        &incarnation,
        &identity.drive_signing_public_key(),
        owner,
        &incarnation,
        identity.drive_xwing_private_key(),
    )?);
    LinkSecret::from_bytes(&bytes)
}

/// What a keyed link's page shows the server to be served the link: derived
/// from the secret and bound to the link, so the link's id alone opens
/// nothing. The server keeps its SHA-256.
pub fn link_access_proof(secret: &LinkSecret, link_id: &str) -> Result<[u8; 32]> {
    if link_id.is_empty() || link_id.len() > 255 {
        return Err(CryptoError::InvalidInput(
            "a link id is 1 to 255 bytes".into(),
        ));
    }
    let mut context = vec![CALENDAR_LINK_VERSION, link_id.len() as u8];
    context.extend_from_slice(link_id.as_bytes());
    let mut proof = [0u8; 32];
    kdf(
        Suite::V1,
        secret.as_bytes(),
        crate::labels::CALENDAR_LINK_ACCESS_V1,
        &context,
        &mut proof,
    )?;
    Ok(proof)
}

/// The proof as a request header carries it: base64url without padding.
pub fn link_access_proof_text(secret: &LinkSecret, link_id: &str) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(link_access_proof(secret, link_id)?))
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
    fn the_owner_keeps_the_secret_on_its_own_key() {
        use crate::account_roots::IdentityRoot;
        let keys = |byte: u8| {
            AccountIdentityKeysV1::derive(&IdentityRoot::from_bytes([byte; 32])).unwrap()
        };
        let (owner_keys, member_keys) = (keys(1), keys(2));
        let owner: AccountRef = "aci:3b0f6a52-7c1e-4d8a-9f2b-5e6c7d8a9b0c@kutup.dev"
            .parse()
            .unwrap();
        let member: AccountRef = "aci:9c4b2f0e-1d3a-4e5b-8c6d-7e8f9a0b1c2d@kutup.dev"
            .parse()
            .unwrap();
        let link = "0b6e1f3a-2c4d-4e5f-8a9b-0c1d2e3f4a5b";
        let secret = LinkSecret::generate();
        let sealed = seal_owner_link_secret(&secret, link, &owner, &owner_keys).unwrap();
        let opened = open_owner_link_secret(&sealed, link, &owner, &owner_keys).unwrap();
        assert_eq!(opened.as_bytes(), secret.as_bytes());
        // Nobody else opens it, nor under another link.
        assert!(open_owner_link_secret(&sealed, link, &member, &member_keys).is_err());
        assert!(open_owner_link_secret(
            &sealed,
            "2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e",
            &owner,
            &owner_keys
        )
        .is_err());
        // The URL form round-trips; the wrong length is refused.
        assert_eq!(
            LinkSecret::from_url(&secret.to_url()).unwrap().as_bytes(),
            secret.as_bytes()
        );
        assert!(LinkSecret::from_url("AAAA").is_err());
    }

    #[test]
    fn the_access_proof_is_the_links_alone() {
        let secret = LinkSecret::generate();
        let proof = link_access_proof(&secret, "link").unwrap();
        assert_eq!(proof, link_access_proof(&secret, "link").unwrap());
        assert_ne!(proof, link_access_proof(&secret, "link2").unwrap());
        assert_ne!(
            proof,
            link_access_proof(&LinkSecret::generate(), "link").unwrap()
        );
        assert!(link_access_proof(&secret, "").is_err());
    }

    #[test]
    fn ids_are_bounded() {
        let secret = LinkSecret::generate();
        let passphrase = Passphrase::generate();
        assert!(seal_link_passphrase(&secret, "", "link", 1, &passphrase).is_err());
        assert!(seal_link_passphrase(&secret, &"x".repeat(256), "link", 1, &passphrase).is_err());
    }
}
