//! One live-location update (docs/plans/maps.md "Live location").
//!
//! A live location is a short-lived stream: the sharer's app makes a random
//! stream id and key, hands them to the conversation in one end-to-end
//! encrypted Chat message, then writes each new position, sealed here, into
//! the stream's single slot on its server. The server keeps only the latest
//! update and never learns whose stream it is.
//!
//! Wire format (88 bytes, always the same size):
//!
//! ```text
//! magic "KUTPLL1\0" (8) | counter u64 BE (8) | nonce (24) | ciphertext (32 + 16 tag)
//! ```
//!
//! The plaintext is fixed-size: latitude f64, longitude f64 (big-endian),
//! accuracy in metres u32, the reading's time in Unix milliseconds u64, and
//! four zero bytes. The AEAD (XChaCha20-Poly1305) authenticates the magic,
//! the stream id and the counter, so an update cannot be moved to another
//! stream or replayed in place of a newer one.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use dryoc::rng::copy_randombytes;

use crate::error::{CryptoError, Result};

const MAGIC: &[u8; 8] = b"KUTPLL1\0";
pub const KEY_LEN: usize = 32;
pub const STREAM_ID_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const PLAINTEXT_LEN: usize = 32;
const TAG_LEN: usize = 16;
/// The whole sealed update.
pub const ENVELOPE_LEN: usize = 8 + 8 + NONCE_LEN + PLAINTEXT_LEN + TAG_LEN;
/// Accuracy beyond this is not a location worth sharing.
pub const MAX_ACCURACY_M: u32 = 100_000;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LiveLocationPoint {
    pub lat: f64,
    pub lon: f64,
    /// The reading's accuracy radius in metres (0 when unknown).
    pub accuracy_m: u32,
    /// When the position was read, Unix milliseconds.
    pub at_ms: u64,
}

impl LiveLocationPoint {
    fn validate(&self) -> Result<()> {
        if !self.lat.is_finite()
            || !self.lon.is_finite()
            || !(-90.0..=90.0).contains(&self.lat)
            || !(-180.0..=180.0).contains(&self.lon)
            || self.accuracy_m > MAX_ACCURACY_M
            || self.at_ms == 0
        {
            return Err(CryptoError::InvalidInput(
                "live location point is out of range".into(),
            ));
        }
        Ok(())
    }

    fn encode(&self) -> [u8; PLAINTEXT_LEN] {
        let mut out = [0u8; PLAINTEXT_LEN];
        out[0..8].copy_from_slice(&self.lat.to_be_bytes());
        out[8..16].copy_from_slice(&self.lon.to_be_bytes());
        out[16..20].copy_from_slice(&self.accuracy_m.to_be_bytes());
        out[20..28].copy_from_slice(&self.at_ms.to_be_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PLAINTEXT_LEN || bytes[28..] != [0, 0, 0, 0] {
            return Err(CryptoError::AuthFailed);
        }
        let point = Self {
            lat: f64::from_be_bytes(bytes[0..8].try_into().expect("8 bytes")),
            lon: f64::from_be_bytes(bytes[8..16].try_into().expect("8 bytes")),
            accuracy_m: u32::from_be_bytes(bytes[16..20].try_into().expect("4 bytes")),
            at_ms: u64::from_be_bytes(bytes[20..28].try_into().expect("8 bytes")),
        };
        point.validate().map_err(|_| CryptoError::AuthFailed)?;
        Ok(point)
    }
}

fn aad(stream_id: &[u8; STREAM_ID_LEN], counter: u64) -> [u8; 8 + STREAM_ID_LEN + 8] {
    let mut out = [0u8; 8 + STREAM_ID_LEN + 8];
    out[..8].copy_from_slice(MAGIC);
    out[8..8 + STREAM_ID_LEN].copy_from_slice(stream_id);
    out[8 + STREAM_ID_LEN..].copy_from_slice(&counter.to_be_bytes());
    out
}

fn cipher(key: &[u8]) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidLength {
        expected: KEY_LEN,
        got: key.len(),
    })
}

fn stream_id_of(stream_id: &[u8]) -> Result<[u8; STREAM_ID_LEN]> {
    stream_id
        .try_into()
        .map_err(|_| CryptoError::InvalidLength {
            expected: STREAM_ID_LEN,
            got: stream_id.len(),
        })
}

/// Seal update number `counter` (from 1, increasing) of a stream.
pub fn seal(
    key: &[u8],
    stream_id: &[u8],
    counter: u64,
    point: &LiveLocationPoint,
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    copy_randombytes(&mut nonce);
    seal_with_nonce(key, stream_id, counter, point, &nonce)
}

/// [`seal`] with a given nonce, for vectors.
pub fn seal_with_nonce(
    key: &[u8],
    stream_id: &[u8],
    counter: u64,
    point: &LiveLocationPoint,
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    let stream_id = stream_id_of(stream_id)?;
    if counter == 0 {
        return Err(CryptoError::InvalidInput(
            "live location updates count from 1".into(),
        ));
    }
    point.validate()?;
    let plaintext = point.encode();
    let ciphertext = cipher(key)?
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: &plaintext,
                aad: &aad(&stream_id, counter),
            },
        )
        .map_err(|_| CryptoError::Backend("live location seal".into()))?;
    let mut out = Vec::with_capacity(ENVELOPE_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&counter.to_be_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// The counter of a sealed update, read without the key (servers use it to
/// refuse an older update replacing a newer one).
pub fn counter_of(envelope: &[u8]) -> Result<u64> {
    if envelope.len() != ENVELOPE_LEN || &envelope[..8] != MAGIC {
        return Err(CryptoError::InvalidInput(
            "not a live location update".into(),
        ));
    }
    let counter = u64::from_be_bytes(envelope[8..16].try_into().expect("8 bytes"));
    if counter == 0 {
        return Err(CryptoError::InvalidInput(
            "live location updates count from 1".into(),
        ));
    }
    Ok(counter)
}

/// Open an update of this stream: its counter and position.
pub fn open(key: &[u8], stream_id: &[u8], envelope: &[u8]) -> Result<(u64, LiveLocationPoint)> {
    let stream_id = stream_id_of(stream_id)?;
    let counter = counter_of(envelope)?;
    let nonce = &envelope[16..16 + NONCE_LEN];
    let plaintext = cipher(key)?
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: &envelope[16 + NONCE_LEN..],
                aad: &aad(&stream_id, counter),
            },
        )
        .map_err(|_| CryptoError::AuthFailed)?;
    Ok((counter, LiveLocationPoint::decode(&plaintext)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];
    const STREAM: [u8; 16] = [3; 16];
    const POINT: LiveLocationPoint = LiveLocationPoint {
        lat: 40.9904,
        lon: 29.0231,
        accuracy_m: 12,
        at_ms: 1_790_000_000_000,
    };

    #[test]
    fn an_update_opens_only_with_its_key_stream_and_counter() {
        let sealed = seal(&KEY, &STREAM, 5, &POINT).unwrap();
        assert_eq!(sealed.len(), ENVELOPE_LEN);
        assert_eq!(counter_of(&sealed).unwrap(), 5);
        assert_eq!(open(&KEY, &STREAM, &sealed).unwrap(), (5, POINT));

        assert!(open(&[8; 32], &STREAM, &sealed).is_err(), "another key");
        assert!(open(&KEY, &[4; 16], &sealed).is_err(), "another stream");
        let mut replayed = sealed.clone();
        replayed[15] = 9; // claim counter 9
        assert!(
            open(&KEY, &STREAM, &replayed).is_err(),
            "counter is authenticated"
        );
        let mut tampered = sealed.clone();
        tampered[ENVELOPE_LEN - 1] ^= 1;
        assert!(open(&KEY, &STREAM, &tampered).is_err());
    }

    #[test]
    fn bad_input_is_refused() {
        assert!(seal(&KEY, &STREAM, 0, &POINT).is_err(), "counter 0");
        assert!(seal(&KEY, &STREAM, 1, &LiveLocationPoint { lat: 91.0, ..POINT }).is_err());
        assert!(seal(
            &KEY,
            &STREAM,
            1,
            &LiveLocationPoint {
                lon: f64::NAN,
                ..POINT
            }
        )
        .is_err());
        assert!(seal(&KEY, &STREAM, 1, &LiveLocationPoint { at_ms: 0, ..POINT }).is_err());
        assert!(seal(&KEY[..31], &STREAM, 1, &POINT).is_err());
        assert!(seal(&KEY, &STREAM[..15], 1, &POINT).is_err());
        assert!(counter_of(&[0u8; ENVELOPE_LEN]).is_err());
    }
}
