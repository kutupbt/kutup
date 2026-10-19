//! Mail forwarding (docs/plans/mail-forwarding.md), as Proton has it.
//!
//! An address forwards end to end to a Kutup address on this server (the
//! server turns each arriving key packet into one for the forwardee with a
//! proxy factor k, reading no message), or outside (re-sent; the address's
//! end-to-end encryption is off while any outside forwarding is on).
//!
//! k with the forwardee's secret key gives the forwarder's, so it is sealed
//! here under `MAIL_FORWARDING_KEYS` (the key's id kept beside it, the AAD
//! bound to the forwarding and both fingerprints), never logged, never
//! returned, and deleted whenever the forwarding can't resume.

use kutup_crypto::mail_forwarding::{self, ProxyInstance};
use uuid::Uuid;

use crate::opaque_setup::OpaqueSetupKeys;

/// Forwardings one address may have, and one account (user decision
/// 2026-10-19).
pub const MAX_PER_ADDRESS: i64 = 10;
pub const MAX_PER_ACCOUNT: i64 = 25;
/// A pending forwarding's activation or confirmation link lives this long.
pub const PENDING_DAYS: i64 = 7;
/// Mail that arrives with more `Received` headers than this is delivered
/// but never forwarded again (a loop through outside providers).
pub const MAX_HOPS: usize = 20;

/// Seals k under the current `MAIL_FORWARDING_KEYS` key:
/// `(key id, sealed)`. `None` without a key: end-to-end forwarding is then
/// unavailable.
pub fn seal(
    keys: &OpaqueSetupKeys,
    forwarding: Uuid,
    instance: &ProxyInstance,
) -> Option<(u16, Vec<u8>)> {
    let (id, key) = keys.current()?;
    mail_forwarding::seal_proxy_parameter(key, id, forwarding.as_bytes(), instance)
        .ok()
        .map(|sealed| (id, sealed))
}

/// Opens a sealed k. `None` when its key is gone from the configuration or
/// it was sealed for another forwarding or subkey: the forwarding is then
/// made Outdated, never an arrival error.
pub fn open(
    keys: &OpaqueSetupKeys,
    key_id: u16,
    forwarding: Uuid,
    forwarder_fingerprint: [u8; 20],
    forwardee_fingerprint: [u8; 20],
    sealed: &[u8],
) -> Option<ProxyInstance> {
    let key = keys.get(key_id)?;
    mail_forwarding::open_proxy_parameter(
        key,
        key_id,
        forwarding.as_bytes(),
        forwarder_fingerprint,
        forwardee_fingerprint,
        sealed,
    )
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn keys(entries: &str) -> OpaqueSetupKeys {
        OpaqueSetupKeys::parse(entries).unwrap()
    }

    const ONE: &str = "1:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const TWO: &str = "2:AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

    /// A rotated configuration seals with the new key and still opens what
    /// the old one sealed; with the old key gone nothing opens, and nothing
    /// panics.
    #[test]
    fn sealed_proxy_parameters_follow_the_configured_keys() {
        let forwarding = Uuid::new_v4();
        let instance = ProxyInstance {
            forwarder_fingerprint: [1u8; 20],
            forwardee_fingerprint: [2u8; 20],
            proxy_parameter: Zeroizing::new([7u8; 32]),
        };
        let (id, sealed) = seal(&keys(ONE), forwarding, &instance).unwrap();
        assert_eq!(id, 1);
        let both = keys(&format!("{ONE},{TWO}"));
        let opened = open(&both, id, forwarding, [1u8; 20], [2u8; 20], &sealed).unwrap();
        assert_eq!(*opened.proxy_parameter, [7u8; 32]);
        assert_eq!(seal(&both, forwarding, &instance).unwrap().0, 2);
        assert!(open(&keys(TWO), id, forwarding, [1u8; 20], [2u8; 20], &sealed).is_none());
        assert!(seal(&OpaqueSetupKeys::default(), forwarding, &instance).is_none());
    }
}
