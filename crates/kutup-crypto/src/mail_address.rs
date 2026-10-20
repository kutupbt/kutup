//! The canonical form of a mail address (docs/plans/mail-custom-domains.md,
//! "Settled"): what address keys and key lists bind, on the server's own
//! domain and on custom domains alike.
//!
//! - The local part takes what Proton lets an address be made of: lowercase
//!   letters, digits, `.`, `_` and `-`, with no dot at either end and no two
//!   dots in a row, at most 64 bytes. No `+`: it starts a sub-address tag,
//!   which delivery strips and no address carries.
//! - The domain is a lowercase DNS name in ASCII (an internationalized name
//!   in its IDNA A-label form, `xn--…`): labels of letters, digits and inner
//!   hyphens, at most 63 bytes each and 253 in all, no trailing dot.
//!
//! Folding (`. _ -` on the server's own names) is a separate step, applied
//! only there; custom domains are compared by this form alone, as Proton
//! compares them (lowercase only).
//!
//! Every address valid under the account-name rule
//! (`named_share::canonical_account`) is valid here, so no stored key or key
//! list changes form.

use crate::error::{CryptoError, Result};

pub const MAX_LOCAL_LEN: usize = 64;
pub const MAX_DOMAIN_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

fn invalid(what: &str) -> CryptoError {
    CryptoError::InvalidInput(format!("mail address is not canonical: {what}"))
}

/// `value` when it is a canonical address, else why not. Nothing is
/// normalized: a caller lowercases (and converts a domain to its A-label)
/// before, so a stored address and its key's user id are byte-equal.
pub fn canonical(value: &str) -> Result<String> {
    let (local, domain) = value.split_once('@').ok_or_else(|| invalid("no @"))?;
    if domain.contains('@') {
        return Err(invalid("more than one @"));
    }
    check_local(local)?;
    check_domain(domain)?;
    Ok(value.to_owned())
}

/// The local part's rule alone (an address being made, before its domain is
/// chosen).
pub fn check_local(local: &str) -> Result<()> {
    if local.is_empty() || local.len() > MAX_LOCAL_LEN {
        return Err(invalid("the local part is empty or longer than 64 bytes"));
    }
    if !local
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
    {
        return Err(invalid(
            "the local part takes lowercase letters, digits, . _ and - only",
        ));
    }
    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return Err(invalid("a dot at an end of the local part, or two in a row"));
    }
    Ok(())
}

/// The domain's rule alone (a custom domain being added).
pub fn check_domain(domain: &str) -> Result<()> {
    if domain.is_empty() || domain.len() > MAX_DOMAIN_LEN {
        return Err(invalid("the domain is empty or longer than 253 bytes"));
    }
    for label in domain.split('.') {
        if label.is_empty() || label.len() > MAX_LABEL_LEN {
            return Err(invalid("an empty domain label, or one over 63 bytes"));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(invalid(
                "a domain label takes lowercase letters, digits and - only",
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(invalid("a domain label starts or ends with -"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typical_addresses_are_canonical() {
        for ok in [
            "alice@kutup.dev",
            "john.doe@example.com",
            "a_b-c@sub.example.co.uk",
            "x@a.test",
            "info@xn--bcher-kva.example",
            "u1@kutup.localhost",
            "admin@localhost",
        ] {
            assert_eq!(canonical(ok).unwrap(), ok, "{ok}");
        }
        let longest = format!("{}@{}", "a".repeat(64), "b".repeat(63));
        assert!(canonical(&longest).is_ok());
    }

    #[test]
    fn everything_else_is_refused() {
        for bad in [
            "",
            "alice",
            "@kutup.dev",
            "alice@",
            "a@b@c",
            "Alice@kutup.dev",
            "alice@Kutup.dev",
            "alice+tag@kutup.dev",
            ".alice@kutup.dev",
            "alice.@kutup.dev",
            "al..ice@kutup.dev",
            "al ice@kutup.dev",
            " alice@kutup.dev",
            "alice@kutup.dev.",
            "alice@.kutup.dev",
            "alice@kutup..dev",
            "alice@-kutup.dev",
            "alice@kutup-.dev",
            "alice@kutup_dev.com",
            "alice@bücher.example",
            "ali\u{0}ce@kutup.dev",
        ] {
            assert!(canonical(bad).is_err(), "{bad:?}");
        }
        assert!(canonical(&format!("{}@kutup.dev", "a".repeat(65))).is_err());
        assert!(canonical(&format!("a@{}.dev", "b".repeat(64))).is_err());
        let long_domain = vec!["a".repeat(63); 4].join(".");
        assert_eq!(long_domain.len(), 255);
        assert!(canonical(&format!("a@{long_domain}")).is_err());
    }

    /// Whatever the account-name rule took, this rule takes.
    #[test]
    fn every_account_form_address_stays_canonical() {
        for name in ["alice", "a_b", "a-b", "_x_", "-y-", "x9", "abc"] {
            for domain in ["kutup.dev", "a.test", "kutup.localhost"] {
                let address = format!("{name}@{domain}");
                assert!(
                    crate::named_share::canonical_account(&address).is_ok(),
                    "{address}"
                );
                assert!(canonical(&address).is_ok(), "{address}");
            }
        }
    }
}
