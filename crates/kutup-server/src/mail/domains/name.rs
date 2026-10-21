//! A custom domain's name as it is added (docs/plans/mail-custom-domains.md
//! §2): normalized to lowercase ASCII (IDNA), then refused when it can't be
//! an account's own mail domain.

/// Why a name was refused, for the API's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Not a valid DNS name (or longer than 253 bytes).
    Invalid,
    /// An IP address, not a name.
    Address,
    /// This server's own domain, or a name under it.
    ServerDomain,
    /// A public suffix (`com`, `co.uk`, `github.io`): nobody owns it alone.
    PublicSuffix,
}

impl Refusal {
    pub fn code(self) -> &'static str {
        match self {
            Refusal::Invalid => "invalidDomain",
            Refusal::Address => "domainIsAddress",
            Refusal::ServerDomain => "serverDomain",
            Refusal::PublicSuffix => "publicSuffix",
        }
    }
}

/// `input` as stored: trimmed, without a trailing dot, lowercase, its
/// internationalized labels in A-label form, and checked.
pub fn normalize(input: &str, server_name: &str) -> Result<String, Refusal> {
    let trimmed = input.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return Err(Refusal::Invalid);
    }
    if trimmed.parse::<std::net::IpAddr>().is_ok()
        || trimmed
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::Ipv6Addr>()
            .is_ok()
    {
        return Err(Refusal::Address);
    }
    let name = idna::domain_to_ascii(trimmed).map_err(|_| Refusal::Invalid)?;
    kutup_crypto::mail_address::check_domain(&name).map_err(|_| Refusal::Invalid)?;
    // A name of digits and dots alone reads as an address to too much.
    if name
        .split('.')
        .all(|label| label.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(Refusal::Address);
    }
    let server = server_name.to_ascii_lowercase();
    if name == server || name.ends_with(&format!(".{server}")) {
        return Err(Refusal::ServerDomain);
    }
    if is_public_suffix(&name) {
        return Err(Refusal::PublicSuffix);
    }
    Ok(name)
}

/// Whether `name` is itself a public suffix, in the list's ICANN or private
/// section (an unknown top-level name counts as one, as the list's `*` rule
/// says).
fn is_public_suffix(name: &str) -> bool {
    match psl::suffix(name.as_bytes()) {
        Some(suffix) => suffix.as_bytes() == name.as_bytes(),
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER: &str = "kutup.dev";

    #[test]
    fn names_are_normalized() {
        assert_eq!(normalize("Example.COM.", SERVER).unwrap(), "example.com");
        assert_eq!(
            normalize("  mail.example.org ", SERVER).unwrap(),
            "mail.example.org"
        );
        assert_eq!(
            normalize("bücher.example.com", SERVER).unwrap(),
            "xn--bcher-kva.example.com"
        );
        assert_eq!(
            normalize("my.github.io.example", SERVER).unwrap(),
            "my.github.io.example"
        );
    }

    #[test]
    fn what_no_account_owns_is_refused() {
        for (name, refusal) in [
            ("", Refusal::Invalid),
            (".", Refusal::Invalid),
            ("exa mple.com", Refusal::Invalid),
            ("-bad.example.com", Refusal::Invalid),
            ("a..b.com", Refusal::Invalid),
            ("192.0.2.1", Refusal::Address),
            ("[2001:db8::1]", Refusal::Address),
            ("2001:db8::1", Refusal::Address),
            ("kutup.dev", Refusal::ServerDomain),
            ("Mail.Kutup.Dev", Refusal::ServerDomain),
            ("com", Refusal::PublicSuffix),
            ("co.uk", Refusal::PublicSuffix),
            ("github.io", Refusal::PublicSuffix),
        ] {
            assert_eq!(normalize(name, SERVER), Err(refusal), "{name:?}");
        }
        let long = format!("{}.com", vec!["a".repeat(60); 5].join("."));
        assert_eq!(normalize(&long, SERVER), Err(Refusal::Invalid));
    }

    #[test]
    fn a_name_under_a_private_suffix_is_its_owners() {
        assert_eq!(
            normalize("alice.github.io", SERVER).unwrap(),
            "alice.github.io"
        );
        assert_eq!(normalize("example.co.uk", SERVER).unwrap(), "example.co.uk");
        // A lookalike of the server's name is someone else's.
        assert_eq!(normalize("notkutup.dev", SERVER).unwrap(), "notkutup.dev");
    }
}
