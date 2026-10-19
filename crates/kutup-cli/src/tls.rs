//! Outbound TLS: rustls with aws-lc-rs, the only provider in the build, as
//! the process default. It offers the post-quantum hybrid X25519MLKEM768 key
//! exchange first, so every HTTPS call this process makes (federation, Web
//! Push, outside keys, maps and the rest) negotiates it with any peer that
//! supports it, and falls back to X25519 or the NIST curves otherwise.

/// Installs the provider as the process default; call it first in `main`.
pub fn install_crypto_provider() {
    // Already installed (a test that runs main's setup twice): keep it.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// A reqwest client builder on that provider. reqwest is built without one
/// of its own, so the provider is installed here too, wherever the client is
/// built.
// The one place a client is built (clippy.toml).
#[allow(clippy::disallowed_methods)]
pub fn client_builder() -> reqwest::blocking::ClientBuilder {
    install_crypto_provider();
    reqwest::blocking::Client::builder()
}

#[cfg(test)]
mod tests {
    use rustls::NamedGroup;

    #[test]
    fn the_process_default_offers_the_post_quantum_exchange_first() {
        super::install_crypto_provider();
        let provider = rustls::crypto::CryptoProvider::get_default().expect("installed");
        let groups: Vec<NamedGroup> = provider
            .kx_groups
            .iter()
            .map(|group| group.name())
            .collect();
        assert_eq!(
            groups.first(),
            Some(&NamedGroup::X25519MLKEM768),
            "{groups:?}"
        );
        assert!(groups.contains(&NamedGroup::X25519));
    }
}
