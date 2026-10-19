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
/// of its own, so the provider is installed here too: a client built where
/// `main` didn't run (a unit test) still gets it.
pub fn client_builder() -> reqwest::ClientBuilder {
    install_crypto_provider();
    reqwest::Client::builder()
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

    /// A real handshake: a client from [`super::client_builder`] against a
    /// rustls server on the same provider negotiates X25519MLKEM768, as it
    /// does with any peer that offers it.
    #[tokio::test]
    async fn a_client_negotiates_the_post_quantum_exchange() {
        use rustls::pki_types::pem::PemObject as _;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        super::install_crypto_provider();
        let certificates =
            CertificateDer::pem_slice_iter(include_bytes!("../tests/fixtures/tls/leaf.pem"))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        let key =
            PrivateKeyDer::from_pem_slice(include_bytes!("../tests/fixtures/tls/leaf-key.pem"))
                .unwrap();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let group = stream
                .get_ref()
                .1
                .negotiated_key_exchange_group()
                .map(|group| format!("{:?}", group.name()))
                .unwrap_or_default();
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            while !request.windows(4).any(|end| end == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{group}",
                group.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            let _ = stream.shutdown().await;
        });
        let client = super::client_builder()
            .add_root_certificate(
                reqwest::Certificate::from_pem(include_bytes!("../tests/fixtures/tls/ca.pem"))
                    .unwrap(),
            )
            .resolve("localhost", address)
            .build()
            .unwrap();
        let group = client
            .get(format!("https://localhost:{}/", address.port()))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(group, "X25519MLKEM768");
    }
}
