use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use kutup_federation_proto::validate_server_name;
use url::Url;

use crate::config::Config;

/// Validated configuration for the unpublished unified federation stack.
/// Legacy Chat variables are intentionally never consulted here.
#[derive(Clone)]
pub(crate) struct FederationRuntimeConfig {
    pub server_name: String,
    pub api_base: String,
    pub signing_key: SigningKey,
    pub next_signing_key: Option<SigningKey>,
    pub allow_private_test_network: bool,
    /// The key was made by this server (`crate::server_keys`), not configured.
    pub generated: bool,
}

impl FederationRuntimeConfig {
    pub fn from_server_config(config: &Config) -> anyhow::Result<Option<Self>> {
        Self::parse(
            &config.federation_server_name,
            &config.server_url,
            &config.federation_signing_key,
            &config.federation_next_signing_key,
            config.federation_test_allow_private,
            &config.app_env,
        )
    }

    /// The identity a server uses when its operator configures no federation:
    /// named after its Chat server name, with a key it made and stored
    /// (`crate::server_keys`). Groups need it even among local members, since
    /// clients verify each ordering server's signed policy history. It
    /// admits no peer by itself: federation admission is unchanged.
    ///
    /// Returns the server name and API base, or `None` when the configured
    /// `SERVER_URL` cannot anchor an identity (plain HTTP in production).
    pub fn generated_identity(config: &Config) -> anyhow::Result<Option<(String, String)>> {
        Ok(generated_identity(
            &config.chat_server_name,
            &config.server_url,
            &config.app_env,
        ))
    }

    pub fn with_generated_key(
        server_name: String,
        api_base: String,
        signing_key: SigningKey,
    ) -> Self {
        Self {
            server_name,
            api_base,
            signing_key,
            next_signing_key: None,
            allow_private_test_network: false,
            generated: true,
        }
    }

    fn parse(
        server_name: &str,
        api_base: &str,
        signing_key: &str,
        next_signing_key: &str,
        allow_private_test_network: bool,
        app_env: &str,
    ) -> anyhow::Result<Option<Self>> {
        if signing_key.is_empty() {
            if !server_name.is_empty() || !next_signing_key.is_empty() || allow_private_test_network
            {
                anyhow::bail!(
                    "FEDERATION_SIGNING_KEY is required when another FEDERATION_* setting is configured"
                );
            }
            return Ok(None);
        }
        if server_name.is_empty() {
            anyhow::bail!("FEDERATION_SERVER_NAME is required with FEDERATION_SIGNING_KEY");
        }
        validate_server_name(server_name).map_err(anyhow::Error::msg)?;
        if allow_private_test_network && app_env != "test" {
            anyhow::bail!("FEDERATION_TEST_ALLOW_PRIVATE may only be enabled with APP_ENV=test");
        }
        let api_base = canonical_api_base(api_base, allow_private_test_network)?;
        let signing_key = decode_signing_key("FEDERATION_SIGNING_KEY", signing_key)?;
        let next_signing_key = if next_signing_key.is_empty() {
            None
        } else {
            Some(decode_signing_key(
                "FEDERATION_NEXT_SIGNING_KEY",
                next_signing_key,
            )?)
        };
        if next_signing_key
            .as_ref()
            .is_some_and(|next| next.verifying_key() == signing_key.verifying_key())
        {
            anyhow::bail!("FEDERATION_NEXT_SIGNING_KEY must introduce a different identity key");
        }
        Ok(Some(Self {
            server_name: server_name.into(),
            api_base,
            signing_key,
            next_signing_key,
            allow_private_test_network,
            generated: false,
        }))
    }

    pub fn ensure_normal_startup(&self) -> anyhow::Result<()> {
        if self.next_signing_key.is_some() {
            anyhow::bail!(
                "FEDERATION_NEXT_SIGNING_KEY is accepted only by `federation-identity rotate`"
            );
        }
        Ok(())
    }

    pub fn require_next_signing_key(&self) -> anyhow::Result<&SigningKey> {
        self.next_signing_key.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "FEDERATION_NEXT_SIGNING_KEY is required by `federation-identity rotate`"
            )
        })
    }
}

fn generated_identity(
    server_name: &str,
    server_url: &str,
    app_env: &str,
) -> Option<(String, String)> {
    // Plain HTTP anchors an identity only outside production (development
    // stacks); a production identity needs its canonical HTTPS address.
    match canonical_api_base(server_url, app_env != "production") {
        Ok(api_base) => Some((server_name.to_string(), api_base)),
        Err(error) => {
            tracing::warn!(
                %error,
                "no server identity: set SERVER_URL to this server's canonical HTTPS address to enable Chat groups"
            );
            None
        }
    }
}

fn decode_signing_key(name: &str, encoded: &str) -> anyhow::Result<SigningKey> {
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| anyhow::anyhow!("{name} must be canonical padded base64"))?;
    if STANDARD.encode(&decoded) != encoded {
        anyhow::bail!("{name} must be canonical padded base64");
    }
    let seed: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} must decode to exactly 32 bytes"))?;
    Ok(SigningKey::from_bytes(&seed))
}

fn canonical_api_base(value: &str, allow_http_for_test: bool) -> anyhow::Result<String> {
    let parsed = Url::parse(value).map_err(|_| anyhow::anyhow!("SERVER_URL must be absolute"))?;
    let scheme_allowed =
        parsed.scheme() == "https" || (allow_http_for_test && parsed.scheme() == "http");
    if !scheme_allowed
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        anyhow::bail!("SERVER_URL must be canonical HTTPS without credentials, query, or fragment");
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("SERVER_URL must contain a DNS host"))?;
    validate_server_name(host).map_err(anyhow::Error::msg)?;
    if parsed.port() == Some(0) {
        anyhow::bail!("SERVER_URL cannot use port zero");
    }
    let mut canonical = format!("{}://{host}", parsed.scheme());
    if let Some(port) = parsed.port() {
        canonical.push(':');
        canonical.push_str(&port.to_string());
    }
    let path = parsed.path().trim_end_matches('/');
    if !path.is_empty() {
        canonical.push_str(path);
    }
    if canonical != value {
        anyhow::bail!("SERVER_URL must already be in canonical form");
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(byte: u8) -> String {
        STANDARD.encode([byte; 32])
    }

    #[test]
    fn empty_generic_configuration_disables_only_the_new_stack() {
        assert!(FederationRuntimeConfig::parse(
            "",
            "http://kutup.local",
            "",
            "",
            false,
            "production",
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn generated_identity_uses_the_chat_name_and_needs_https_in_production() {
        assert_eq!(
            generated_identity("kutup.example", "https://kutup.example", "production"),
            Some(("kutup.example".into(), "https://kutup.example".into()))
        );
        assert_eq!(
            generated_identity("kutup.example", "http://kutup.example", "production"),
            None
        );
        assert_eq!(
            generated_identity("kutup.local", "http://kutup.local", "development"),
            Some(("kutup.local".into(), "http://kutup.local".into()))
        );
        assert_eq!(
            generated_identity("kutup.local", "https://kutup.local/", "development"),
            None
        );
    }

    #[test]
    fn production_configuration_is_explicit_and_https_only() {
        let config = FederationRuntimeConfig::parse(
            "alpha.example",
            "https://edge.example/api/fed",
            &seed(1),
            "",
            false,
            "production",
        )
        .unwrap()
        .unwrap();
        assert_eq!(config.server_name, "alpha.example");
        assert_eq!(config.api_base, "https://edge.example/api/fed");
        config.ensure_normal_startup().unwrap();

        for (domain, url) in [
            ("Alpha.example", "https://edge.example"),
            ("alpha.example", "http://edge.example"),
            ("alpha.example", "https://edge.example/"),
            ("alpha.example", "https://edge.example:443"),
        ] {
            assert!(
                FederationRuntimeConfig::parse(domain, url, &seed(1), "", false, "production",)
                    .is_err()
            );
        }
    }

    #[test]
    fn private_http_escape_hatch_is_test_only_and_rotation_only_key_is_separate() {
        assert!(FederationRuntimeConfig::parse(
            "alpha.test",
            "http://edge.test:3000",
            &seed(1),
            &seed(2),
            true,
            "production",
        )
        .is_err());
        let config = FederationRuntimeConfig::parse(
            "alpha.test",
            "http://edge.test:3000",
            &seed(1),
            &seed(2),
            true,
            "test",
        )
        .unwrap()
        .unwrap();
        assert!(config.ensure_normal_startup().is_err());
        config.require_next_signing_key().unwrap();
    }

    #[test]
    fn malformed_or_ambiguous_key_configuration_fails() {
        assert!(FederationRuntimeConfig::parse(
            "alpha.example",
            "https://alpha.example",
            "not-base64",
            "",
            false,
            "production",
        )
        .is_err());
        assert!(FederationRuntimeConfig::parse(
            "alpha.example",
            "https://alpha.example",
            &seed(1),
            &seed(1),
            false,
            "production",
        )
        .is_err());
        assert!(FederationRuntimeConfig::parse(
            "alpha.example",
            "https://alpha.example",
            "",
            &seed(2),
            false,
            "production",
        )
        .is_err());
    }
}
