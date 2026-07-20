use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use futures_util::StreamExt as _;
use kutup_federation_proto::{
    validate_server_name, FederationCapabilityId, FederationDiscoveryTransportPolicy,
    FederationDiscoveryV2, FederationFeature, FederationHttpRequest, FederationHttpResponse,
    FederationIdentityDocumentV1, FederationProtocolVersion, FederationSignatureHeaders,
    FederationSignedRequest, FederationVerifiedRequest, MAX_SIGNATURE_LIFETIME_SECONDS,
};
use reqwest::{Method, Url};
use time::OffsetDateTime;
use tokio::sync::Mutex;

use super::policy::{
    FederationAdmissionDecision, FederationAdmissionError, FederationAdmissionPreflight,
    FederationDirection, FederationPolicyFeature,
};
use super::replay::FederationReplayOutcome;
use super::trust::PinnedFederationPeer;
use super::FederationStack;
use crate::error::{AppError, AppResult};
use crate::ssrf;

pub(crate) const CONTENT_DIGEST_HEADER: &str = "content-digest";
pub(crate) const SIGNATURE_INPUT_HEADER: &str = "signature-input";
pub(crate) const SIGNATURE_HEADER: &str = "signature";
pub(crate) const FEDERATION_VERSION_HEADER: &str = "kutup-federation-version";
pub(crate) const FEDERATION_FEATURE_HEADER: &str = "kutup-federation-feature";
pub(crate) const FEDERATION_ORIGIN_HEADER: &str = "kutup-origin";
pub(crate) const FEDERATION_DESTINATION_HEADER: &str = "kutup-destination";

const DISCOVERY_PATH: &str = "/.well-known/kutup/federation.json";
const IDENTITY_PATH_PREFIX: &str = "/.well-known/kutup/federation/identity/";
const MAX_DISCOVERY_BYTES: usize = 256 * 1024;
const MAX_IDENTITY_DOCUMENT_BYTES: usize = 256 * 1024;
const MAX_IDENTITY_SEQUENCE: u64 = 1024;
const NEGATIVE_CACHE_SECONDS: i64 = 15;
const DEFAULT_HTTP_TIMEOUT: StdDuration = StdDuration::from_secs(30);

#[derive(Debug, Clone)]
pub(crate) struct ResolvedFederationPeer {
    pub api_base: String,
    pub public_key: [u8; 32],
}

#[derive(Debug, Clone)]
struct CachedDiscovery {
    discovery: FederationDiscoveryV2,
}

#[derive(Debug, Clone)]
struct NegativeDiscovery {
    error: String,
    retry_at: i64,
}

#[derive(Default)]
pub(super) struct FederationTransportState {
    positive: Mutex<HashMap<String, CachedDiscovery>>,
    negative: Mutex<HashMap<String, NegativeDiscovery>>,
    domain_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

#[derive(Debug, Clone)]
pub(crate) struct FederationRequestSpec {
    pub feature: FederationFeature,
    pub method: Method,
    /// Feature-owned fixed endpoint beneath the authenticated API base.
    pub path: String,
    /// Raw query without a leading `?`.
    pub query: Option<String>,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    pub request_id: String,
    pub extra_headers: Vec<(HeaderName, HeaderValue)>,
    pub response_limit: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct AuthenticatedFederationResponse {
    pub status: StatusCode,
    pub body: Vec<u8>,
}

pub(crate) struct AuthenticatedFederationRequest {
    pub verified: FederationVerifiedRequest,
}

impl AuthenticatedFederationRequest {
    pub fn origin(&self) -> &str {
        &self.verified.request.origin
    }

    pub fn destination(&self) -> &str {
        &self.verified.request.destination
    }
}

impl FederationStack {
    pub(crate) async fn resolve_peer(
        &self,
        domain: &str,
        feature: FederationFeature,
        direction: FederationDirection,
        now: OffsetDateTime,
    ) -> anyhow::Result<ResolvedFederationPeer> {
        validate_server_name(domain).map_err(anyhow::Error::msg)?;
        if domain == self.server_name() {
            anyhow::bail!("federation peer must differ from the local server");
        }
        let policy_feature = policy_feature(feature);
        match self
            .policy
            .check_admission(domain, policy_feature, direction)
            .await?
        {
            FederationAdmissionPreflight::Allowed => {}
            FederationAdmissionPreflight::Denied { reason } => {
                return Err(FederationAdmissionError(reason).into())
            }
        }

        let lock = {
            let mut locks = self.transport.domain_locks.lock().await;
            locks
                .entry(domain.to_owned())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        let _guard = lock.lock().await;

        if let Some(peer) = self
            .resolved_from_cache(domain, feature, direction, now)
            .await?
        {
            return Ok(peer);
        }
        if let Some(negative) = self.transport.negative.lock().await.get(domain).cloned() {
            if negative.retry_at > now.unix_timestamp() {
                anyhow::bail!(
                    "federation discovery is temporarily unavailable: {}",
                    negative.error
                );
            }
        }

        let result = self
            .fetch_and_pin_discovery(domain, feature, direction, now)
            .await;
        match result {
            Ok(peer) => {
                self.transport.negative.lock().await.remove(domain);
                Ok(peer)
            }
            Err(error) => {
                let message = format!("{error:#}");
                self.transport.positive.lock().await.remove(domain);
                self.transport.negative.lock().await.insert(
                    domain.to_owned(),
                    NegativeDiscovery {
                        error: message.clone(),
                        retry_at: now.unix_timestamp() + NEGATIVE_CACHE_SECONDS,
                    },
                );
                if let Err(record_error) = self.trust.record_discovery_error(domain, &message).await
                {
                    tracing::warn!(%record_error, %domain, "failed to persist federation discovery error");
                }
                Err(error)
            }
        }
    }

    async fn resolved_from_cache(
        &self,
        domain: &str,
        feature: FederationFeature,
        direction: FederationDirection,
        now: OffsetDateTime,
    ) -> anyhow::Result<Option<ResolvedFederationPeer>> {
        let cached = self.transport.positive.lock().await.get(domain).cloned();
        let Some(cached) = cached else {
            return Ok(None);
        };
        if cached.discovery.expires_at <= now.unix_timestamp()
            || !has_feature(&cached.discovery, feature)
        {
            self.transport.positive.lock().await.remove(domain);
            return Ok(None);
        }
        let Some(pinned) = self.trust.pinned_peer(domain).await? else {
            self.transport.positive.lock().await.remove(domain);
            return Ok(None);
        };
        if pinned.document_hash != cached.discovery.identity_document_hash {
            self.transport.positive.lock().await.remove(domain);
            return Ok(None);
        }
        enforce_final_policy(&self.policy, domain, policy_feature(feature), direction).await?;
        Ok(Some(resolved_peer(cached.discovery, pinned)))
    }

    async fn fetch_and_pin_discovery(
        &self,
        domain: &str,
        feature: FederationFeature,
        direction: FederationDirection,
        now: OffsetDateTime,
    ) -> anyhow::Result<ResolvedFederationPeer> {
        let scheme = if self.config.allow_private_test_network {
            "http"
        } else {
            "https"
        };
        let origin = format!("{scheme}://{domain}");
        let discovery_url = Url::parse(&format!("{origin}{DISCOVERY_PATH}"))?;
        let bytes = self
            .bounded_request(
                Method::GET,
                discovery_url,
                HeaderMap::new(),
                Vec::new(),
                MAX_DISCOVERY_BYTES,
            )
            .await?;
        if bytes.status != StatusCode::OK {
            anyhow::bail!("federation discovery returned {}", bytes.status);
        }
        let discovery: FederationDiscoveryV2 = serde_json::from_slice(&bytes.body)
            .map_err(|_| anyhow::anyhow!("invalid federation v2 discovery response"))?;
        let transport_policy = self.discovery_transport_policy();
        discovery.verify_at_with_transport_policy(
            domain,
            now.unix_timestamp(),
            transport_policy,
        )?;
        if discovery.identity.sequence > MAX_IDENTITY_SEQUENCE {
            anyhow::bail!("federation identity sequence exceeds the supported history bound");
        }
        if !has_feature(&discovery, feature) {
            anyhow::bail!(
                "peer does not advertise the required {} capability",
                feature.as_str()
            );
        }

        let mut chain = Vec::with_capacity(discovery.identity.sequence as usize + 1);
        for sequence in 0..discovery.identity.sequence {
            let url = Url::parse(&format!("{origin}{IDENTITY_PATH_PREFIX}{sequence}.json"))?;
            let response = self
                .bounded_request(
                    Method::GET,
                    url,
                    HeaderMap::new(),
                    Vec::new(),
                    MAX_IDENTITY_DOCUMENT_BYTES,
                )
                .await?;
            if response.status != StatusCode::OK {
                anyhow::bail!(
                    "federation identity document {sequence} returned {}",
                    response.status
                );
            }
            let document: FederationIdentityDocumentV1 = serde_json::from_slice(&response.body)
                .map_err(|_| anyhow::anyhow!("invalid federation identity document {sequence}"))?;
            chain.push(document);
        }
        chain.push(discovery.identity.clone());
        self.trust
            .observe_peer_with_transport_policy(&discovery, &chain, now, transport_policy)
            .await?;
        self.trust
            .record_authenticated_discovery(&discovery)
            .await?;
        enforce_final_policy(&self.policy, domain, policy_feature(feature), direction).await?;
        let pinned = self
            .trust
            .pinned_peer(domain)
            .await?
            .ok_or_else(|| anyhow::anyhow!("accepted federation identity was not persisted"))?;
        if pinned.document_hash != discovery.identity_document_hash {
            anyhow::bail!("pinned federation identity does not match authenticated discovery");
        }
        self.transport.positive.lock().await.insert(
            domain.to_owned(),
            CachedDiscovery {
                discovery: discovery.clone(),
            },
        );
        Ok(resolved_peer(discovery, pinned))
    }

    pub(crate) async fn send(
        &self,
        destination: &str,
        spec: FederationRequestSpec,
    ) -> anyhow::Result<AuthenticatedFederationResponse> {
        validate_request_spec(&spec)?;
        let now = OffsetDateTime::now_utc();
        let peer = self
            .resolve_peer(
                destination,
                spec.feature,
                FederationDirection::Outbound,
                now,
            )
            .await?;
        let target = operation_url(&peer.api_base, &spec.path, spec.query.as_deref())?;
        let authority = canonical_authority(&target)?;
        let path = target.path().to_owned();
        let query = target
            .query()
            .map(|value| format!("?{value}"))
            .unwrap_or_else(|| "?".into());
        let request = FederationHttpRequest {
            method: spec.method.as_str().to_owned(),
            authority,
            path,
            query,
            content_type: spec.content_type.into(),
            body: spec.body.clone(),
            federation_version: FederationProtocolVersion::V2,
            feature: spec.feature,
            origin: self.server_name().to_owned(),
            destination: destination.to_owned(),
        };
        let created = now.unix_timestamp();
        let signed = FederationSignedRequest::sign(
            request,
            spec.request_id,
            created,
            created + MAX_SIGNATURE_LIFETIME_SECONDS,
            self.local_identity.signing_key(),
        )?;
        let mut headers = signature_request_headers(&signed.headers, &signed.request)?;
        for (name, value) in spec.extra_headers {
            if headers.contains_key(&name) {
                anyhow::bail!(
                    "feature header attempts to replace federation authentication metadata"
                );
            }
            headers.insert(name, value);
        }
        let response = self
            .bounded_request(spec.method, target, headers, spec.body, spec.response_limit)
            .await?;
        let response_headers = parse_signature_headers(&response.headers)?;
        require_metadata_headers(
            &response.headers,
            spec.feature,
            destination,
            self.server_name(),
        )?;
        let federation_response = FederationHttpResponse {
            status: response.status.as_u16(),
            content_type: required_header(&response.headers, header::CONTENT_TYPE.as_str())?.into(),
            body: response.body,
            federation_version: FederationProtocolVersion::V2,
            feature: spec.feature,
            origin: destination.to_owned(),
            destination: self.server_name().to_owned(),
        };
        let verified = match signed.verify_response(
            federation_response,
            &response_headers,
            &peer.public_key,
            OffsetDateTime::now_utc().unix_timestamp(),
        ) {
            Ok(verified) => verified,
            Err(error) => {
                // A response from the endpoint selected by authenticated
                // discovery no longer verifies under the cached pin. Fail
                // this operation, but force the next retry through discovery
                // so a valid chained rotation can advance without waiting for
                // the old discovery document to expire.
                self.evict_peer_cache(destination).await;
                return Err(error.into());
            }
        };
        Ok(AuthenticatedFederationResponse {
            status: StatusCode::from_u16(verified.status)?,
            body: verified.body,
        })
    }

    pub(crate) async fn authenticate_inbound(
        &self,
        headers: &HeaderMap,
        method: &str,
        path: &str,
        query: Option<&str>,
        body: &[u8],
        feature: FederationFeature,
    ) -> AppResult<AuthenticatedFederationRequest> {
        require_metadata_headers(
            headers,
            feature,
            header_value(headers, FEDERATION_ORIGIN_HEADER)?,
            self.server_name(),
        )
        .map_err(|error| AppError::unauthorized(error.to_string()))?;
        let origin = header_value(headers, FEDERATION_ORIGIN_HEADER)?;
        let destination = header_value(headers, FEDERATION_DESTINATION_HEADER)?;
        if destination != self.server_name() {
            return Err(AppError::unauthorized(
                "federation destination does not match this server",
            ));
        }
        match self
            .policy
            .check_admission(
                origin,
                policy_feature(feature),
                FederationDirection::Inbound,
            )
            .await
            .map_err(AppError::from)?
        {
            FederationAdmissionPreflight::Allowed => {}
            FederationAdmissionPreflight::Denied { reason } => {
                return Err(AppError::forbidden(reason.to_string()))
            }
        }
        let peer = self
            .resolve_peer(
                origin,
                feature,
                FederationDirection::Inbound,
                OffsetDateTime::now_utc(),
            )
            .await
            .map_err(|error| {
                AppError::unauthorized(format!("cannot authenticate federation origin: {error}"))
            })?;
        let request = FederationHttpRequest {
            method: method.to_owned(),
            authority: header_value(headers, header::HOST.as_str())?.to_owned(),
            path: path.to_owned(),
            query: query
                .map(|value| format!("?{value}"))
                .unwrap_or_else(|| "?".into()),
            content_type: header_value(headers, header::CONTENT_TYPE.as_str())?.to_owned(),
            body: body.to_vec(),
            federation_version: FederationProtocolVersion::V2,
            feature,
            origin: origin.to_owned(),
            destination: destination.to_owned(),
        };
        let signature_headers = parse_signature_headers(headers)
            .map_err(|error| AppError::unauthorized(error.to_string()))?;
        let verified = FederationVerifiedRequest::verify(
            request,
            signature_headers,
            &peer.public_key,
            OffsetDateTime::now_utc().unix_timestamp(),
        )
        .map_err(|error| AppError::unauthorized(error.to_string()))?;
        let replay = self
            .replay
            .reserve_verified(
                &verified
                    .replay_metadata()
                    .map_err(|error| AppError::unauthorized(error.to_string()))?,
                OffsetDateTime::now_utc(),
            )
            .await
            .map_err(AppError::from)?;
        if replay == FederationReplayOutcome::Conflict {
            return Err(AppError::conflict(
                "federation request ID was reused with different signed content",
            ));
        }
        Ok(AuthenticatedFederationRequest { verified })
    }

    pub(crate) fn signed_response(
        &self,
        authenticated: &AuthenticatedFederationRequest,
        status: StatusCode,
        content_type: &'static str,
        body: Vec<u8>,
    ) -> AppResult<Response> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let response = FederationHttpResponse {
            status: status.as_u16(),
            content_type: content_type.into(),
            body: body.clone(),
            federation_version: FederationProtocolVersion::V2,
            feature: authenticated.verified.request.feature,
            origin: self.server_name().to_owned(),
            destination: authenticated.origin().to_owned(),
        };
        let signature = authenticated
            .verified
            .sign_response(
                &response,
                now,
                now + MAX_SIGNATURE_LIFETIME_SECONDS,
                self.local_identity.signing_key(),
            )
            .map_err(|error| AppError::internal(error.to_string()))?;
        let builder = Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, content_type)
            .header(CONTENT_DIGEST_HEADER, signature.content_digest)
            .header(SIGNATURE_INPUT_HEADER, signature.signature_input)
            .header(SIGNATURE_HEADER, signature.signature)
            .header(FEDERATION_VERSION_HEADER, "2")
            .header(FEDERATION_FEATURE_HEADER, response.feature.as_str())
            .header(FEDERATION_ORIGIN_HEADER, self.server_name())
            .header(FEDERATION_DESTINATION_HEADER, authenticated.origin());
        let response = builder
            .body(Body::from(body))
            .map_err(|error| AppError::internal(error.to_string()))?;
        Ok(response)
    }

    pub(crate) async fn evict_peer_cache(&self, domain: &str) {
        self.transport.positive.lock().await.remove(domain);
        self.transport.negative.lock().await.remove(domain);
    }

    fn discovery_transport_policy(&self) -> FederationDiscoveryTransportPolicy {
        if self.config.allow_private_test_network {
            FederationDiscoveryTransportPolicy::AllowHttpForTesting
        } else {
            FederationDiscoveryTransportPolicy::HttpsOnly
        }
    }

    async fn bounded_request(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Vec<u8>,
        limit: usize,
    ) -> anyhow::Result<BoundedHttpResponse> {
        let client = bound_client(&url, self.config.allow_private_test_network).await?;
        let response = client
            .request(method, url)
            .headers(headers)
            .body(body)
            .send()
            .await?;
        let status = StatusCode::from_u16(response.status().as_u16())?;
        let headers = response.headers().clone();
        if response
            .content_length()
            .is_some_and(|length| length > limit as u64)
        {
            anyhow::bail!("federation response exceeds the configured byte limit");
        }
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if bytes.len().saturating_add(chunk.len()) > limit {
                anyhow::bail!("federation response exceeds the configured byte limit");
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(BoundedHttpResponse {
            status,
            headers,
            body: bytes,
        })
    }
}

struct BoundedHttpResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

async fn enforce_final_policy(
    policy: &super::policy::FederationPolicyStore,
    domain: &str,
    feature: FederationPolicyFeature,
    direction: FederationDirection,
) -> anyhow::Result<()> {
    match policy.evaluate(domain, feature, direction).await? {
        FederationAdmissionDecision::Allowed { .. } => Ok(()),
        FederationAdmissionDecision::Denied { reason } => {
            Err(FederationAdmissionError(reason).into())
        }
    }
}

fn resolved_peer(
    discovery: FederationDiscoveryV2,
    pinned: PinnedFederationPeer,
) -> ResolvedFederationPeer {
    ResolvedFederationPeer {
        api_base: discovery.api_base,
        public_key: pinned.public_key,
    }
}

fn policy_feature(feature: FederationFeature) -> FederationPolicyFeature {
    match feature {
        FederationFeature::ChatV1 => FederationPolicyFeature::Chat,
        FederationFeature::DriveV1 => FederationPolicyFeature::Drive,
    }
}

fn has_feature(discovery: &FederationDiscoveryV2, feature: FederationFeature) -> bool {
    let required = match feature {
        FederationFeature::ChatV1 => FederationCapabilityId::chat_v1(),
        FederationFeature::DriveV1 => FederationCapabilityId::drive_v1(),
    };
    discovery.capabilities.binary_search(&required).is_ok()
}

fn validate_request_spec(spec: &FederationRequestSpec) -> anyhow::Result<()> {
    let required_prefix = match spec.feature {
        FederationFeature::ChatV1 => "/api/fed/chat/",
        FederationFeature::DriveV1 => "/api/fed/drive/",
    };
    if !spec.path.starts_with(required_prefix)
        || spec.path.contains(['?', '#'])
        || !spec.path.is_ascii()
    {
        anyhow::bail!("federation operation is outside its feature-owned endpoint namespace");
    }
    if spec
        .query
        .as_deref()
        .is_some_and(|query| query.contains('#') || !query.is_ascii())
    {
        anyhow::bail!("federation operation query is not canonical ASCII");
    }
    if spec.response_limit == 0 {
        anyhow::bail!("federation response limit must be positive");
    }
    Ok(())
}

fn operation_url(api_base: &str, path: &str, query: Option<&str>) -> anyhow::Result<Url> {
    let mut value = format!("{api_base}{path}");
    if let Some(query) = query {
        value.push('?');
        value.push_str(query);
    }
    let url = Url::parse(&value)?;
    if url.fragment().is_some() {
        anyhow::bail!("federation operation URL cannot contain a fragment");
    }
    Ok(url)
}

fn canonical_authority(url: &Url) -> anyhow::Result<String> {
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("federation URL has no host"))?;
    let mut authority = host.to_owned();
    if let Some(port) = url.port() {
        authority.push(':');
        authority.push_str(&port.to_string());
    }
    Ok(authority)
}

async fn bound_client(
    url: &Url,
    allow_private_test_network: bool,
) -> anyhow::Result<reqwest::Client> {
    let scheme_allowed =
        url.scheme() == "https" || (allow_private_test_network && url.scheme() == "http");
    if !scheme_allowed
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        anyhow::bail!("federation URL must use the configured secure transport policy");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("federation URL has no host"))?;
    validate_server_name(host).map_err(anyhow::Error::msg)?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("federation URL has no port"))?;
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    if addresses.is_empty() {
        anyhow::bail!("federation host resolved to no addresses");
    }
    if !allow_private_test_network
        && addresses
            .iter()
            .any(|address| ssrf::is_private_ip(address.ip()))
    {
        anyhow::bail!("federation to private/internal addresses is not allowed");
    }
    Ok(reqwest::Client::builder()
        // Environment-configured proxies would connect somewhere other than
        // the DNS answers validated above and invalidate the SSRF binding.
        .no_proxy()
        .timeout(DEFAULT_HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(host, &addresses)
        .build()?)
}

fn signature_request_headers(
    signature: &FederationSignatureHeaders,
    request: &FederationHttpRequest,
) -> anyhow::Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    insert_header(
        &mut headers,
        header::CONTENT_TYPE.as_str(),
        &request.content_type,
    )?;
    insert_header(
        &mut headers,
        CONTENT_DIGEST_HEADER,
        &signature.content_digest,
    )?;
    insert_header(
        &mut headers,
        SIGNATURE_INPUT_HEADER,
        &signature.signature_input,
    )?;
    insert_header(&mut headers, SIGNATURE_HEADER, &signature.signature)?;
    insert_header(&mut headers, FEDERATION_VERSION_HEADER, "2")?;
    insert_header(
        &mut headers,
        FEDERATION_FEATURE_HEADER,
        request.feature.as_str(),
    )?;
    insert_header(&mut headers, FEDERATION_ORIGIN_HEADER, &request.origin)?;
    insert_header(
        &mut headers,
        FEDERATION_DESTINATION_HEADER,
        &request.destination,
    )?;
    Ok(headers)
}

fn parse_signature_headers(headers: &HeaderMap) -> anyhow::Result<FederationSignatureHeaders> {
    Ok(FederationSignatureHeaders {
        content_digest: required_header(headers, CONTENT_DIGEST_HEADER)?.into(),
        signature_input: required_header(headers, SIGNATURE_INPUT_HEADER)?.into(),
        signature: required_header(headers, SIGNATURE_HEADER)?.into(),
    })
}

fn require_metadata_headers(
    headers: &HeaderMap,
    feature: FederationFeature,
    expected_origin: &str,
    expected_destination: &str,
) -> anyhow::Result<()> {
    if required_header(headers, FEDERATION_VERSION_HEADER)? != "2"
        || required_header(headers, FEDERATION_FEATURE_HEADER)? != feature.as_str()
        || required_header(headers, FEDERATION_ORIGIN_HEADER)? != expected_origin
        || required_header(headers, FEDERATION_DESTINATION_HEADER)? != expected_destination
    {
        anyhow::bail!("federation metadata headers do not match the required v2 request");
    }
    Ok(())
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> AppResult<&'a str> {
    required_header(headers, name)
        .map_err(|_| AppError::unauthorized(format!("missing or invalid {name} header")))
}

fn required_header<'a>(headers: &'a HeaderMap, name: &str) -> anyhow::Result<&'a str> {
    headers
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("missing {name} header"))?
        .to_str()
        .map_err(|_| anyhow::anyhow!("invalid {name} header"))
}

fn insert_header(headers: &mut HeaderMap, name: &str, value: &str) -> anyhow::Result<()> {
    headers.insert(
        HeaderName::from_bytes(name.as_bytes())?,
        HeaderValue::from_str(value)?,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn feature_paths_cannot_cross_protocol_namespaces() {
        let mut spec = FederationRequestSpec {
            feature: FederationFeature::ChatV1,
            method: Method::GET,
            path: "/api/fed/chat/users/alice/keys".into(),
            query: None,
            content_type: "application/json",
            body: vec![],
            request_id: Uuid::new_v4().to_string(),
            extra_headers: vec![],
            response_limit: 1024,
        };
        validate_request_spec(&spec).unwrap();
        spec.path = "/api/fed/drive/users/alice".into();
        assert!(validate_request_spec(&spec).is_err());
        spec.path = "https://internal.example/api/fed/chat/users/alice/keys".into();
        assert!(validate_request_spec(&spec).is_err());
    }

    #[test]
    fn delegated_base_prefix_is_part_of_the_signed_path() {
        let url = operation_url(
            "https://edge.example/base",
            "/api/fed/chat/users/alice/keys",
            Some("tree=7"),
        )
        .unwrap();
        assert_eq!(url.path(), "/base/api/fed/chat/users/alice/keys");
        assert_eq!(url.query(), Some("tree=7"));
        assert_eq!(canonical_authority(&url).unwrap(), "edge.example");
    }
}
