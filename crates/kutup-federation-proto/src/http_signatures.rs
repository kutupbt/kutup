use std::{fmt, str::FromStr};

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::{
    decode_base64, federation_key_id, push_string, validate_server_name, FederationProtocolError,
    FederationProtocolVersion, CLOCK_SKEW_SECONDS, FEDERATION_SIGNATURE_LABEL,
    FEDERATION_SIGNATURE_TAG, MAX_SIGNATURE_LIFETIME_SECONDS,
};

const REQUEST_COMPONENTS: &str = "(\"@method\" \"@authority\" \"@path\" \"@query\" \"content-digest\" \"content-type\" \"kutup-federation-version\" \"kutup-federation-feature\" \"kutup-origin\" \"kutup-destination\")";
const RESPONSE_COMPONENTS: &str = "(\"@status\" \"content-digest\" \"content-type\" \"kutup-federation-version\" \"kutup-federation-feature\" \"kutup-origin\" \"kutup-destination\" \"@method\";req \"@authority\";req \"@path\";req \"@query\";req \"content-digest\";req \"content-type\";req \"kutup-federation-version\";req \"kutup-federation-feature\";req \"kutup-origin\";req \"kutup-destination\";req)";
const REPLAY_HASH_DOMAIN: &[u8] = b"kutup-federation-request-replay-hash-v1\0";

/// Feature protocol selected independently from federation authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum FederationFeature {
    #[serde(rename = "chat.v1")]
    ChatV1,
    #[serde(rename = "drive.v1")]
    DriveV1,
}

impl FederationFeature {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ChatV1 => "chat.v1",
            Self::DriveV1 => "drive.v1",
        }
    }
}

impl fmt::Display for FederationFeature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for FederationFeature {
    type Err = FederationProtocolError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "chat.v1" => Ok(Self::ChatV1),
            "drive.v1" => Ok(Self::DriveV1),
            _ => Err(crate::error::invalid_field(
                "kutup-federation-feature",
                "is not a supported feature protocol",
            )),
        }
    }
}

/// Exact request inputs covered by the Kutup RFC 9421 profile. Callers must
/// preserve the raw path/query used on the HTTP request target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationHttpRequest {
    pub method: String,
    pub authority: String,
    pub path: String,
    /// Includes the leading `?`; an absent query is represented by exactly `?`.
    pub query: String,
    pub content_type: String,
    pub body: Vec<u8>,
    pub federation_version: FederationProtocolVersion,
    pub feature: FederationFeature,
    pub origin: String,
    pub destination: String,
}

/// Exact response inputs covered by the Kutup RFC 9421 profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationHttpResponse {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
    pub federation_version: FederationProtocolVersion,
    pub feature: FederationFeature,
    pub origin: String,
    pub destination: String,
}

/// The three HTTP fields emitted/consumed by the fixed profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationSignatureHeaders {
    pub content_digest: String,
    pub signature_input: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FederationRequestContext {
    request: FederationHttpRequest,
    request_content_digest: String,
    nonce: String,
    created: i64,
    expires: i64,
}

/// Authenticated inputs for the shared replay store. The request hash covers
/// the stable signed request content but deliberately excludes signature time
/// parameters, allowing an exact logical retry to be freshly signed with the
/// same nonce without being misclassified as conflicting content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationReplayMetadata {
    origin: String,
    request_id: String,
    request_hash: String,
    created: i64,
    expires: i64,
    /// Keep the reservation through the verifier's permitted post-expiry
    /// clock skew, not merely through the signed `expires` second.
    store_until: i64,
}

impl FederationReplayMetadata {
    pub fn origin(&self) -> &str {
        &self.origin
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn request_hash(&self) -> &str {
        &self.request_hash
    }

    pub const fn created(&self) -> i64 {
        self.created
    }

    pub const fn expires(&self) -> i64 {
        self.expires
    }

    pub const fn store_until(&self) -> i64 {
        self.store_until
    }
}

/// Locally signed request plus the context required to authenticate its
/// response. The context cannot be caller-forged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationSignedRequest {
    pub request: FederationHttpRequest,
    pub headers: FederationSignatureHeaders,
    context: FederationRequestContext,
}

/// Successfully authenticated inbound request plus the context the response
/// signer must bind with RFC 9421 `;req` components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationVerifiedRequest {
    pub request: FederationHttpRequest,
    pub headers: FederationSignatureHeaders,
    context: FederationRequestContext,
}

impl FederationSignedRequest {
    pub fn sign(
        request: FederationHttpRequest,
        nonce: impl Into<String>,
        created: i64,
        expires: i64,
        signing_key: &SigningKey,
    ) -> Result<Self, FederationProtocolError> {
        validate_request(&request)?;
        let nonce = nonce.into();
        validate_nonce(&nonce)?;
        validate_signed_window(created, expires, created)?;
        let content_digest = content_digest_sha256(&request.body);
        let parameters = signature_parameters(
            REQUEST_COMPONENTS,
            created,
            expires,
            &federation_key_id(&signing_key.verifying_key().to_bytes()),
            &nonce,
        );
        let base = request_signature_base(&request, &content_digest, &parameters);
        let headers = FederationSignatureHeaders {
            content_digest: content_digest.clone(),
            signature_input: format!("{FEDERATION_SIGNATURE_LABEL}={parameters}"),
            signature: encode_signature_header(&signing_key.sign(base.as_bytes())),
        };
        let context = FederationRequestContext {
            request: request.clone(),
            request_content_digest: content_digest,
            nonce,
            created,
            expires,
        };
        Ok(Self {
            request,
            headers,
            context,
        })
    }

    /// The exact RFC 9421 signature base, exposed for implementations in
    /// other languages to compare against the published conformance vector.
    pub fn signature_base(&self) -> Result<String, FederationProtocolError> {
        let parsed = parse_signature_input(&self.headers.signature_input, REQUEST_COMPONENTS)?;
        Ok(request_signature_base(
            &self.request,
            &self.headers.content_digest,
            &parsed.parameters,
        ))
    }

    pub fn verify_response(
        &self,
        response: FederationHttpResponse,
        headers: &FederationSignatureHeaders,
        pinned_public_key: &[u8; 32],
        now: i64,
    ) -> Result<FederationHttpResponse, FederationProtocolError> {
        verify_response(&self.context, response, headers, pinned_public_key, now)
    }

    /// Authenticate a response whose body was hashed while streaming rather
    /// than retained in memory. `actual_content_digest` must describe the
    /// exact received bytes.
    pub fn verify_response_with_content_digest(
        &self,
        response: FederationHttpResponse,
        headers: &FederationSignatureHeaders,
        actual_content_digest: &str,
        pinned_public_key: &[u8; 32],
        now: i64,
    ) -> Result<FederationHttpResponse, FederationProtocolError> {
        verify_response_with_content_digest(
            &self.context,
            response,
            headers,
            actual_content_digest,
            pinned_public_key,
            now,
        )
    }
}

impl FederationVerifiedRequest {
    pub fn verify(
        request: FederationHttpRequest,
        headers: FederationSignatureHeaders,
        pinned_public_key: &[u8; 32],
        now: i64,
    ) -> Result<Self, FederationProtocolError> {
        validate_request(&request)?;
        let expected_digest = content_digest_sha256(&request.body);
        if headers.content_digest != expected_digest {
            return Err(FederationProtocolError::ContentDigestMismatch);
        }
        let parsed = parse_signature_input(&headers.signature_input, REQUEST_COMPONENTS)?;
        validate_signed_window(parsed.created, parsed.expires, now)?;
        if parsed.key_id != federation_key_id(pinned_public_key) {
            return Err(FederationProtocolError::KeyIdMismatch);
        }
        let base = request_signature_base(&request, &headers.content_digest, &parsed.parameters);
        verify_signature_header(&headers.signature, pinned_public_key, base.as_bytes())?;
        let context = FederationRequestContext {
            request: request.clone(),
            request_content_digest: expected_digest,
            nonce: parsed.nonce,
            created: parsed.created,
            expires: parsed.expires,
        };
        Ok(Self {
            request,
            headers,
            context,
        })
    }

    /// Return replay inputs only after the request profile, digest, time
    /// window, key ID, and Ed25519 signature have all verified.
    pub fn replay_metadata(&self) -> Result<FederationReplayMetadata, FederationProtocolError> {
        Ok(FederationReplayMetadata {
            origin: self.context.request.origin.clone(),
            request_id: self.context.nonce.clone(),
            request_hash: request_replay_hash(
                &self.context.request,
                &self.context.request_content_digest,
            )?,
            created: self.context.created,
            expires: self.context.expires,
            // Verification accepts the inclusive `expires + skew` second;
            // retain the nonce until the following second so a request valid
            // at that boundary can still be reserved.
            store_until: self
                .context
                .expires
                .saturating_add(CLOCK_SKEW_SECONDS)
                .saturating_add(1),
        })
    }

    pub fn sign_response(
        &self,
        response: &FederationHttpResponse,
        created: i64,
        expires: i64,
        signing_key: &SigningKey,
    ) -> Result<FederationSignatureHeaders, FederationProtocolError> {
        validate_response_for_request(response, &self.context.request)?;
        validate_signed_window(created, expires, created)?;
        let content_digest = content_digest_sha256(&response.body);
        let parameters = signature_parameters(
            RESPONSE_COMPONENTS,
            created,
            expires,
            &federation_key_id(&signing_key.verifying_key().to_bytes()),
            &self.context.nonce,
        );
        let base = response_signature_base(response, &content_digest, &self.context, &parameters);
        Ok(FederationSignatureHeaders {
            content_digest,
            signature_input: format!("{FEDERATION_SIGNATURE_LABEL}={parameters}"),
            signature: encode_signature_header(&signing_key.sign(base.as_bytes())),
        })
    }

    /// Sign response metadata using a digest computed while reading the body.
    /// This keeps the signature bound to the exact bytes without requiring the
    /// signer to buffer a potentially large encrypted Drive object.
    pub fn sign_response_with_content_digest(
        &self,
        response: &FederationHttpResponse,
        content_digest: &str,
        created: i64,
        expires: i64,
        signing_key: &SigningKey,
    ) -> Result<FederationSignatureHeaders, FederationProtocolError> {
        validate_response_for_request(response, &self.context.request)?;
        validate_content_digest(content_digest)?;
        validate_signed_window(created, expires, created)?;
        let parameters = signature_parameters(
            RESPONSE_COMPONENTS,
            created,
            expires,
            &federation_key_id(&signing_key.verifying_key().to_bytes()),
            &self.context.nonce,
        );
        let base = response_signature_base(response, content_digest, &self.context, &parameters);
        Ok(FederationSignatureHeaders {
            content_digest: content_digest.to_owned(),
            signature_input: format!("{FEDERATION_SIGNATURE_LABEL}={parameters}"),
            signature: encode_signature_header(&signing_key.sign(base.as_bytes())),
        })
    }

    /// The exact response signature base, including the original request's
    /// `;req` components, for cross-language conformance checks.
    pub fn response_signature_base(
        &self,
        response: &FederationHttpResponse,
        headers: &FederationSignatureHeaders,
    ) -> Result<String, FederationProtocolError> {
        validate_response_for_request(response, &self.context.request)?;
        if headers.content_digest != content_digest_sha256(&response.body) {
            return Err(FederationProtocolError::ContentDigestMismatch);
        }
        let parsed = parse_signature_input(&headers.signature_input, RESPONSE_COMPONENTS)?;
        if parsed.nonce != self.context.nonce {
            return Err(FederationProtocolError::InvalidHttpSignature(
                "response nonce does not match its request",
            ));
        }
        Ok(response_signature_base(
            response,
            &headers.content_digest,
            &self.context,
            &parsed.parameters,
        ))
    }
}

pub fn content_digest_sha256(body: &[u8]) -> String {
    content_digest_sha256_from_digest(&Sha256::digest(body).into())
}

/// Format an already-computed raw SHA-256 digest as RFC 9530 content digest.
pub fn content_digest_sha256_from_digest(digest: &[u8; 32]) -> String {
    format!(
        "sha-256=:{}:",
        base64::engine::general_purpose::STANDARD.encode(digest)
    )
}

fn request_replay_hash(
    request: &FederationHttpRequest,
    content_digest: &str,
) -> Result<String, FederationProtocolError> {
    validate_request(request)?;
    if content_digest != content_digest_sha256(&request.body) {
        return Err(FederationProtocolError::ContentDigestMismatch);
    }
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(REPLAY_HASH_DOMAIN);
    push_string(&mut bytes, "@method", &request.method)?;
    push_string(&mut bytes, "@authority", &request.authority)?;
    push_string(&mut bytes, "@path", &request.path)?;
    push_string(&mut bytes, "@query", &request.query)?;
    push_string(&mut bytes, "content-digest", content_digest)?;
    push_string(&mut bytes, "content-type", &request.content_type)?;
    bytes.extend_from_slice(&u16::from(request.federation_version).to_be_bytes());
    push_string(
        &mut bytes,
        "kutup-federation-feature",
        request.feature.as_str(),
    )?;
    push_string(&mut bytes, "kutup-origin", &request.origin)?;
    push_string(&mut bytes, "kutup-destination", &request.destination)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn verify_response(
    context: &FederationRequestContext,
    response: FederationHttpResponse,
    headers: &FederationSignatureHeaders,
    pinned_public_key: &[u8; 32],
    now: i64,
) -> Result<FederationHttpResponse, FederationProtocolError> {
    let expected_digest = content_digest_sha256(&response.body);
    verify_response_with_content_digest(
        context,
        response,
        headers,
        &expected_digest,
        pinned_public_key,
        now,
    )
}

fn verify_response_with_content_digest(
    context: &FederationRequestContext,
    response: FederationHttpResponse,
    headers: &FederationSignatureHeaders,
    actual_content_digest: &str,
    pinned_public_key: &[u8; 32],
    now: i64,
) -> Result<FederationHttpResponse, FederationProtocolError> {
    validate_response_for_request(&response, &context.request)?;
    validate_content_digest(actual_content_digest)?;
    if headers.content_digest != actual_content_digest {
        return Err(FederationProtocolError::ContentDigestMismatch);
    }
    let parsed = parse_signature_input(&headers.signature_input, RESPONSE_COMPONENTS)?;
    validate_signed_window(parsed.created, parsed.expires, now)?;
    if parsed.key_id != federation_key_id(pinned_public_key) {
        return Err(FederationProtocolError::KeyIdMismatch);
    }
    if parsed.nonce != context.nonce {
        return Err(FederationProtocolError::InvalidHttpSignature(
            "response nonce does not match its request",
        ));
    }
    let base = response_signature_base(
        &response,
        &headers.content_digest,
        context,
        &parsed.parameters,
    );
    verify_signature_header(&headers.signature, pinned_public_key, base.as_bytes())?;
    Ok(response)
}

fn validate_content_digest(value: &str) -> Result<(), FederationProtocolError> {
    let encoded = value
        .strip_prefix("sha-256=:")
        .and_then(|value| value.strip_suffix(':'))
        .ok_or(FederationProtocolError::ContentDigestMismatch)?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| FederationProtocolError::ContentDigestMismatch)?;
    if decoded.len() != 32 || base64::engine::general_purpose::STANDARD.encode(&decoded) != encoded
    {
        return Err(FederationProtocolError::ContentDigestMismatch);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedSignatureInput {
    created: i64,
    expires: i64,
    key_id: String,
    nonce: String,
    parameters: String,
}

fn parse_signature_input(
    value: &str,
    required_components: &str,
) -> Result<ParsedSignatureInput, FederationProtocolError> {
    let prefix = format!("{FEDERATION_SIGNATURE_LABEL}={required_components};created=");
    let rest = value
        .strip_prefix(&prefix)
        .ok_or(FederationProtocolError::InvalidHttpSignature(
            "signature input label or covered components are not the required exact profile",
        ))?;
    let (created, rest) = take_until(rest, ";expires=")?;
    let (expires, rest) = take_until(rest, ";keyid=\"")?;
    let (key_id, rest) = take_until(rest, "\";alg=\"ed25519\";nonce=\"")?;
    let (nonce, tag) = take_until(rest, "\";tag=\"")?;
    if tag != format!("{FEDERATION_SIGNATURE_TAG}\"") {
        return Err(FederationProtocolError::InvalidHttpSignature(
            "signature tag or trailing parameters are invalid",
        ));
    }
    let created = parse_timestamp("created", created)?;
    let expires = parse_timestamp("expires", expires)?;
    crate::validate_hash("keyid", key_id)?;
    validate_nonce(nonce)?;
    Ok(ParsedSignatureInput {
        created,
        expires,
        key_id: key_id.into(),
        nonce: nonce.into(),
        parameters: value
            .strip_prefix(&format!("{FEDERATION_SIGNATURE_LABEL}="))
            .expect("prefix was checked")
            .into(),
    })
}

fn take_until<'a>(
    value: &'a str,
    delimiter: &str,
) -> Result<(&'a str, &'a str), FederationProtocolError> {
    value
        .split_once(delimiter)
        .ok_or(FederationProtocolError::InvalidHttpSignature(
            "signature parameters are missing or out of order",
        ))
}

fn parse_timestamp(field: &'static str, value: &str) -> Result<i64, FederationProtocolError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(crate::error::invalid_field(
            field,
            "must be a canonical non-negative integer",
        ));
    }
    value
        .parse()
        .map_err(|_| crate::error::invalid_field(field, "must be a canonical non-negative integer"))
}

fn validate_signed_window(
    created: i64,
    expires: i64,
    now: i64,
) -> Result<(), FederationProtocolError> {
    if created < 0 || expires <= created || expires - created > MAX_SIGNATURE_LIFETIME_SECONDS {
        return Err(FederationProtocolError::InvalidHttpSignature(
            "signature lifetime must be positive and no longer than five minutes",
        ));
    }
    if created > now.saturating_add(CLOCK_SKEW_SECONDS) {
        return Err(FederationProtocolError::SignatureNotYetValid);
    }
    if expires < now.saturating_sub(CLOCK_SKEW_SECONDS) {
        return Err(FederationProtocolError::SignatureExpired);
    }
    Ok(())
}

fn validate_nonce(nonce: &str) -> Result<(), FederationProtocolError> {
    if nonce.is_empty()
        || nonce.len() > 128
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-'))
    {
        return Err(crate::error::invalid_field(
            "nonce",
            "must be 1-128 unescaped URI-safe ASCII characters",
        ));
    }
    Ok(())
}

fn validate_request(request: &FederationHttpRequest) -> Result<(), FederationProtocolError> {
    if request.method.is_empty()
        || !request.method.bytes().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        return Err(crate::error::invalid_field(
            "@method",
            "must be a canonical uppercase HTTP method",
        ));
    }
    validate_authority(&request.authority)?;
    if !request.path.starts_with('/')
        || !is_visible_ascii(&request.path)
        || request.path.contains(['?', '#'])
    {
        return Err(crate::error::invalid_field(
            "@path",
            "must be a raw absolute ASCII path without query or fragment",
        ));
    }
    if !request.query.starts_with('?')
        || !is_visible_ascii(&request.query)
        || request.query.contains('#')
    {
        return Err(crate::error::invalid_field(
            "@query",
            "must be a raw ASCII query beginning with ? (or exactly ? when absent)",
        ));
    }
    validate_content_type(&request.content_type)?;
    validate_server_name(&request.origin)?;
    validate_server_name(&request.destination)?;
    if request.origin == request.destination {
        return Err(crate::error::invalid_field(
            "kutup-destination",
            "must differ from the origin",
        ));
    }
    Ok(())
}

fn validate_response_for_request(
    response: &FederationHttpResponse,
    request: &FederationHttpRequest,
) -> Result<(), FederationProtocolError> {
    if !(100..=599).contains(&response.status) {
        return Err(crate::error::invalid_field(
            "@status",
            "must be a three-digit HTTP status",
        ));
    }
    validate_content_type(&response.content_type)?;
    validate_server_name(&response.origin)?;
    validate_server_name(&response.destination)?;
    if response.federation_version != request.federation_version
        || response.feature != request.feature
        || response.origin != request.destination
        || response.destination != request.origin
    {
        return Err(FederationProtocolError::InvalidHttpSignature(
            "response version, feature, origin, or destination does not match the request",
        ));
    }
    Ok(())
}

fn validate_authority(authority: &str) -> Result<(), FederationProtocolError> {
    if authority.is_empty() || authority.contains(['/', '?', '#', '@']) || !authority.is_ascii() {
        return Err(crate::error::invalid_field(
            "@authority",
            "must be a canonical DNS authority",
        ));
    }
    let parsed = Url::parse(&format!("https://{authority}/")).map_err(|_| {
        crate::error::invalid_field("@authority", "must be a canonical DNS authority")
    })?;
    let host = parsed
        .host_str()
        .ok_or_else(|| crate::error::invalid_field("@authority", "must contain a DNS host"))?;
    validate_server_name(host).map_err(|_| {
        crate::error::invalid_field("@authority", "must contain a canonical DNS host")
    })?;
    if matches!(parsed.port(), Some(0 | 443)) {
        return Err(crate::error::invalid_field(
            "@authority",
            "must use a valid non-default HTTPS port",
        ));
    }
    let canonical = match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.into(),
    };
    if canonical != authority {
        return Err(crate::error::invalid_field(
            "@authority",
            "must be lowercase and canonical",
        ));
    }
    Ok(())
}

fn validate_content_type(value: &str) -> Result<(), FederationProtocolError> {
    if value.is_empty()
        || value.len() > 256
        || !is_visible_ascii(value)
        || value.trim() != value
        || !value.contains('/')
    {
        return Err(crate::error::invalid_field(
            "content-type",
            "must be a non-empty canonical visible ASCII media type",
        ));
    }
    Ok(())
}

fn is_visible_ascii(value: &str) -> bool {
    value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn signature_parameters(
    components: &str,
    created: i64,
    expires: i64,
    key_id: &str,
    nonce: &str,
) -> String {
    format!(
        "{components};created={created};expires={expires};keyid=\"{key_id}\";alg=\"ed25519\";nonce=\"{nonce}\";tag=\"{FEDERATION_SIGNATURE_TAG}\""
    )
}

fn request_signature_base(
    request: &FederationHttpRequest,
    content_digest: &str,
    parameters: &str,
) -> String {
    [
        format!("\"@method\": {}", request.method),
        format!("\"@authority\": {}", request.authority),
        format!("\"@path\": {}", request.path),
        format!("\"@query\": {}", request.query),
        format!("\"content-digest\": {content_digest}"),
        format!("\"content-type\": {}", request.content_type),
        format!(
            "\"kutup-federation-version\": {}",
            u16::from(request.federation_version)
        ),
        format!("\"kutup-federation-feature\": {}", request.feature.as_str()),
        format!("\"kutup-origin\": {}", request.origin),
        format!("\"kutup-destination\": {}", request.destination),
        format!("\"@signature-params\": {parameters}"),
    ]
    .join("\n")
}

fn response_signature_base(
    response: &FederationHttpResponse,
    content_digest: &str,
    context: &FederationRequestContext,
    parameters: &str,
) -> String {
    let request = &context.request;
    [
        format!("\"@status\": {}", response.status),
        format!("\"content-digest\": {content_digest}"),
        format!("\"content-type\": {}", response.content_type),
        format!(
            "\"kutup-federation-version\": {}",
            u16::from(response.federation_version)
        ),
        format!(
            "\"kutup-federation-feature\": {}",
            response.feature.as_str()
        ),
        format!("\"kutup-origin\": {}", response.origin),
        format!("\"kutup-destination\": {}", response.destination),
        format!("\"@method\";req: {}", request.method),
        format!("\"@authority\";req: {}", request.authority),
        format!("\"@path\";req: {}", request.path),
        format!("\"@query\";req: {}", request.query),
        format!("\"content-digest\";req: {}", context.request_content_digest),
        format!("\"content-type\";req: {}", request.content_type),
        format!(
            "\"kutup-federation-version\";req: {}",
            u16::from(request.federation_version)
        ),
        format!(
            "\"kutup-federation-feature\";req: {}",
            request.feature.as_str()
        ),
        format!("\"kutup-origin\";req: {}", request.origin),
        format!("\"kutup-destination\";req: {}", request.destination),
        format!("\"@signature-params\": {parameters}"),
    ]
    .join("\n")
}

fn encode_signature_header(signature: &Signature) -> String {
    format!(
        "{FEDERATION_SIGNATURE_LABEL}=:{}:",
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    )
}

fn verify_signature_header(
    value: &str,
    public_key: &[u8; 32],
    message: &[u8],
) -> Result<(), FederationProtocolError> {
    let prefix = format!("{FEDERATION_SIGNATURE_LABEL}=:");
    let encoded = value
        .strip_prefix(&prefix)
        .and_then(|rest| rest.strip_suffix(':'))
        .ok_or(FederationProtocolError::InvalidHttpSignature(
            "Signature is not the required single binary member",
        ))?;
    let signature = Signature::from_bytes(&decode_base64::<64>("Signature", encoded)?);
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| {
        FederationProtocolError::InvalidHttpSignature("pinned key is not a valid Ed25519 key")
    })?;
    key.verify_strict(message, &signature)
        .map_err(|_| FederationProtocolError::InvalidHttpSignature("signature verification failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn request(feature: FederationFeature) -> FederationHttpRequest {
        FederationHttpRequest {
            method: "POST".into(),
            authority: "beta.example".into(),
            path: "/api/fed/chat/v1/transactions".into(),
            query: "?batch=1%2F2".into(),
            content_type: "application/json".into(),
            body: br#"{"transactionId":"01HXYZ"}"#.to_vec(),
            federation_version: FederationProtocolVersion::V2,
            feature,
            origin: "alpha.example".into(),
            destination: "beta.example".into(),
        }
    }

    fn response(feature: FederationFeature) -> FederationHttpResponse {
        FederationHttpResponse {
            status: 202,
            content_type: "application/json".into(),
            body: br#"{"accepted":true}"#.to_vec(),
            federation_version: FederationProtocolVersion::V2,
            feature,
            origin: "beta.example".into(),
            destination: "alpha.example".into(),
        }
    }

    #[test]
    fn request_and_bound_response_round_trip() {
        let client = key(1);
        let server = key(2);
        let signed = FederationSignedRequest::sign(
            request(FederationFeature::ChatV1),
            "request-123",
            1_700_000_000,
            1_700_000_300,
            &client,
        )
        .unwrap();
        let verified = FederationVerifiedRequest::verify(
            signed.request.clone(),
            signed.headers.clone(),
            &client.verifying_key().to_bytes(),
            1_700_000_100,
        )
        .unwrap();
        let response = response(FederationFeature::ChatV1);
        let headers = verified
            .sign_response(&response, 1_700_000_101, 1_700_000_201, &server)
            .unwrap();
        signed
            .verify_response(
                response,
                &headers,
                &server.verifying_key().to_bytes(),
                1_700_000_150,
            )
            .unwrap();
    }

    #[test]
    fn streamed_response_digest_is_signed_and_verified_without_buffering() {
        let client = key(1);
        let server = key(2);
        let signed = FederationSignedRequest::sign(
            request(FederationFeature::DriveV1),
            "drive-download-1",
            1_700_000_000,
            1_700_000_300,
            &client,
        )
        .unwrap();
        let verified = FederationVerifiedRequest::verify(
            signed.request.clone(),
            signed.headers.clone(),
            &client.verifying_key().to_bytes(),
            1_700_000_100,
        )
        .unwrap();
        let mut metadata = response(FederationFeature::DriveV1);
        metadata.content_type = "application/octet-stream".into();
        metadata.body.clear();
        let ciphertext = b"encrypted object bytes hashed chunk by chunk";
        let digest = content_digest_sha256(ciphertext);
        let headers = verified
            .sign_response_with_content_digest(
                &metadata,
                &digest,
                1_700_000_101,
                1_700_000_201,
                &server,
            )
            .unwrap();
        signed
            .verify_response_with_content_digest(
                metadata.clone(),
                &headers,
                &digest,
                &server.verifying_key().to_bytes(),
                1_700_000_150,
            )
            .unwrap();

        let altered = content_digest_sha256(b"altered encrypted object bytes");
        assert_eq!(
            signed
                .verify_response_with_content_digest(
                    metadata,
                    &headers,
                    &altered,
                    &server.verifying_key().to_bytes(),
                    1_700_000_150,
                )
                .unwrap_err(),
            FederationProtocolError::ContentDigestMismatch
        );
    }

    #[test]
    fn rfc_9530_digest_includes_empty_content() {
        assert_eq!(
            content_digest_sha256(b""),
            "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
        );
    }

    #[test]
    fn replay_metadata_is_authenticated_stable_and_content_sensitive() {
        let signing_key = key(1);
        let first = FederationSignedRequest::sign(
            request(FederationFeature::ChatV1),
            "stable-request-id",
            100,
            200,
            &signing_key,
        )
        .unwrap();
        let first = FederationVerifiedRequest::verify(
            first.request,
            first.headers,
            &signing_key.verifying_key().to_bytes(),
            150,
        )
        .unwrap()
        .replay_metadata()
        .unwrap();
        assert_eq!(first.origin(), "alpha.example");
        assert_eq!(first.request_id(), "stable-request-id");
        assert_eq!((first.created(), first.expires()), (100, 200));
        assert_eq!(first.store_until(), 261);

        let resigned = FederationSignedRequest::sign(
            request(FederationFeature::ChatV1),
            "stable-request-id",
            110,
            210,
            &signing_key,
        )
        .unwrap();
        let resigned = FederationVerifiedRequest::verify(
            resigned.request,
            resigned.headers,
            &signing_key.verifying_key().to_bytes(),
            150,
        )
        .unwrap()
        .replay_metadata()
        .unwrap();
        assert_eq!(first.request_hash(), resigned.request_hash());

        let mut changed_request = request(FederationFeature::ChatV1);
        changed_request.body.push(b' ');
        let changed = FederationSignedRequest::sign(
            changed_request,
            "stable-request-id",
            110,
            210,
            &signing_key,
        )
        .unwrap();
        let changed = FederationVerifiedRequest::verify(
            changed.request,
            changed.headers,
            &signing_key.verifying_key().to_bytes(),
            150,
        )
        .unwrap()
        .replay_metadata()
        .unwrap();
        assert_ne!(first.request_hash(), changed.request_hash());
    }

    #[test]
    fn exact_component_profile_rejects_missing_reordered_extra_and_v1() {
        let signing_key = key(1);
        let signed = FederationSignedRequest::sign(
            request(FederationFeature::ChatV1),
            "nonce",
            100,
            200,
            &signing_key,
        )
        .unwrap();
        for replacement in [
            REQUEST_COMPONENTS.replace(" \"@query\"", ""),
            REQUEST_COMPONENTS.replace("\"@method\" \"@authority\"", "\"@authority\" \"@method\""),
            REQUEST_COMPONENTS.replace("\"@query\"", "\"@query\" \"x-extra\""),
            REQUEST_COMPONENTS.replace("\"@query\"", "\"@query\" \"@query\""),
        ] {
            let mut headers = signed.headers.clone();
            headers.signature_input =
                headers
                    .signature_input
                    .replacen(REQUEST_COMPONENTS, &replacement, 1);
            assert!(FederationVerifiedRequest::verify(
                signed.request.clone(),
                headers,
                &signing_key.verifying_key().to_bytes(),
                150,
            )
            .is_err());
        }

        let mut json = serde_json::json!({
            "method": "POST",
            "authority": "beta.example",
            "path": "/",
            "query": "?",
            "contentType": "application/json",
            "body": [],
            "federationVersion": 1,
            "feature": "chat.v1",
            "origin": "alpha.example",
            "destination": "beta.example"
        });
        assert!(serde_json::from_value::<FederationProtocolVersion>(
            json["federationVersion"].take()
        )
        .is_err());
    }

    #[test]
    fn body_digest_signature_and_pinned_key_tampering_fail() {
        let signing_key = key(1);
        let signed = FederationSignedRequest::sign(
            request(FederationFeature::ChatV1),
            "nonce",
            100,
            200,
            &signing_key,
        )
        .unwrap();

        let mut request = signed.request.clone();
        request.body.push(0);
        assert_eq!(
            FederationVerifiedRequest::verify(
                request,
                signed.headers.clone(),
                &signing_key.verifying_key().to_bytes(),
                150,
            )
            .unwrap_err(),
            FederationProtocolError::ContentDigestMismatch
        );

        let mut headers = signed.headers.clone();
        headers.signature = format!(
            "{FEDERATION_SIGNATURE_LABEL}=:{}:",
            base64::engine::general_purpose::STANDARD.encode([0; 64])
        );
        assert!(FederationVerifiedRequest::verify(
            signed.request.clone(),
            headers,
            &signing_key.verifying_key().to_bytes(),
            150,
        )
        .is_err());
        assert!(FederationVerifiedRequest::verify(
            signed.request,
            signed.headers,
            &key(9).verifying_key().to_bytes(),
            150,
        )
        .is_err());
    }

    #[test]
    fn expiry_tag_algorithm_keyid_and_nonce_are_strict() {
        let signing_key = key(1);
        let signed = FederationSignedRequest::sign(
            request(FederationFeature::ChatV1),
            "nonce",
            100,
            200,
            &signing_key,
        )
        .unwrap();
        assert_eq!(
            FederationVerifiedRequest::verify(
                signed.request.clone(),
                signed.headers.clone(),
                &signing_key.verifying_key().to_bytes(),
                261,
            )
            .unwrap_err(),
            FederationProtocolError::SignatureExpired
        );
        for (from, to) in [
            ("tag=\"kutup-federation-v2\"", "tag=\"other\""),
            ("alg=\"ed25519\"", "alg=\"rsa\""),
            ("keyid=\"", "keyid=\"00"),
            ("nonce=\"nonce\"", "nonce=\"bad nonce\""),
        ] {
            let mut headers = signed.headers.clone();
            headers.signature_input = headers.signature_input.replacen(from, to, 1);
            assert!(FederationVerifiedRequest::verify(
                signed.request.clone(),
                headers,
                &signing_key.verifying_key().to_bytes(),
                150,
            )
            .is_err());
        }
    }

    #[test]
    fn response_is_bound_to_request_and_feature() {
        let client = key(1);
        let server = key(2);
        let signed = FederationSignedRequest::sign(
            request(FederationFeature::ChatV1),
            "bound-nonce",
            100,
            200,
            &client,
        )
        .unwrap();
        let verified = FederationVerifiedRequest::verify(
            signed.request.clone(),
            signed.headers.clone(),
            &client.verifying_key().to_bytes(),
            150,
        )
        .unwrap();
        let valid_response = response(FederationFeature::ChatV1);
        let headers = verified
            .sign_response(&valid_response, 151, 220, &server)
            .unwrap();

        let mut wrong_feature = valid_response.clone();
        wrong_feature.feature = FederationFeature::DriveV1;
        assert!(signed
            .verify_response(
                wrong_feature,
                &headers,
                &server.verifying_key().to_bytes(),
                170,
            )
            .is_err());

        let other_request = FederationSignedRequest::sign(
            FederationHttpRequest {
                path: "/api/fed/chat/v1/other".into(),
                ..request(FederationFeature::ChatV1)
            },
            "bound-nonce",
            100,
            200,
            &client,
        )
        .unwrap();
        assert!(other_request
            .verify_response(
                valid_response,
                &headers,
                &server.verifying_key().to_bytes(),
                170,
            )
            .is_err());
    }

    #[test]
    fn response_component_profile_and_legacy_authorization_fail_closed() {
        let client = key(1);
        let server = key(2);
        let signed = FederationSignedRequest::sign(
            request(FederationFeature::ChatV1),
            "bound-nonce",
            100,
            200,
            &client,
        )
        .unwrap();
        let verified = FederationVerifiedRequest::verify(
            signed.request.clone(),
            signed.headers.clone(),
            &client.verifying_key().to_bytes(),
            150,
        )
        .unwrap();
        let response = response(FederationFeature::ChatV1);
        let valid_headers = verified
            .sign_response(&response, 151, 220, &server)
            .unwrap();

        for replacement in [
            RESPONSE_COMPONENTS.replace(" \"@query\";req", ""),
            RESPONSE_COMPONENTS.replace(
                "\"@status\" \"content-digest\"",
                "\"content-digest\" \"@status\"",
            ),
            RESPONSE_COMPONENTS.replace("\"@query\";req", "\"@query\";req \"x-extra\""),
            RESPONSE_COMPONENTS.replace("\"@query\";req", "\"@query\";req \"@query\";req"),
        ] {
            let mut headers = valid_headers.clone();
            headers.signature_input =
                headers
                    .signature_input
                    .replacen(RESPONSE_COMPONENTS, &replacement, 1);
            assert!(signed
                .verify_response(
                    response.clone(),
                    &headers,
                    &server.verifying_key().to_bytes(),
                    170,
                )
                .is_err());
        }

        let legacy = FederationSignatureHeaders {
            content_digest: valid_headers.content_digest,
            signature_input: "Kutup eyJmZWRWZXJzaW9uIjoxfQ".into(),
            signature: valid_headers.signature,
        };
        assert!(signed
            .verify_response(response, &legacy, &server.verifying_key().to_bytes(), 170,)
            .is_err());
    }

    #[test]
    fn malformed_targets_and_headers_fail_before_crypto() {
        for authority in [
            "BETA.example",
            "beta.example:443",
            "beta.example:0",
            "127.0.0.1",
            "user@beta.example",
        ] {
            let mut value = request(FederationFeature::ChatV1);
            value.authority = authority.into();
            assert!(FederationSignedRequest::sign(value, "nonce", 100, 200, &key(1)).is_err());
        }
        for nonce in ["", "has space", "has\"quote"] {
            assert!(FederationSignedRequest::sign(
                request(FederationFeature::ChatV1),
                nonce,
                100,
                200,
                &key(1),
            )
            .is_err());
        }
        for (field, invalid) in [
            ("method", "post"),
            ("path", "relative"),
            ("path", "/path?query"),
            ("query", "batch=1"),
            ("contentType", "application/json\r\nx: y"),
            ("origin", "Alpha.example"),
            ("destination", "alpha.example"),
        ] {
            let mut value = request(FederationFeature::ChatV1);
            match field {
                "method" => value.method = invalid.into(),
                "path" => value.path = invalid.into(),
                "query" => value.query = invalid.into(),
                "contentType" => value.content_type = invalid.into(),
                "origin" => value.origin = invalid.into(),
                "destination" => value.destination = invalid.into(),
                _ => unreachable!(),
            }
            assert!(FederationSignedRequest::sign(value, "nonce", 100, 200, &key(1)).is_err());
        }
        for (created, expires) in [(100, 100), (100, 401), (-1, 100)] {
            assert!(FederationSignedRequest::sign(
                request(FederationFeature::ChatV1),
                "nonce",
                created,
                expires,
                &key(1),
            )
            .is_err());
        }
        assert_eq!(
            "drive.v1".parse::<FederationFeature>().unwrap(),
            FederationFeature::DriveV1
        );
        assert!("chat.v2".parse::<FederationFeature>().is_err());
    }
}
