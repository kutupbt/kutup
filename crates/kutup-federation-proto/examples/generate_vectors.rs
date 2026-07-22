//! Regenerates `test-vectors/federation-v2.json` from fixed, non-secret test
//! seeds. Review changes to that file as protocol wire-format changes.

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use kutup_federation_proto::{
    federation_key_id, grouped_fingerprint, FederationCapabilityId, FederationDiscoveryV2,
    FederationFeature, FederationHttpRequest, FederationHttpResponse, FederationIdentityDocumentV1,
    FederationProtocolVersion, FederationSignedRequest, FederationVerifiedRequest,
};
use serde_json::json;

fn main() {
    let identity_seed = [11; 32];
    let rotated_seed = [12; 32];
    let response_seed = [13; 32];
    let identity_key = SigningKey::from_bytes(&identity_seed);
    let rotated_key = SigningKey::from_bytes(&rotated_seed);
    let response_key = SigningKey::from_bytes(&response_seed);

    let genesis =
        FederationIdentityDocumentV1::genesis("alpha.example", 1_700_000_000, &identity_key)
            .unwrap();
    let rotation =
        FederationIdentityDocumentV1::rotate(&genesis, 1_700_000_100, &identity_key, &rotated_key)
            .unwrap();
    let discovery = FederationDiscoveryV2::sign(
        "alpha.example",
        "https://federation.alpha.example/api/fed",
        vec![
            FederationCapabilityId::identity_v1(),
            FederationCapabilityId::drive_v1(),
            FederationCapabilityId::chat_v1(),
        ],
        rotation.clone(),
        1_700_000_200,
        1_700_003_800,
        &rotated_key,
    )
    .unwrap();

    let request = FederationHttpRequest {
        method: "POST".into(),
        authority: "beta.example".into(),
        path: "/api/fed/chat/v1/transactions".into(),
        query: "?batch=1%2F2".into(),
        content_type: "application/json".into(),
        body: br#"{"transactionId":"01HXYZ"}"#.to_vec(),
        federation_version: FederationProtocolVersion::V2,
        feature: FederationFeature::ChatV1,
        origin: "alpha.example".into(),
        destination: "beta.example".into(),
    };
    let signed_request = FederationSignedRequest::sign(
        request,
        "01HZX-test-nonce",
        1_700_000_300,
        1_700_000_600,
        &rotated_key,
    )
    .unwrap();
    let verified_request = FederationVerifiedRequest::verify(
        signed_request.request.clone(),
        signed_request.headers.clone(),
        &rotated_key.verifying_key().to_bytes(),
        1_700_000_400,
    )
    .unwrap();
    let response = FederationHttpResponse {
        status: 202,
        content_type: "application/json".into(),
        body: br#"{"accepted":true}"#.to_vec(),
        federation_version: FederationProtocolVersion::V2,
        feature: FederationFeature::ChatV1,
        origin: "beta.example".into(),
        destination: "alpha.example".into(),
    };
    let response_headers = verified_request
        .sign_response(&response, 1_700_000_401, 1_700_000_601, &response_key)
        .unwrap();
    let genesis_hash = genesis.document_hash().unwrap();
    let rotation_hash = rotation.document_hash().unwrap();
    let request_signature_base = signed_request.signature_base().unwrap();
    let response_signature_base = verified_request
        .response_signature_base(&response, &response_headers)
        .unwrap();

    let vector = json!({
        "description": "Kutup unified federation v2 deterministic Ed25519 conformance vector; seeds are test-only",
        "identity": {
            "genesisSeedBase64": base64::engine::general_purpose::STANDARD.encode(identity_seed),
            "rotatedSeedBase64": base64::engine::general_purpose::STANDARD.encode(rotated_seed),
            "genesis": genesis,
            "genesisDocumentHash": genesis_hash,
            "rotation": rotation,
            "rotationDocumentHash": rotation_hash,
            "rotationFingerprint": grouped_fingerprint(&rotation.key.key_id).unwrap(),
        },
        "discovery": discovery,
        "httpSignature": {
            "requestSignerPublicKeyBase64": base64::engine::general_purpose::STANDARD.encode(rotated_key.verifying_key().to_bytes()),
            "requestSignerKeyId": federation_key_id(&rotated_key.verifying_key().to_bytes()),
            "request": {
                "method": signed_request.request.method,
                "authority": signed_request.request.authority,
                "path": signed_request.request.path,
                "query": signed_request.request.query,
                "contentType": signed_request.request.content_type,
                "bodyBase64": base64::engine::general_purpose::STANDARD.encode(&signed_request.request.body),
                "fedVersion": u16::from(signed_request.request.federation_version),
                "feature": signed_request.request.feature.as_str(),
                "origin": signed_request.request.origin,
                "destination": signed_request.request.destination,
            },
            "requestHeaders": signed_request.headers,
            "requestSignatureBase": request_signature_base,
            "responseSignerSeedBase64": base64::engine::general_purpose::STANDARD.encode(response_seed),
            "responseSignerPublicKeyBase64": base64::engine::general_purpose::STANDARD.encode(response_key.verifying_key().to_bytes()),
            "responseSignerKeyId": federation_key_id(&response_key.verifying_key().to_bytes()),
            "response": {
                "status": response.status,
                "contentType": response.content_type,
                "bodyBase64": base64::engine::general_purpose::STANDARD.encode(&response.body),
                "fedVersion": u16::from(response.federation_version),
                "feature": response.feature.as_str(),
                "origin": response.origin,
                "destination": response.destination,
            },
            "responseHeaders": response_headers,
            "responseSignatureBase": response_signature_base,
        }
    });
    println!("{}", serde_json::to_string_pretty(&vector).unwrap());
}
