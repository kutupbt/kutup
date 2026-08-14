use base64::Engine as _;
use ed25519_dalek::SigningKey;
use kutup_federation_proto::{
    grouped_fingerprint, verify_identity_chain, FederationCapabilityId, FederationDiscoveryV2,
    FederationFeature, FederationHttpRequest, FederationHttpResponse, FederationIdentityDocumentV1,
    FederationProtocolVersion, FederationSignatureHeaders, FederationSignedRequest,
    FederationVerifiedRequest,
};
use serde_json::Value;

const VECTOR: &str = include_str!("../test-vectors/federation-v2.json");

fn seed(value: &Value, field: &str) -> SigningKey {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value[field].as_str().unwrap())
        .unwrap();
    SigningKey::from_bytes(&decoded.try_into().unwrap())
}

fn body(value: &Value) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(value["bodyBase64"].as_str().unwrap())
        .unwrap()
}

#[test]
fn published_vector_is_byte_for_byte_reproducible_and_verifiable() {
    let vector: Value = serde_json::from_str(VECTOR).unwrap();
    let identity_vector = &vector["identity"];
    let genesis_key = seed(identity_vector, "genesisSeedBase64");
    let rotated_key = seed(identity_vector, "rotatedSeedBase64");

    let genesis: FederationIdentityDocumentV1 =
        serde_json::from_value(identity_vector["genesis"].clone()).unwrap();
    let rotation: FederationIdentityDocumentV1 =
        serde_json::from_value(identity_vector["rotation"].clone()).unwrap();
    verify_identity_chain("alpha.example", &[genesis.clone(), rotation.clone()]).unwrap();
    assert_eq!(
        genesis.document_hash().unwrap(),
        identity_vector["genesisDocumentHash"].as_str().unwrap()
    );
    assert_eq!(
        rotation.document_hash().unwrap(),
        identity_vector["rotationDocumentHash"].as_str().unwrap()
    );
    assert_eq!(
        grouped_fingerprint(&rotation.key.key_id).unwrap(),
        identity_vector["rotationFingerprint"].as_str().unwrap()
    );
    assert_eq!(
        FederationIdentityDocumentV1::genesis("alpha.example", 1_700_000_000, &genesis_key,)
            .unwrap(),
        genesis
    );
    assert_eq!(
        FederationIdentityDocumentV1::rotate(&genesis, 1_700_000_100, &genesis_key, &rotated_key,)
            .unwrap(),
        rotation
    );

    let discovery: FederationDiscoveryV2 =
        serde_json::from_value(vector["discovery"].clone()).unwrap();
    discovery.verify_at("alpha.example", 1_700_000_300).unwrap();
    assert_eq!(
        FederationDiscoveryV2::sign(
            "alpha.example",
            "https://federation.alpha.example/api/fed",
            vec![
                FederationCapabilityId::identity_v1(),
                FederationCapabilityId::drive_v1(),
                FederationCapabilityId::chat_v1(),
            ],
            rotation,
            1_700_000_200,
            1_700_003_800,
            &rotated_key,
        )
        .unwrap(),
        discovery
    );

    let http = &vector["httpSignature"];
    let request_value = &http["request"];
    let request = FederationHttpRequest {
        method: request_value["method"].as_str().unwrap().into(),
        authority: request_value["authority"].as_str().unwrap().into(),
        path: request_value["path"].as_str().unwrap().into(),
        query: request_value["query"].as_str().unwrap().into(),
        content_type: request_value["contentType"].as_str().unwrap().into(),
        body: body(request_value),
        federation_version: FederationProtocolVersion::V2,
        feature: FederationFeature::ChatV1,
        origin: request_value["origin"].as_str().unwrap().into(),
        destination: request_value["destination"].as_str().unwrap().into(),
    };
    let expected_request_headers: FederationSignatureHeaders =
        serde_json::from_value(http["requestHeaders"].clone()).unwrap();
    let signed_request = FederationSignedRequest::sign(
        request,
        "01HZX-test-nonce",
        1_700_000_300,
        1_700_000_600,
        &rotated_key,
    )
    .unwrap();
    assert_eq!(signed_request.headers, expected_request_headers);
    assert_eq!(
        signed_request.signature_base().unwrap(),
        http["requestSignatureBase"].as_str().unwrap()
    );
    let verified_request = FederationVerifiedRequest::verify(
        signed_request.request.clone(),
        expected_request_headers,
        &rotated_key.verifying_key().to_bytes(),
        1_700_000_400,
    )
    .unwrap();

    let response_value = &http["response"];
    let response = FederationHttpResponse {
        status: response_value["status"].as_u64().unwrap() as u16,
        content_type: response_value["contentType"].as_str().unwrap().into(),
        body: body(response_value),
        federation_version: FederationProtocolVersion::V2,
        feature: FederationFeature::ChatV1,
        origin: response_value["origin"].as_str().unwrap().into(),
        destination: response_value["destination"].as_str().unwrap().into(),
    };
    let response_key = seed(http, "responseSignerSeedBase64");
    let expected_response_headers: FederationSignatureHeaders =
        serde_json::from_value(http["responseHeaders"].clone()).unwrap();
    let response_headers = verified_request
        .sign_response(&response, 1_700_000_401, 1_700_000_601, &response_key)
        .unwrap();
    assert_eq!(response_headers, expected_response_headers);
    assert_eq!(
        verified_request
            .response_signature_base(&response, &response_headers)
            .unwrap(),
        http["responseSignatureBase"].as_str().unwrap()
    );
    signed_request
        .verify_response(
            response,
            &response_headers,
            &response_key.verifying_key().to_bytes(),
            1_700_000_500,
        )
        .unwrap();
}
