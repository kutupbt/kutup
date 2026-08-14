#![no_main]

use base64::Engine as _;
use kutup_chat_proto::{
    AnonymousPreKeyRequestV1, FederatedSealedTransactionV1, SealedMessageSubmissionV1,
    SenderCertificateResponseV1,
};
use libfuzzer_sys::fuzz_target;
use libsignal_protocol::{
    sealed_sender_decrypt_to_usmc, IdentityKeyPair, InMemIdentityKeyStore, PrivateKey,
    SenderCertificate, UnidentifiedSenderMessageContent,
};

const MAX_INPUT_BYTES: usize = 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let _ = SenderCertificate::deserialize(data);
    let _ = UnidentifiedSenderMessageContent::deserialize(data);
    let mut identity_store = fixed_identity_store();
    let _ = futures_executor::block_on(sealed_sender_decrypt_to_usmc(data, &mut identity_store));

    if let Ok(response) = serde_json::from_slice::<SenderCertificateResponseV1>(data) {
        if let Ok(certificate) =
            base64::engine::general_purpose::STANDARD.decode(&response.certificate)
        {
            if base64::engine::general_purpose::STANDARD.encode(&certificate)
                == response.certificate
            {
                let _ = SenderCertificate::deserialize(&certificate);
            }
        }
    }
    if let Ok(request) = serde_json::from_slice::<AnonymousPreKeyRequestV1>(data) {
        let _ = request.capability_bytes();
    }
    if let Ok(request) = serde_json::from_slice::<SealedMessageSubmissionV1>(data) {
        let _ = request.validate();
        for envelope in request.envelopes.iter().take(32) {
            if let Ok(ciphertext) =
                base64::engine::general_purpose::STANDARD.decode(&envelope.content)
            {
                let mut identity_store = fixed_identity_store();
                let _ = futures_executor::block_on(sealed_sender_decrypt_to_usmc(
                    &ciphertext,
                    &mut identity_store,
                ));
            }
        }
    }
    if let Ok(transaction) = serde_json::from_slice::<FederatedSealedTransactionV1>(data) {
        let _ = transaction.validate(&transaction.origin, "destination.example");
    }
});

fn fixed_identity_store() -> InMemIdentityKeyStore {
    let private_key = PrivateKey::deserialize(&[0x42; 32]).expect("fixed private key is valid");
    let public_key = private_key
        .public_key()
        .expect("fixed private key has a public key");
    let identity = IdentityKeyPair::new(public_key.into(), private_key);
    InMemIdentityKeyStore::new(identity, 1)
}
