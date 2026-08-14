#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use kutup_crypto::chat_attachment_ledger;
    use kutup_crypto::chat_media::{self, ChatMediaObjectContextV1};

    let _ = chat_attachment_ledger::inspect(data);
    let _ = chat_attachment_ledger::envelope_digest(data);

    if let Ok(context) = ChatMediaObjectContextV1::new("11111111-1111-4111-8111-111111111111") {
        let _ = chat_media::validate_public_object(data, context);
        if data.len() >= chat_media::CHAT_MEDIA_OBJECT_HEADER_BYTES {
            let _ = chat_media::inspect_object_header(
                &data[..chat_media::CHAT_MEDIA_OBJECT_HEADER_BYTES],
            );
        }
    }

    if let Ok(json) = std::str::from_utf8(data) {
        if let Ok(value) =
            serde_json::from_str::<kutup_chat_proto::ChatAttachmentDescriptorV1>(json)
        {
            let _ = value.validate();
        }
        if let Ok(value) = serde_json::from_str::<kutup_chat_proto::ChatMediaDeliveryOfferV1>(json)
        {
            let _ = value.validate("example.test", 1_700_000_000);
        }
        if let Ok(value) =
            serde_json::from_str::<kutup_chat_proto::FederatedChatMediaTransactionV1>(json)
        {
            let _ = value.validate("example.test", 1_700_000_000);
        }
        let _ = serde_json::from_str::<kutup_chat_proto::ChatMediaOfferResponseV1>(json);
        let _ = serde_json::from_str::<kutup_chat_proto::ChatMediaCapabilitiesV1>(json);
        if let Ok(value) =
            serde_json::from_str::<kutup_chat_proto::ChatAttachmentLedgerPutReceiptV1>(json)
        {
            let _ = value.validate();
        }
        if let Ok(value) =
            serde_json::from_str::<kutup_chat_proto::ChatAttachmentLedgerDiffPageV1>(json)
        {
            let _ = value.validate("0");
        }
    }

    if let Ok(entry) = kutup_chat_proto::ChatAttachmentLedgerEntryV1::from_canonical_bytes(data) {
        let _ = entry.canonical_bytes();
    }
});
