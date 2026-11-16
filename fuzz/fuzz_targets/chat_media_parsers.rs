#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = kutup_crypto::account_record::validate_for(
        data,
        kutup_crypto::account_record::AccountRecordPurpose::ChatAttachmentLedger,
        "0b6b5e0c-4c1e-4b8e-9c2d-6a1f3e5d7c9b",
        &[0u8; 32],
    );

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
    }

    if let Ok(entry) = kutup_chat_proto::ChatAttachmentLedgerEntryV1::from_canonical_bytes(data) {
        let _ = entry.canonical_bytes();
    }
});
