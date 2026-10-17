#![no_main]

use kutup_crypto::account_ref::AccountRef;
use kutup_crypto::collection_epoch::CollectionEpochStatementV1;
use kutup_crypto::drive_envelope::{self, DriveEnvelopeContextV1, DriveEnvelopePurpose};
use kutup_crypto::drive_object::{self, DriveFileBlobContextV1, FILE_BLOB_HEADER_BYTES};
use kutup_crypto::envelope;
use kutup_crypto::named_share::NamedShareEnvelopeV1;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() >= FILE_BLOB_HEADER_BYTES {
        let header = &data[..FILE_BLOB_HEADER_BYTES];
        let _ = drive_object::inspect_file_blob_header(header);
        let context = DriveFileBlobContextV1::new("22222222-2222-4222-8222-222222222222", 1)
            .expect("fixed fuzz context is valid");
        let _ = drive_object::validate_file_blob_header(header, context);
        let _ = drive_object::decrypt_file_blob(data, &[0x5a; 32], context);
    }
    if let Ok(statement) = CollectionEpochStatementV1::decode(data) {
        let _ = statement.verify_authority(&[0x41; 32]);
        let _ = statement.verify_collection_key(&[0x42; 32]);
        let _ = statement.statement_hash();
    }
    if let Ok(envelope) = NamedShareEnvelopeV1::decode(data) {
        let alice = AccountRef::new("a.test", "3f1c9a52-6b7e-4f0e-9d1a-2c3b4d5e6f70")
            .expect("fixed fuzz account is valid");
        let bob = AccountRef::new("b.test", "8d2e4b61-0c3a-4e9f-b7d5-6a1f2e3c4d5b")
            .expect("fixed fuzz account is valid");
        let _ = envelope.open(
            "11111111-1111-4111-8111-111111111111",
            1,
            &alice,
            &"1".repeat(64),
            &[0x41; 32],
            &bob,
            &"2".repeat(64),
            &[0x42; 32],
        );
    }
    let _ = envelope::Frame::unpack(data);
    let _ = envelope::verify(data, &[0x41; 32]);
    let _ = envelope::open(data, &[0x42; 32], "22222222-2222-4222-8222-222222222222", 1);
    let _ = drive_envelope::inspect(data);
    for purpose in [
        DriveEnvelopePurpose::CollectionKey,
        DriveEnvelopePurpose::CollectionName,
        DriveEnvelopePurpose::FileKey,
        DriveEnvelopePurpose::FileMetadata,
        DriveEnvelopePurpose::PublicLinkCollectionKey,
        DriveEnvelopePurpose::WhiteboardAsset,
    ] {
        let context = DriveEnvelopeContextV1::new(
            purpose,
            1,
            1,
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
        )
        .expect("fixed fuzz context is valid");
        let _ = drive_envelope::validate(data, context);
        let _ = drive_envelope::open(data, &[0x5a; 32], context);
    }
});
