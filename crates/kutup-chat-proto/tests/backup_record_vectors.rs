//! Checked-in vectors for Chat backup records (docs/plans/format-evolution.md,
//! "Chat backup records"): a segment holding a display record and a record
//! of a type this reader doesn't know (kept as it came), segments that are
//! corrupt, and one of a newer version.
//! Regenerate only for a deliberate format change:
//! `KUTUP_WRITE_BACKUP_RECORD_VECTORS=1 cargo test -p kutup-chat-proto --test backup_record_vectors -- --ignored`.

use kutup_chat_proto::{ChatBackupRecordV1, ChatBackupSegmentPlaintextV1};
use serde::{Deserialize, Serialize};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/chat-backup-records-v1.json"
);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    description: String,
    /// Canonical segment plaintext: a display record, then one of an
    /// unknown type.
    segment: String,
    /// The record types in order, as a reader sees them.
    types: Vec<String>,
    /// Corrupt segments.
    invalid: Vec<String>,
    /// Segments of a version above this reader's: "newer format: ".
    newer: Vec<String>,
}

fn build() -> Vectors {
    let display = serde_json::json!({
        "type": "display",
        "version": 1,
        "recordId": "55555555-5555-4555-8555-555555555555",
        "mutationSequence": 1,
        "conversation": {"kind": "direct", "account": {"server": "b.test", "accountId": "00000000-0000-4000-8000-000000000002"}},
        "sender": {"server": "a.test", "accountId": "00000000-0000-4000-8000-000000000001"},
        "senderDeviceId": 1,
        "outgoing": true,
        "content": {"version": 1, "kind": "text", "sentAt": "2026-08-11T12:00:00Z", "seq": "1", "body": {"text": "protected"}},
        "timestampMs": 1_800_000_000_000_i64,
        "delivered": true,
        "tombstone": false
    });
    let other = serde_json::json!({
        "type": "pinnedNote",
        "recordId": "77777777-7777-4777-8777-777777777777",
        "mutationSequence": 3,
        "tombstone": false,
        "note": {"text": "a newer client's record"}
    });
    let parsed: ChatBackupSegmentPlaintextV1 = serde_json::from_value(serde_json::json!({
        "version": 1,
        "records": [display, other],
    }))
    .unwrap();
    let segment = String::from_utf8(parsed.canonical_bytes().unwrap()).unwrap();
    let invalid = vec![
        // A display record without its type.
        segment.replacen(r#""type":"display","#, "", 1),
        // An unknown type without its frame.
        segment.replacen(r#""mutationSequence":3,"#, "", 1),
        // "display" spelled another way is no unknown type.
        segment.replacen(r#""type":"display""#, r#""type":"Display""#, 1),
        "garbage".into(),
    ];
    let newer = vec![
        segment.replacen(r#"{"version":1,"#, r#"{"version":2,"#, 1),
        // A newer version whose records changed shape is still newer.
        r#"{"version":2,"records":[{"shape":"new"}]}"#.into(),
    ];
    Vectors {
        description: "Chat backup segment plaintext (kutup-chat-proto/src/backup.rs): every record has a type; a type this reader doesn't know is kept by its frame (recordId, mutationSequence, tombstone) and re-encodes unchanged; a newer version is newer than this reader.".into(),
        segment,
        types: vec!["display".into(), "pinnedNote".into()],
        invalid,
        newer,
    }
}

#[test]
#[ignore = "writes the vectors"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_BACKUP_RECORD_VECTORS").as_deref() != Ok("1") {
        return;
    }
    std::fs::write(PATH, serde_json::to_string_pretty(&build()).unwrap() + "\n").unwrap();
}

#[test]
fn checked_in_vectors_hold() {
    let v: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    let segment = ChatBackupSegmentPlaintextV1::from_canonical_bytes(v.segment.as_bytes()).unwrap();
    let types: Vec<&str> = segment
        .records
        .iter()
        .map(|record| match record {
            ChatBackupRecordV1::Display(record) => record.record_type.as_str(),
            ChatBackupRecordV1::Other(record) => record.record_type.as_str(),
        })
        .collect();
    assert_eq!(types, v.types);
    assert_eq!(segment.canonical_bytes().unwrap(), v.segment.as_bytes());
    for bad in &v.invalid {
        let error = ChatBackupSegmentPlaintextV1::from_canonical_bytes(bad.as_bytes()).unwrap_err();
        assert!(!error.starts_with("newer format: "), "{bad}");
    }
    for newer in &v.newer {
        let error =
            ChatBackupSegmentPlaintextV1::from_canonical_bytes(newer.as_bytes()).unwrap_err();
        assert!(error.starts_with("newer format: "), "{newer}");
    }
}
