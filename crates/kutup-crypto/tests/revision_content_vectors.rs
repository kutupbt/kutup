//! Checked-in vectors for a revision's sealed content commitment
//! (`kutup_crypto::revision_content`, docs/plans/drive-block-format.md §2):
//! the canonical record, its envelope under a fixed nonce, and negatives that
//! must not open (another revision as the parent, another file, another
//! generation, another purpose, a record naming another revision).
//! Regenerate only for a deliberate format change:
//! `KUTUP_WRITE_REVISION_CONTENT_VECTORS=1 cargo test -p kutup-crypto --test revision_content_vectors`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::drive_envelope::{self, DriveEnvelopeContextV1, DriveEnvelopePurpose};
use kutup_crypto::revision_content::{self, RevisionContentV1};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/revision-content-v1.json"
);

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    file_key: String,
    file_id: String,
    revision_id: String,
    generation: u32,
    nonce: String,
    content: RevisionContentV1,
    /// The canonical JSON the envelope seals.
    encoded: String,
    envelope: String,
    negatives: Vec<Negative>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
struct Negative {
    name: String,
    envelope: String,
    /// Opened as for the positive case, unless these say otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    file_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    revision_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    generation: Option<u32>,
}

const KEY: [u8; 32] = [0x42; 32];
const NONCE: [u8; 24] = [0x24; 24];
const FILE: &str = "11111111-1111-4111-8111-111111111111";
const REVISION: &str = "22222222-2222-4222-8222-222222222222";
const OTHER_FILE: &str = "33333333-3333-4333-8333-333333333333";
const OTHER_REVISION: &str = "44444444-4444-4444-8444-444444444444";
const GENERATION: u32 = 2;

fn build() -> Vectors {
    let content = RevisionContentV1 {
        revision_id: REVISION.into(),
        manifest_sha256: STANDARD.encode([0x5a; 32]),
        size: 4 * 1024 * 1024 + 17,
    };
    let encoded = revision_content::encode(&content).unwrap();
    let seal = |body: &[u8], context: DriveEnvelopeContextV1| {
        STANDARD.encode(drive_envelope::seal_with_nonce(body, &KEY, context, &NONCE).unwrap())
    };
    let envelope = STANDARD.encode(
        revision_content::seal_revision_content_with_nonce(
            &content, &KEY, FILE, GENERATION, &NONCE,
        )
        .unwrap(),
    );
    let mut naming_other = content.clone();
    naming_other.revision_id = OTHER_REVISION.into();
    let negatives = vec![
        Negative {
            name: "another revision as the parent".into(),
            envelope: envelope.clone(),
            file_id: None,
            revision_id: Some(OTHER_REVISION.into()),
            generation: None,
        },
        Negative {
            name: "another file".into(),
            envelope: envelope.clone(),
            file_id: Some(OTHER_FILE.into()),
            revision_id: None,
            generation: None,
        },
        Negative {
            name: "another key generation".into(),
            envelope: envelope.clone(),
            file_id: None,
            revision_id: None,
            generation: Some(GENERATION + 1),
        },
        Negative {
            name: "file metadata purpose, same ids".into(),
            envelope: seal(
                &encoded,
                DriveEnvelopeContextV1::new(
                    DriveEnvelopePurpose::FileMetadata,
                    GENERATION,
                    1,
                    FILE,
                    REVISION,
                )
                .unwrap(),
            ),
            file_id: None,
            revision_id: None,
            generation: None,
        },
        Negative {
            name: "sealed for this revision, naming another".into(),
            envelope: seal(
                &revision_content::encode(&naming_other).unwrap(),
                DriveEnvelopeContextV1::revision_content(FILE, REVISION, GENERATION).unwrap(),
            ),
            file_id: None,
            revision_id: None,
            generation: None,
        },
    ];
    Vectors {
        file_key: STANDARD.encode(KEY),
        file_id: FILE.into(),
        revision_id: REVISION.into(),
        generation: GENERATION,
        nonce: STANDARD.encode(NONCE),
        content,
        encoded: String::from_utf8(encoded).unwrap(),
        envelope,
        negatives,
    }
}

#[test]
fn revision_content_matches_its_vectors() {
    let built = build();
    if std::env::var_os("KUTUP_WRITE_REVISION_CONTENT_VECTORS").is_some() {
        std::fs::write(PATH, serde_json::to_string_pretty(&built).unwrap() + "\n").unwrap();
    }
    let stored: Vectors = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    assert_eq!(stored, built);

    let key = STANDARD.decode(&stored.file_key).unwrap();
    let envelope = STANDARD.decode(&stored.envelope).unwrap();
    revision_content::validate(
        &envelope,
        &stored.file_id,
        &stored.revision_id,
        stored.generation,
    )
    .unwrap();
    let opened = revision_content::open_revision_content(
        &envelope,
        &key,
        &stored.file_id,
        &stored.revision_id,
        stored.generation,
    )
    .unwrap();
    assert_eq!(opened, stored.content);
    assert_eq!(
        revision_content::encode(&opened).unwrap(),
        stored.encoded.as_bytes()
    );
    for negative in &stored.negatives {
        let bytes = STANDARD.decode(&negative.envelope).unwrap();
        let file = negative.file_id.as_deref().unwrap_or(&stored.file_id);
        let revision = negative
            .revision_id
            .as_deref()
            .unwrap_or(&stored.revision_id);
        let generation = negative.generation.unwrap_or(stored.generation);
        assert!(
            revision_content::open_revision_content(&bytes, &key, file, revision, generation)
                .is_err(),
            "{}",
            negative.name
        );
    }
}
