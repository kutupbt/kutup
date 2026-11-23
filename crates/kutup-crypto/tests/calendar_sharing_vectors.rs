//! Checked-in vectors for shared calendars (docs/plans/calendar-e3.md, E3a):
//! a calendar at its second key generation, the owner's share of that
//! generation's passphrase to a member (signed by the owner, sealed to the
//! member's account key), and a full link: the generation's passphrase
//! under the link secret and the secret under the passphrase, with fixed
//! nonces so those bytes are exact. HPKE and OpenPGP output is random, so
//! the share and the key are fixed values that must open (in Rust here and
//! in the browser through `scripts/test-crypto-wasm.mjs`).
//! Regenerate only for a deliberate format change:
//! `KUTUP_WRITE_CALENDAR_VECTORS=1 cargo test -p kutup-crypto --features calendar,test-vectors --test calendar_sharing_vectors -- --ignored`

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kutup_crypto::account_ref::AccountRef;
use kutup_crypto::account_roots::IdentityRoot;
use kutup_crypto::calendar::{
    generate_calendar_key, next_key_generation, open_own_passphrase, open_passphrase,
    seal_own_passphrase, seal_passphrase, unlock_calendar_key, CalendarMember, CalendarOwner,
    CalendarShareEnvelopeV1, Passphrase, SealedMetadataV1, FIRST_KEY_GENERATION,
};
use kutup_crypto::calendar_link::{self, LinkSecret};
use kutup_crypto::identity::AccountIdentityKeysV1;

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/calendar-sharing-v1.json"
);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    calendar_id: String,
    owner_account: String,
    owner_identity_root: String,
    /// What a member checks the owner's shares against (hex incarnation,
    /// base64 account signing key), as the owner's verified binding names.
    owner_incarnation_id: String,
    owner_signing_public_key: String,
    member_account: String,
    member_identity_root: String,
    member_incarnation_id: String,
    member_xwing_public_key: String,
    key_generation: u32,
    passphrase: String,
    calendar_locked_secret_key: String,
    calendar_fingerprint: String,
    /// The calendar key's encryption subkey's key ID (hex).
    calendar_key_id: String,
    /// The owner's own share and the member's, of this generation.
    own_share: String,
    member_share: String,
    /// Shares the member must refuse at this generation.
    refused_member_shares: Vec<Refused>,
    link_id: String,
    /// As the URL carries it.
    link_url_secret: String,
    /// This generation's passphrase under the link secret.
    link_passphrase: String,
    /// The link secret under this generation's passphrase.
    link_secret: String,
    refused_link_passphrases: Vec<Refused>,
    /// The link's purpose, sealed to the calendar key and signed by the
    /// owner's address key (the mail vectors' key, public here).
    owner_address_public_key: String,
    link_purpose_text: String,
    link_purpose: SealedMetadataV1,
}

#[derive(Serialize, Deserialize)]
struct Refused {
    why: String,
    sealed: String,
}

const OWNER_ACCOUNT: &str = "aci:3b0f6a52-7c1e-4d8a-9f2b-5e6c7d8a9b0c@kutup.dev";
const MEMBER_ACCOUNT: &str = "aci:9c4b2f0e-1d3a-4e5b-8c6d-7e8f9a0b1c2d@kutup.dev";

fn identity(root: &[u8]) -> AccountIdentityKeysV1 {
    AccountIdentityKeysV1::derive(&IdentityRoot::from_bytes(root.try_into().unwrap())).unwrap()
}

fn b64(value: &str) -> Vec<u8> {
    STANDARD.decode(value).unwrap()
}

fn share_to(
    passphrase: &Passphrase,
    calendar_id: &str,
    generation: u32,
    owner: &AccountRef,
    owner_keys: &AccountIdentityKeysV1,
    member: &AccountRef,
    member_keys: &AccountIdentityKeysV1,
) -> String {
    let incarnation = member_keys.incarnation_id();
    let xwing = member_keys.drive_xwing_public_key();
    seal_passphrase(
        passphrase,
        calendar_id,
        generation,
        owner,
        owner_keys,
        &CalendarMember {
            account: member,
            incarnation_id: &incarnation,
            xwing_public_key: &xwing,
        },
    )
    .unwrap()
    .encode_b64()
    .unwrap()
}

#[test]
#[ignore = "writes the vectors"]
fn write_vectors() {
    if std::env::var("KUTUP_WRITE_CALENDAR_VECTORS").is_err() {
        return;
    }
    let calendar_id = "6f1d3c2a-8b4e-4f7a-9c1d-2e3f4a5b6c7d";
    let link_id = "0b6e1f3a-2c4d-4e5f-8a9b-0c1d2e3f4a5b";
    let generation = next_key_generation(FIRST_KEY_GENERATION).unwrap();
    let owner_root = [0x5au8; 32];
    let member_root = [0x6bu8; 32];
    let owner: AccountRef = OWNER_ACCOUNT.parse().unwrap();
    let member: AccountRef = MEMBER_ACCOUNT.parse().unwrap();
    let owner_keys = identity(&owner_root);
    let member_keys = identity(&member_root);
    let stranger: AccountRef = "aci:7d2e4f6a-8b0c-4d1e-9f2a-3b4c5d6e7f80@kutup.dev"
        .parse()
        .unwrap();
    let stranger_keys = identity(&[0x7cu8; 32]);

    let passphrase = Passphrase::generate();
    let calendar = generate_calendar_key(&passphrase, 1_790_000_000).unwrap();
    let share = |id: &str, generation: u32, to: &AccountRef, keys: &AccountIdentityKeysV1| {
        share_to(&passphrase, id, generation, &owner, &owner_keys, to, keys)
    };
    let own_share = seal_own_passphrase(&passphrase, calendar_id, generation, &owner, &owner_keys)
        .unwrap()
        .encode_b64()
        .unwrap();
    // Shared by someone else than the owner: signed by the stranger.
    let by_stranger = share_to(
        &passphrase,
        calendar_id,
        generation,
        &stranger,
        &stranger_keys,
        &member,
        &member_keys,
    );
    let refused_member_shares = vec![
        Refused {
            why: "the previous generation's share".into(),
            sealed: share(calendar_id, FIRST_KEY_GENERATION, &member, &member_keys),
        },
        Refused {
            why: "another calendar's share".into(),
            sealed: share(
                "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
                generation,
                &member,
                &member_keys,
            ),
        },
        Refused {
            why: "a share to another member".into(),
            sealed: share(calendar_id, generation, &stranger, &stranger_keys),
        },
        Refused {
            why: "a share someone else signed".into(),
            sealed: by_stranger,
        },
    ];

    let secret = LinkSecret::from_bytes(&[0x2du8; 32]).unwrap();
    let nonce = [0x11u8; 24];
    let link_passphrase = calendar_link::vectors::seal_link_passphrase(
        &secret,
        calendar_id,
        link_id,
        generation,
        &passphrase,
        &nonce,
    )
    .unwrap();
    let link_secret = calendar_link::vectors::seal_link_secret(
        &passphrase,
        calendar_id,
        link_id,
        generation,
        &secret,
        &nonce,
    )
    .unwrap();
    let other = |calendar: &str, link: &str, generation: u32| {
        calendar_link::encode(
            &calendar_link::vectors::seal_link_passphrase(
                &secret,
                calendar,
                link,
                generation,
                &passphrase,
                &nonce,
            )
            .unwrap(),
        )
    };
    let mut tampered = link_passphrase.clone();
    *tampered.last_mut().unwrap() ^= 1;
    let refused_link_passphrases = vec![
        Refused {
            why: "the previous generation's".into(),
            sealed: other(calendar_id, link_id, FIRST_KEY_GENERATION),
        },
        Refused {
            why: "another link's".into(),
            sealed: other(
                calendar_id,
                "2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e",
                generation,
            ),
        },
        Refused {
            why: "another calendar's".into(),
            sealed: other("1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d", link_id, generation),
        },
        Refused {
            why: "a changed tag".into(),
            sealed: calendar_link::encode(&tampered),
        },
    ];

    // The owner's address key: the mail vectors' (the browser check opens
    // its sealed envelope there).
    let mail: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/mail-address-key-v1.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let owner_address_secret = b64(mail["secretKey"].as_str().unwrap());
    let purpose_text = "Family — İstanbul";
    let link_purpose = calendar
        .unlocked
        .seal_link_purpose(calendar_id, link_id, purpose_text, &owner_address_secret)
        .unwrap();

    let vectors = Vectors {
        calendar_id: calendar_id.into(),
        owner_account: OWNER_ACCOUNT.into(),
        owner_identity_root: STANDARD.encode(owner_root),
        owner_incarnation_id: owner_keys.incarnation_id(),
        owner_signing_public_key: STANDARD.encode(owner_keys.drive_signing_public_key()),
        member_account: MEMBER_ACCOUNT.into(),
        member_identity_root: STANDARD.encode(member_root),
        member_incarnation_id: member_keys.incarnation_id(),
        member_xwing_public_key: STANDARD.encode(member_keys.drive_xwing_public_key()),
        key_generation: generation,
        passphrase: passphrase.as_str().to_owned(),
        calendar_locked_secret_key: STANDARD.encode(&calendar.locked_secret_key),
        calendar_fingerprint: hex::encode(calendar.fingerprint),
        calendar_key_id: hex::encode(calendar.unlocked.key_id().unwrap()),
        own_share,
        member_share: share(calendar_id, generation, &member, &member_keys),
        refused_member_shares,
        link_id: link_id.into(),
        link_url_secret: secret.to_url(),
        link_passphrase: calendar_link::encode(&link_passphrase),
        link_secret: calendar_link::encode(&link_secret),
        refused_link_passphrases,
        owner_address_public_key: mail["publicKey"].as_str().unwrap().to_owned(),
        link_purpose_text: purpose_text.into(),
        link_purpose: SealedMetadataV1::of(&link_purpose),
    };
    std::fs::write(PATH, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
}

fn vectors() -> Vectors {
    serde_json::from_str(&std::fs::read_to_string(PATH).expect("vectors")).expect("JSON")
}

#[test]
fn calendar_sharing_vectors_open() {
    let v = vectors();
    let owner: AccountRef = v.owner_account.parse().unwrap();
    let member: AccountRef = v.member_account.parse().unwrap();
    let owner_keys = identity(&b64(&v.owner_identity_root));
    let member_keys = identity(&b64(&v.member_identity_root));
    assert_eq!(owner_keys.incarnation_id(), v.owner_incarnation_id);
    assert_eq!(member_keys.incarnation_id(), v.member_incarnation_id);
    let signing = b64(&v.owner_signing_public_key);
    let open_member = |share: &str| {
        open_passphrase(
            &CalendarShareEnvelopeV1::decode_b64(share)?,
            &v.calendar_id,
            v.key_generation,
            &CalendarOwner {
                account: &owner,
                incarnation_id: &v.owner_incarnation_id,
                signing_public_key: &signing,
            },
            &member,
            &member_keys,
        )
    };

    // The member opens their share; the owner their own; the same passphrase.
    let passphrase = open_member(&v.member_share).unwrap();
    assert_eq!(passphrase.as_str(), v.passphrase);
    let own = open_own_passphrase(
        &CalendarShareEnvelopeV1::decode_b64(&v.own_share).unwrap(),
        &v.calendar_id,
        v.key_generation,
        &owner,
        &owner_keys,
    )
    .unwrap();
    assert_eq!(own.as_str(), v.passphrase);
    assert!(!v.refused_member_shares.is_empty());
    for case in &v.refused_member_shares {
        assert!(
            open_member(&case.sealed).is_err(),
            "{} was accepted",
            case.why
        );
    }
    let unlocked = unlock_calendar_key(&b64(&v.calendar_locked_secret_key), &passphrase).unwrap();
    assert_eq!(hex::encode(unlocked.fingerprint()), v.calendar_fingerprint);
    assert_eq!(hex::encode(unlocked.key_id().unwrap()), v.calendar_key_id);

    // The link: exact bytes with the fixed nonce, and they open.
    let secret = LinkSecret::from_url(&v.link_url_secret).unwrap();
    let nonce = [0x11u8; 24];
    assert_eq!(
        calendar_link::encode(
            &calendar_link::vectors::seal_link_passphrase(
                &secret,
                &v.calendar_id,
                &v.link_id,
                v.key_generation,
                &passphrase,
                &nonce,
            )
            .unwrap()
        ),
        v.link_passphrase
    );
    assert_eq!(
        calendar_link::encode(
            &calendar_link::vectors::seal_link_secret(
                &passphrase,
                &v.calendar_id,
                &v.link_id,
                v.key_generation,
                &secret,
                &nonce,
            )
            .unwrap()
        ),
        v.link_secret
    );
    let open_link = |sealed: &str| {
        calendar_link::open_link_passphrase(
            &secret,
            &v.calendar_id,
            &v.link_id,
            v.key_generation,
            &calendar_link::decode(sealed)?,
        )
    };
    assert_eq!(
        open_link(&v.link_passphrase).unwrap().as_str(),
        v.passphrase
    );
    assert!(!v.refused_link_passphrases.is_empty());
    for case in &v.refused_link_passphrases {
        assert!(
            open_link(&case.sealed).is_err(),
            "{} was accepted",
            case.why
        );
    }
    let opened = calendar_link::open_link_secret(
        &passphrase,
        &v.calendar_id,
        &v.link_id,
        v.key_generation,
        &calendar_link::decode(&v.link_secret).unwrap(),
    )
    .unwrap();
    assert_eq!(opened.to_url(), v.link_url_secret);

    // The link's purpose: opens under its calendar and link, signed by the
    // owner's address key; refused under another link, unverified with
    // another key.
    let sealed = v.link_purpose.to_sealed().unwrap();
    let owner_address = b64(&v.owner_address_public_key);
    let (purpose, verified) = unlocked
        .open_link_purpose(&sealed, &v.calendar_id, &v.link_id, &[&owner_address])
        .unwrap();
    assert_eq!(purpose, v.link_purpose_text);
    assert!(verified);
    assert!(unlocked
        .open_link_purpose(
            &sealed,
            &v.calendar_id,
            "2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e",
            &[&owner_address]
        )
        .is_err());
    let (_, by_other) = unlocked
        .open_link_purpose(
            &sealed,
            &v.calendar_id,
            &v.link_id,
            &[b"not a key".as_slice()],
        )
        .unwrap();
    assert!(!by_other);
}
