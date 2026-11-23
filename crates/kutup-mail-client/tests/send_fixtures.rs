//! tests/fixtures/send.json through `send`: the recipients split, the PGP
//! groups and the Kutup targets, or why the send can't go. `mail-core`'s
//! sendPlan.test.ts runs the same file through `sendPlan.ts`.

use std::collections::BTreeMap;

use kutup_mail_client::keys::AddressKeys;
use kutup_mail_client::protection::{KeySource, KutupLookup, Protection};
use kutup_mail_client::send::{
    everyone, kutup_targets, pgp_groups, split_recipients, KutupRecipient, PgpGroup, Scheme,
    SendError, Targets,
};
use serde::Deserialize;

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/send.json");

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProtectionInput {
    kind: String,
    public_key: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Member {
    address: String,
    primary: String,
    encryption_disabled: bool,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum RecipientInput {
    #[serde(rename_all = "camelCase")]
    Keys {
        primary: String,
        encryption_disabled: bool,
    },
    Group {
        members: Vec<Member>,
    },
    NotKutup,
    Disabled,
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
struct Plan {
    local: Vec<String>,
    external: Vec<String>,
    groups: Vec<PgpGroup>,
    plain: Vec<String>,
    targets: Targets,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Expect {
    Refused { error: SendError },
    Sent(Plan),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    name: String,
    to: Vec<String>,
    cc: Vec<String>,
    bcc: Vec<String>,
    own_domain: String,
    sender: String,
    encrypt: bool,
    default_scheme: Scheme,
    lookups: BTreeMap<String, String>,
    pinned_keys: Vec<String>,
    schemes: BTreeMap<String, Scheme>,
    protections: BTreeMap<String, ProtectionInput>,
    recipients: BTreeMap<String, RecipientInput>,
    expect: Expect,
}

#[derive(Deserialize)]
struct Fixtures {
    cases: Vec<Case>,
}

fn keys(address: &str, primary: &str, encryption_disabled: bool) -> AddressKeys {
    AddressKeys {
        address: address.into(),
        sequence: 1,
        account_ref: None,
        known_as: None,
        group: None,
        authority_public_key: String::new(),
        primary: primary.into(),
        all: vec![primary.into()],
        encryption_disabled,
        disabled: false,
    }
}

fn plan(case: &Case) -> Result<Plan, SendError> {
    let all = everyone(&case.to, &case.cc, &case.bcc);
    let domain = format!("@{}", case.own_domain);
    let (local, external) = split_recipients(
        &all,
        |a| a.ends_with(&domain),
        |a| match case.lookups.get(a).map(String::as_str) {
            Some("keys") => KutupLookup::Keys {
                encryption_disabled: false,
            },
            Some("disabled") => KutupLookup::Disabled,
            Some("notKutup") => KutupLookup::NotKutup,
            Some("group") => KutupLookup::Group,
            _ => KutupLookup::Failed,
        },
        |a| case.pinned_keys.iter().any(|p| p == a),
    )?;
    let protections: Vec<Protection> = external
        .iter()
        .map(|a| {
            let input = &case.protections[a];
            let key = || input.public_key.clone().unwrap();
            match input.kind.as_str() {
                "found" => Protection::Found {
                    public_key: key(),
                    fingerprint: String::new(),
                    source: KeySource::Wkd,
                },
                "pinned" => Protection::Pinned {
                    public_key: key(),
                    fingerprint: String::new(),
                },
                "pinnedUnusable" => Protection::PinnedUnusable {
                    fingerprint: String::new(),
                },
                _ => Protection::None,
            }
        })
        .collect();
    let (groups, plain) = pgp_groups(
        &external,
        &protections,
        &case.bcc,
        |a| case.schemes.get(a).copied(),
        case.default_scheme,
        case.encrypt,
    )?;
    let targets = kutup_targets(
        &local,
        |a| match &case.recipients[a] {
            RecipientInput::Keys {
                primary,
                encryption_disabled,
            } => KutupRecipient::Keys(Box::new(keys(a, primary, *encryption_disabled))),
            RecipientInput::Group { members } => KutupRecipient::Group(
                members
                    .iter()
                    .map(|m| keys(&m.address, &m.primary, m.encryption_disabled))
                    .collect(),
            ),
            RecipientInput::NotKutup => KutupRecipient::NotKutup,
            RecipientInput::Disabled => KutupRecipient::Disabled,
        },
        &case.sender,
        case.encrypt,
    )?;
    Ok(Plan {
        local,
        external,
        groups,
        plain,
        targets,
    })
}

#[test]
fn the_send_plan_matches_the_fixtures() {
    let fixtures: Fixtures = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    assert!(fixtures.cases.len() >= 10);
    for case in &fixtures.cases {
        match (&case.expect, plan(case)) {
            (Expect::Sent(want), Ok(got)) => assert_eq!(&got, want, "{}", case.name),
            (Expect::Refused { error }, Err(got)) => assert_eq!(&got, error, "{}", case.name),
            (_, got) => panic!("{}: {got:?}", case.name),
        }
    }
}
