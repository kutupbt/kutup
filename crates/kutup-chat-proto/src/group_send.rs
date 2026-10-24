//! Group send endorsements on the wire (docs/plans/group-send-endorsements.md):
//! an account's daily endorsement from its own server, the endorsement keys a
//! server publishes, and the sealed blobs a group's home keeps for its
//! members. The cryptography is `kutup-group-send`'s; these are only shapes.
//! Times are Unix seconds.

use serde::{Deserialize, Serialize};

use crate::group_route::{canonical, decode_bounded, decode_fixed, from_canonical};

/// An endorsement blob's length before sealing: every blob is padded to it.
pub const ENDORSEMENT_BLOB_BYTES: usize = 512;

/// A blob's length sealed under its group's state key (version, nonce and
/// tag included): the only length the home takes.
pub const ENDORSEMENT_SEALED_BYTES: usize =
    kutup_crypto::chat_group::sealed_len(ENDORSEMENT_BLOB_BYTES);

/// Seconds in a day: expirations are day-aligned.
const SECONDS_PER_DAY: u64 = 24 * 60 * 60;

/// The longest serialized endorsement response or key a message carries (a
/// one-account response is 121 bytes, a key 33).
const MAX_ZK_BYTES: usize = 1024;

/// The longest full token a multi-recipient request carries (one is 33
/// bytes plus its expiration).
pub const MAX_GROUP_SEND_TOKEN_BYTES: usize = 256;

/// Refusal codes on the home's endorsement operations (with `Refused`).
pub const ENDORSEMENT_EXPIRATION: &str = "endorsementExpiration";
pub const ENDORSEMENT_SIZE: &str = "endorsementSize";

/// The `401` code on the multi-recipient route for a token that doesn't
/// verify (Signal's): the client sends those copies pairwise.
pub const GROUP_SEND_TOKEN_INVALID: &str = "groupSendTokenInvalid";

fn day_aligned(name: &str, value: u64) -> Result<(), String> {
    if value == 0 || !value.is_multiple_of(SECONDS_PER_DAY) {
        return Err(format!("{name} must be a day-aligned Unix time"));
    }
    Ok(())
}

fn zk_bytes(name: &str, value: &str) -> Result<Vec<u8>, String> {
    let bytes = decode_bounded(name, value, MAX_ZK_BYTES)?;
    if bytes.is_empty() {
        return Err(format!("{name} is empty"));
    }
    Ok(bytes)
}

/// `GET /api/chat/group-send/endorsement`: today's endorsement of the
/// signed-in account, from its own server (§3.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupSendEndorsementResponseV1 {
    /// The key it was issued with ([`GroupSendKeyV1::key_id`]).
    pub key_id: u32,
    pub expiration: u64,
    /// The serialized `GroupSendEndorsementsResponse`, with its proof,
    /// canonical padded base64.
    pub response: String,
}

impl GroupSendEndorsementResponseV1 {
    pub fn validate(&self) -> Result<(), String> {
        day_aligned("expiration", self.expiration)?;
        self.response_bytes().map(|_| ())
    }

    pub fn response_bytes(&self) -> Result<Vec<u8>, String> {
        zk_bytes("response", &self.response)
    }
}

/// One of a server's endorsement keys, as discovery's `chatGroupSend` and
/// `GET /api/chat/group-send/params` publish it (§4): the current one, and
/// the previous one while it still verifies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupSendKeyV1 {
    pub key_id: u32,
    /// The serialized `EndorsementPublicKey`, canonical padded base64.
    pub endorsement_public_key: String,
    /// When it stops issuing (it verifies until the last expiration it
    /// issued).
    pub issues_until: u64,
}

impl GroupSendKeyV1 {
    pub fn validate(&self) -> Result<(), String> {
        self.public_key_bytes().map(|_| ())
    }

    pub fn public_key_bytes(&self) -> Result<Vec<u8>, String> {
        zk_bytes("endorsementPublicKey", &self.endorsement_public_key)
    }
}

/// `GET /api/chat/group-send/params`: this server's endorsement keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupSendParamsV1 {
    pub keys: Vec<GroupSendKeyV1>,
}

impl GroupSendParamsV1 {
    /// At most a current and a previous key, by distinct ids.
    pub fn validate(&self) -> Result<(), String> {
        if self.keys.is_empty() || self.keys.len() > 2 {
            return Err("a server publishes one or two endorsement keys".into());
        }
        if self.keys.len() == 2 && self.keys[0].key_id == self.keys[1].key_id {
            return Err("endorsement key ids must differ".into());
        }
        self.keys.iter().try_for_each(GroupSendKeyV1::validate)
    }

    pub fn key(&self, key_id: u32) -> Option<&GroupSendKeyV1> {
        self.keys.iter().find(|key| key.key_id == key_id)
    }
}

/// The body of [`crate::group_route::GroupOperationV1::PutEndorsement`]: the
/// member's blob for one expiration, sealed under the group's state key
/// (§3.3). The expiration is in clear so the home drops expired blobs
/// without reading them; the home refuses one not day-aligned or more than
/// the cap ahead (`endorsementExpiration`), and any other length
/// (`endorsementSize`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupEndorsementUploadV1 {
    pub expiration: u64,
    /// [`ENDORSEMENT_SEALED_BYTES`], canonical padded base64.
    pub sealed: String,
}

impl GroupEndorsementUploadV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        canonical(self)
    }

    /// The upload, shaped; the expiration's range and the sealed length are
    /// the home's checks (each with its own code).
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        from_canonical(bytes, 2 * ENDORSEMENT_SEALED_BYTES, "endorsement upload")
    }

    pub fn sealed_bytes(&self) -> Result<[u8; ENDORSEMENT_SEALED_BYTES], String> {
        decode_fixed::<ENDORSEMENT_SEALED_BYTES>("sealed", &self.sealed)
    }
}

/// The body of [`crate::group_route::GroupOperationV1::GetEndorsements`]:
/// what was uploaded after `after` (0 for everything). `limit` is a request;
/// the home clamps it to its page size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupEndorsementQueryV1 {
    pub after: u64,
    pub limit: u16,
}

impl GroupEndorsementQueryV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        canonical(self)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        let value: Self = from_canonical(bytes, 64, "endorsement query")?;
        if value.limit == 0 {
            return Err("endorsement query limit must be positive".into());
        }
        Ok(value)
    }
}

/// One member's blob as the home keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupEndorsementV1 {
    /// The uploading member's pseudonym (its public key, canonical padded
    /// base64): the reader checks the response against that member's
    /// verified account.
    pub pseudonym: String,
    pub expiration: u64,
    pub sealed: String,
    /// Its place in the group's upload order.
    pub seq: u64,
}

/// The answer to `GetEndorsements`: blobs in `seq` order; `nextAfter` is the
/// cursor for the next read (the last `seq`, or the query's `after` when
/// empty), `more` when the page stopped early.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupEndorsementPageV1 {
    pub endorsements: Vec<GroupEndorsementV1>,
    pub more: bool,
    pub next_after: u64,
}

impl GroupEndorsementPageV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        canonical(self)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        let value: Self =
            from_canonical(bytes, kutup_crypto::oblivious::MAX_BODY, "endorsement page")?;
        value.validate()?;
        Ok(value)
    }

    /// Ascending `seq`s, the cursor at or past the last, and every entry
    /// shaped: a pseudonym key, a day-aligned expiration, a sealed blob of
    /// the one length.
    fn validate(&self) -> Result<(), String> {
        let mut last = 0;
        for endorsement in &self.endorsements {
            if endorsement.seq <= last {
                return Err("endorsement seqs must ascend".into());
            }
            last = endorsement.seq;
            decode_fixed::<32>("pseudonym", &endorsement.pseudonym)?;
            day_aligned("expiration", endorsement.expiration)?;
            decode_fixed::<ENDORSEMENT_SEALED_BYTES>("sealed", &endorsement.sealed)?;
        }
        if self.next_after < last {
            return Err("nextAfter is behind the page".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    use super::*;

    const DAY: u64 = 1_793_145_600;

    fn entry(seq: u64) -> GroupEndorsementV1 {
        GroupEndorsementV1 {
            pseudonym: STANDARD.encode([seq as u8; 32]),
            expiration: DAY,
            sealed: STANDARD.encode([7u8; ENDORSEMENT_SEALED_BYTES]),
            seq,
        }
    }

    #[test]
    fn the_sealed_length_is_a_padded_blob_sealed() {
        assert_eq!(ENDORSEMENT_SEALED_BYTES, 1 + 24 + 512 + 16);
    }

    #[test]
    fn an_upload_takes_only_the_one_sealed_length() {
        let upload = GroupEndorsementUploadV1 {
            expiration: DAY,
            sealed: STANDARD.encode([1u8; ENDORSEMENT_SEALED_BYTES]),
        };
        let bytes = upload.canonical_bytes().unwrap();
        assert_eq!(
            String::from_utf8(bytes.clone()).unwrap(),
            format!(r#"{{"expiration":{DAY},"sealed":"{}"}}"#, upload.sealed)
        );
        let parsed = GroupEndorsementUploadV1::from_canonical_bytes(&bytes).unwrap();
        assert!(parsed.sealed_bytes().is_ok());
        let short = GroupEndorsementUploadV1 {
            sealed: STANDARD.encode([1u8; ENDORSEMENT_SEALED_BYTES - 1]),
            ..upload
        };
        assert!(short.sealed_bytes().is_err());
    }

    #[test]
    fn a_query_asks_for_a_positive_page() {
        let query = GroupEndorsementQueryV1 {
            after: 4,
            limit: 100,
        };
        let bytes = query.canonical_bytes().unwrap();
        assert_eq!(bytes, br#"{"after":4,"limit":100}"#);
        assert_eq!(
            GroupEndorsementQueryV1::from_canonical_bytes(&bytes).unwrap(),
            query
        );
        assert!(
            GroupEndorsementQueryV1::from_canonical_bytes(br#"{"after":4,"limit":0}"#).is_err()
        );
        assert!(
            GroupEndorsementQueryV1::from_canonical_bytes(br#"{"limit":1,"after":4}"#).is_err(),
            "canonical field order"
        );
    }

    #[test]
    fn a_page_ascends_and_its_cursor_follows() {
        let page = GroupEndorsementPageV1 {
            endorsements: vec![entry(3), entry(9)],
            more: true,
            next_after: 9,
        };
        let bytes = page.canonical_bytes().unwrap();
        assert_eq!(
            GroupEndorsementPageV1::from_canonical_bytes(&bytes).unwrap(),
            page
        );
        let empty = GroupEndorsementPageV1 {
            endorsements: Vec::new(),
            more: false,
            next_after: 12,
        };
        assert!(empty.canonical_bytes().is_ok());
        for bad in [
            GroupEndorsementPageV1 {
                endorsements: vec![entry(9), entry(3)],
                ..page.clone()
            },
            GroupEndorsementPageV1 {
                next_after: 8,
                ..page.clone()
            },
            GroupEndorsementPageV1 {
                endorsements: vec![GroupEndorsementV1 {
                    expiration: DAY + 1,
                    ..entry(1)
                }],
                ..page.clone()
            },
            GroupEndorsementPageV1 {
                endorsements: vec![GroupEndorsementV1 {
                    sealed: STANDARD.encode([7u8; 10]),
                    ..entry(1)
                }],
                ..page.clone()
            },
        ] {
            assert!(bad.canonical_bytes().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_own_server_answers_are_shaped() {
        let issued = GroupSendEndorsementResponseV1 {
            key_id: 1,
            expiration: DAY,
            response: STANDARD.encode([1u8; 121]),
        };
        assert_eq!(issued.validate(), Ok(()));
        assert!(GroupSendEndorsementResponseV1 {
            expiration: DAY + 60,
            ..issued.clone()
        }
        .validate()
        .is_err());
        assert!(GroupSendEndorsementResponseV1 {
            response: String::new(),
            ..issued
        }
        .validate()
        .is_err());
        let key = |key_id| GroupSendKeyV1 {
            key_id,
            endorsement_public_key: STANDARD.encode([2u8; 33]),
            issues_until: DAY,
        };
        let params = GroupSendParamsV1 {
            keys: vec![key(2), key(1)],
        };
        assert_eq!(params.validate(), Ok(()));
        assert_eq!(params.key(1), Some(&key(1)));
        let json = serde_json::to_string(&params.keys[0]).unwrap();
        assert!(
            json.starts_with(r#"{"keyId":2,"endorsementPublicKey":"#),
            "{json}"
        );
        for bad in [vec![], vec![key(1), key(1)], vec![key(1), key(2), key(3)]] {
            assert!(GroupSendParamsV1 { keys: bad }.validate().is_err());
        }
    }
}
