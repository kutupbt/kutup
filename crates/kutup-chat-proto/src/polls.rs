//! Polls, as in Signal: a question with 2–10 options, optionally allowing
//! several choices; each member's latest vote counts; the author can end the
//! poll. Three content kinds: `poll` (visible), `pollVote` and
//! `pollTerminate` (folded into it).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::content::{kind, ChatContent};

pub const MAX_POLL_QUESTION_CHARS: usize = 200;
pub const MAX_POLL_OPTION_CHARS: usize = 100;
pub const MIN_POLL_OPTIONS: usize = 2;
pub const MAX_POLL_OPTIONS: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PollBody {
    pub question: String,
    pub options: Vec<String>,
    #[serde(default)]
    pub allow_multiple: bool,
}

impl PollBody {
    pub fn validate(&self) -> Result<(), String> {
        let text_ok = |value: &str, max: usize| {
            let trimmed = value.trim();
            !trimmed.is_empty()
                && trimmed == value
                && value.chars().count() <= max
                && !value.chars().any(char::is_control)
        };
        if !text_ok(&self.question, MAX_POLL_QUESTION_CHARS) {
            return Err("a Chat poll question is 1 to 200 characters on one line".into());
        }
        if !(MIN_POLL_OPTIONS..=MAX_POLL_OPTIONS).contains(&self.options.len()) {
            return Err("a Chat poll has 2 to 10 options".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        for option in &self.options {
            if !text_ok(option, MAX_POLL_OPTION_CHARS) || !seen.insert(option.to_lowercase()) {
                return Err("Chat poll options are distinct, 1 to 100 characters each".into());
            }
        }
        Ok(())
    }
}

/// A member's current choice: the option indexes (ascending, distinct);
/// empty takes the vote back. Whether several are allowed is the poll's rule,
/// checked where the poll is known.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PollVoteBody {
    pub target_message_id: String,
    pub options: Vec<u8>,
}

impl PollVoteBody {
    pub fn validate(&self) -> Result<(), String> {
        validate_target(&self.target_message_id)?;
        if self.options.len() > MAX_POLL_OPTIONS
            || self
                .options
                .iter()
                .any(|&index| usize::from(index) >= MAX_POLL_OPTIONS)
            || self.options.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err("a Chat poll vote names distinct option indexes in order".into());
        }
        Ok(())
    }
}

/// The author ends the poll; later votes do not count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PollTerminateBody {
    pub target_message_id: String,
}

fn validate_target(target: &str) -> Result<(), String> {
    let parsed =
        Uuid::parse_str(target).map_err(|_| "a Chat poll target must be a UUID".to_string())?;
    if parsed.is_nil() || parsed.to_string() != target {
        return Err("a Chat poll target must be a canonical non-nil UUID".into());
    }
    Ok(())
}

impl ChatContent {
    fn structured<T: Serialize>(
        kind: &str,
        message_id: impl Into<String>,
        sent_at: impl Into<String>,
        seq: u64,
        body: &T,
    ) -> Result<Self, String> {
        Ok(ChatContent {
            v: Self::VERSION,
            kind: kind.to_string(),
            sent_at: sent_at.into(),
            seq,
            message_id: Some(message_id.into()),
            reply_to: None,
            profile_key: None,
            profile_suite: None,
            body: serde_json::to_value(body).map_err(|error| error.to_string())?,
            extra: serde_json::Map::new(),
        })
    }

    fn structured_body<T: serde::de::DeserializeOwned>(&self, kind: &str) -> Option<T> {
        if self.kind != kind || self.v != Self::VERSION || self.message_id.is_none() {
            return None;
        }
        serde_json::from_value(self.body.clone()).ok()
    }

    pub fn poll_with_id(
        message_id: impl Into<String>,
        sent_at: impl Into<String>,
        seq: u64,
        body: &PollBody,
    ) -> Result<Self, String> {
        body.validate()?;
        Self::structured(kind::POLL, message_id, sent_at, seq, body)
    }

    pub fn as_poll(&self) -> Option<PollBody> {
        let body: PollBody = self.structured_body(kind::POLL)?;
        body.validate().ok()?;
        Some(body)
    }

    pub fn poll_vote_with_id(
        message_id: impl Into<String>,
        sent_at: impl Into<String>,
        seq: u64,
        body: &PollVoteBody,
    ) -> Result<Self, String> {
        body.validate()?;
        Self::structured(kind::POLL_VOTE, message_id, sent_at, seq, body)
    }

    pub fn as_poll_vote(&self) -> Option<PollVoteBody> {
        let body: PollVoteBody = self.structured_body(kind::POLL_VOTE)?;
        body.validate().ok()?;
        Some(body)
    }

    pub fn poll_terminate_with_id(
        message_id: impl Into<String>,
        sent_at: impl Into<String>,
        seq: u64,
        body: &PollTerminateBody,
    ) -> Result<Self, String> {
        validate_target(&body.target_message_id)?;
        Self::structured(kind::POLL_TERMINATE, message_id, sent_at, seq, body)
    }

    pub fn as_poll_terminate(&self) -> Option<PollTerminateBody> {
        let body: PollTerminateBody = self.structured_body(kind::POLL_TERMINATE)?;
        validate_target(&body.target_message_id).ok()?;
        Some(body)
    }

    /// For a poll kind: whether its body is valid; `None` for other kinds.
    /// Receivers refuse a poll-kind message that does not validate.
    pub fn poll_content_is_valid(&self) -> Option<bool> {
        match self.kind.as_str() {
            kind::POLL => Some(self.as_poll().is_some()),
            kind::POLL_VOTE => Some(self.as_poll_vote().is_some()),
            kind::POLL_TERMINATE => Some(self.as_poll_terminate().is_some()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0b0f6a8e-35f5-4a8e-9f5a-0a8f3c2d1e4b";

    fn poll() -> PollBody {
        PollBody {
            question: "Where shall we eat?".into(),
            options: vec!["Pizza".into(), "Kebab".into(), "Sushi".into()],
            allow_multiple: false,
        }
    }

    #[test]
    fn polls_round_trip_and_bound_their_text() {
        let content = ChatContent::poll_with_id(ID, "t", 1, &poll()).unwrap();
        assert!(content.is_known_kind());
        assert_eq!(content.as_poll(), Some(poll()));
        assert_eq!(content.poll_content_is_valid(), Some(true));
        for bad in [
            PollBody {
                options: vec!["Only".into()],
                ..poll()
            },
            PollBody {
                options: vec!["A".into(), "a".into()],
                ..poll()
            },
            PollBody {
                question: " padded".into(),
                ..poll()
            },
            PollBody {
                question: "q".repeat(201),
                ..poll()
            },
            PollBody {
                options: (0..11).map(|i| i.to_string()).collect(),
                ..poll()
            },
        ] {
            assert!(ChatContent::poll_with_id(ID, "t", 1, &bad).is_err());
        }
    }

    #[test]
    fn votes_are_ordered_distinct_indexes_and_may_be_empty() {
        let vote = PollVoteBody {
            target_message_id: ID.into(),
            options: vec![0, 2],
        };
        let content = ChatContent::poll_vote_with_id(ID, "t", 2, &vote).unwrap();
        assert_eq!(content.as_poll_vote(), Some(vote));
        let withdrawn = PollVoteBody {
            target_message_id: ID.into(),
            options: vec![],
        };
        assert!(ChatContent::poll_vote_with_id(ID, "t", 3, &withdrawn).is_ok());
        for options in [vec![2, 0], vec![1, 1], vec![10]] {
            let bad = PollVoteBody {
                target_message_id: ID.into(),
                options,
            };
            assert!(ChatContent::poll_vote_with_id(ID, "t", 2, &bad).is_err());
        }
        let end = PollTerminateBody {
            target_message_id: ID.into(),
        };
        assert_eq!(
            ChatContent::poll_terminate_with_id(ID, "t", 4, &end)
                .unwrap()
                .as_poll_terminate(),
            Some(end)
        );
    }
}
