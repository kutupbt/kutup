//! 1:1 call signaling and call history (docs/chat-calls.md).
//!
//! A call's WebRTC offer, answer, ICE candidates and hang-up travel as the
//! ephemeral `call` content kind over the Direct (libsignal) session, like
//! typing: never stored, never copied to the sender's other devices. Because
//! the SDP (with its DTLS fingerprint) arrives end-to-end encrypted and
//! authenticated, the media keys are bound to the two accounts.
//!
//! An offer rings every device of the callee. Replies name the caller's
//! device, so the caller's other devices ignore them; once a callee device
//! answers, the caller names it too, and tells the other callee devices to
//! stop ringing.
//!
//! The `callLog` kind is the timeline record of a call ("Missed voice
//! call"). Each device writes its own; it never travels.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const MAX_CALL_SDP_BYTES: usize = 32 * 1024;
pub const MAX_CALL_ICE_CANDIDATES: usize = 32;
const MAX_ICE_CANDIDATE_BYTES: usize = 1024;
const MAX_SDP_MID_BYTES: usize = 64;
/// Longer than any real call record needs (a week).
const MAX_CALL_DURATION_SECONDS: u32 = 7 * 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CallMediaV1 {
    Audio,
    Video,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IceCandidateV1 {
    pub candidate: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdp_mid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdp_m_line_index: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HangupReasonV1 {
    /// Either side ended the call (or the caller gave up before an answer).
    Normal,
    /// The callee turned the call down.
    Declined,
    /// Another device of the callee answered: stop ringing here.
    AnsweredElsewhere,
    /// Another device of the callee declined: stop ringing here.
    DeclinedElsewhere,
    /// Nobody answered in time.
    Unanswered,
    /// The connection could not be made or was lost.
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum CallSignalKindV1 {
    #[serde(rename_all = "camelCase")]
    Offer { media: CallMediaV1, sdp: String },
    #[serde(rename_all = "camelCase")]
    Answer { sdp: String },
    #[serde(rename_all = "camelCase")]
    Ice { candidates: Vec<IceCandidateV1> },
    #[serde(rename_all = "camelCase")]
    Hangup { reason: HangupReasonV1 },
    /// The callee is already in a call.
    Busy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CallSignalV1 {
    pub call_id: Uuid,
    /// The device that placed the call; replies go only to it.
    pub caller_device_id: u32,
    /// The callee device that answered, once one has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callee_device_id: Option<u32>,
    pub signal: CallSignalKindV1,
}

fn validate_device(device_id: u32) -> Result<(), String> {
    if (1..=127).contains(&device_id) {
        Ok(())
    } else {
        Err("a call names a device id 1-127".into())
    }
}

fn validate_sdp(sdp: &str) -> Result<(), String> {
    if sdp.is_empty() || sdp.len() > MAX_CALL_SDP_BYTES || !sdp.starts_with("v=0") {
        return Err("a call description must be SDP of at most 32 KiB".into());
    }
    Ok(())
}

impl CallSignalV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.call_id.is_nil() {
            return Err("a call needs an id".into());
        }
        validate_device(self.caller_device_id)?;
        if let Some(device) = self.callee_device_id {
            validate_device(device)?;
        }
        match &self.signal {
            CallSignalKindV1::Offer { sdp, .. } | CallSignalKindV1::Answer { sdp } => {
                validate_sdp(sdp)
            }
            CallSignalKindV1::Ice { candidates } => {
                if candidates.is_empty() || candidates.len() > MAX_CALL_ICE_CANDIDATES {
                    return Err("a call sends 1 to 32 ICE candidates at once".into());
                }
                for candidate in candidates {
                    if candidate.candidate.len() > MAX_ICE_CANDIDATE_BYTES
                        || candidate
                            .sdp_mid
                            .as_ref()
                            .is_some_and(|mid| mid.len() > MAX_SDP_MID_BYTES)
                    {
                        return Err("an ICE candidate is too long".into());
                    }
                }
                Ok(())
            }
            CallSignalKindV1::Hangup { .. } | CallSignalKindV1::Busy => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CallOutcomeV1 {
    Answered,
    /// Incoming, not answered here or anywhere.
    Missed,
    Declined,
    /// Outgoing, nobody answered.
    Unanswered,
    Busy,
    Failed,
}

/// One call in a conversation's timeline, written by this device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CallLogBody {
    pub call_id: Uuid,
    pub incoming: bool,
    pub media: CallMediaV1,
    pub outcome: CallOutcomeV1,
    pub started_at_ms: i64,
    /// For an answered call: how long it lasted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_seconds: Option<u32>,
}

impl CallLogBody {
    pub fn validate(&self) -> Result<(), String> {
        if self.call_id.is_nil() || !(0..=crate::MAX_SAFE_CLOCK_MS).contains(&self.started_at_ms) {
            return Err("a call record needs an id and a time".into());
        }
        match (self.outcome, self.duration_seconds) {
            (CallOutcomeV1::Answered, Some(seconds)) if seconds <= MAX_CALL_DURATION_SECONDS => {
                Ok(())
            }
            (CallOutcomeV1::Answered, _) => Err("an answered call records its duration".into()),
            (_, None) => Ok(()),
            (_, Some(_)) => Err("only an answered call has a duration".into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GroupCallEventV1 {
    Started,
    Ended,
}

/// A group call starting or ending, sent to the group over MLS. The room on
/// `host`'s SFU is joined with a token from that server; `room_id` is the
/// capability, known only to the group's members. Media frames are
/// encrypted with a key derived from the MLS epoch (docs/chat-calls.md).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GroupCallBody {
    pub call_id: Uuid,
    pub event: GroupCallEventV1,
    pub host: String,
    /// 32 lowercase hex characters (128 random bits).
    pub room_id: String,
    pub media: CallMediaV1,
    /// Standard base64 of 32 random bytes, known only to the group: it keys
    /// the participant tags, so the SFU cannot tell who is in the call.
    pub secret: String,
}

impl GroupCallBody {
    pub fn validate(&self) -> Result<(), String> {
        if self.call_id.is_nil() {
            return Err("a group call needs an id".into());
        }
        validate_room_id(&self.room_id)?;
        crate::mls::decode_canonical_base64("groupCallSecret", &self.secret, 32, 32)?;
        kutup_federation_proto::validate_server_name(&self.host)
            .map_err(|error| format!("group call host: {error}"))
    }
}

/// A group call room id: 32 lowercase hex characters.
pub fn validate_room_id(room_id: &str) -> Result<(), String> {
    if room_id.len() != 32
        || !room_id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("a group call room id is 32 lowercase hex characters".into());
    }
    Ok(())
}

impl crate::ChatContent {
    pub fn group_call_with_id(
        message_id: impl Into<String>,
        sent_at: impl Into<String>,
        seq: u64,
        body: &GroupCallBody,
    ) -> Result<Self, String> {
        body.validate()?;
        Self::structured(
            crate::content::kind::GROUP_CALL,
            message_id,
            sent_at,
            seq,
            body,
        )
    }

    pub fn as_group_call(&self) -> Option<GroupCallBody> {
        let body: GroupCallBody = self.structured_body(crate::content::kind::GROUP_CALL)?;
        body.validate().ok()?;
        Some(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signal(kind: CallSignalKindV1) -> CallSignalV1 {
        CallSignalV1 {
            call_id: Uuid::from_u128(1),
            caller_device_id: 2,
            callee_device_id: None,
            signal: kind,
        }
    }

    #[test]
    fn signals_round_trip_and_validate() {
        let offer = signal(CallSignalKindV1::Offer {
            media: CallMediaV1::Video,
            sdp: "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\n".into(),
        });
        let json = serde_json::to_value(&offer).unwrap();
        assert_eq!(json["signal"]["type"], "offer");
        assert_eq!(json["signal"]["media"], "video");
        let back: CallSignalV1 = serde_json::from_value(json).unwrap();
        assert_eq!(back, offer);
        back.validate().unwrap();

        assert!(signal(CallSignalKindV1::Answer { sdp: "nope".into() })
            .validate()
            .is_err());
        assert!(signal(CallSignalKindV1::Ice { candidates: vec![] })
            .validate()
            .is_err());
        let hangup = signal(CallSignalKindV1::Hangup {
            reason: HangupReasonV1::AnsweredElsewhere,
        });
        assert_eq!(
            serde_json::to_value(&hangup).unwrap()["signal"]["reason"],
            "answeredElsewhere"
        );
        let mut bad_device = signal(CallSignalKindV1::Busy);
        bad_device.caller_device_id = 0;
        assert!(bad_device.validate().is_err());
    }

    #[test]
    fn group_calls_name_a_room_on_a_host() {
        let body = GroupCallBody {
            call_id: Uuid::from_u128(4),
            event: GroupCallEventV1::Started,
            host: "a.test".into(),
            room_id: "0123456789abcdef0123456789abcdef".into(),
            media: CallMediaV1::Video,
            secret: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [3u8; 32]),
        };
        let content = crate::ChatContent::group_call_with_id("m", "t", 1, &body).unwrap();
        assert_eq!(content.as_group_call(), Some(body.clone()));
        assert!(GroupCallBody {
            room_id: "0123456789ABCDEF0123456789ABCDEF".into(),
            ..body.clone()
        }
        .validate()
        .is_err());
        assert!(GroupCallBody {
            host: "https://a.test".into(),
            ..body
        }
        .validate()
        .is_err());
    }

    #[test]
    fn call_records_carry_a_duration_only_when_answered() {
        let record = CallLogBody {
            call_id: Uuid::from_u128(1),
            incoming: true,
            media: CallMediaV1::Audio,
            outcome: CallOutcomeV1::Answered,
            started_at_ms: 1,
            duration_seconds: Some(90),
        };
        record.validate().unwrap();
        assert!(CallLogBody {
            duration_seconds: None,
            ..record.clone()
        }
        .validate()
        .is_err());
        assert!(CallLogBody {
            outcome: CallOutcomeV1::Missed,
            ..record
        }
        .validate()
        .is_err());
    }
}
