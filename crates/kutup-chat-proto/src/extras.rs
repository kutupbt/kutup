//! What a visible message (text or attachment) may carry beside its body,
//! as Signal's DataMessage does: mentions, a link preview, the forwarded
//! mark, view-once. Each is an authenticated top-level content field, like
//! `expiresAfterSeconds`, so older readers keep the message and ignore what
//! they do not know, and a malformed value fails the whole message closed.

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::content::{kind, ChatContent};
use crate::AccountAddress;

const MENTIONS_FIELD: &str = "mentions";
const LINK_PREVIEW_FIELD: &str = "linkPreview";
const FORWARDED_FIELD: &str = "forwarded";
const VIEW_ONCE_FIELD: &str = "viewOnce";
const STICKER_FIELD: &str = "sticker";

/// One mention in a text: `length` UTF-16 code units from `start` (the
/// units JavaScript strings index by, as Signal's body ranges) stand for
/// `member`, usually as "@Name".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MentionV1 {
    pub start: u32,
    pub length: u32,
    /// Canonical `username@server`.
    pub member: String,
}

/// A preview of a link in the text, made by the sender (so recipients never
/// contact the site): the page's title and description and a small image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkPreviewV1 {
    /// An `https://` URL that appears in the text.
    pub url: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<LinkPreviewImageV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkPreviewImageV1 {
    pub content_type: String,
    /// Standard base64.
    pub data: String,
}

/// Everything optional a visible message carries, as one value to send or read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VisibleMessageExtrasV1 {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mentions: Vec<MentionV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_preview: Option<LinkPreviewV1>,
    /// The sender forwarded it from another conversation.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub forwarded: bool,
    /// A photo or video the recipient can open once.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub view_once: bool,
    /// The image is a sticker: shown large, without a bubble.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sticker: Option<StickerMarkV1>,
}

/// A sticker's mark on its image attachment: the emoji it stands for.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StickerMarkV1 {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub emoji: String,
}

impl VisibleMessageExtrasV1 {
    pub const MAX_MENTIONS: usize = 64;
    pub const MAX_URL_BYTES: usize = 2048;
    pub const MAX_TITLE_CHARS: usize = 300;
    pub const MAX_DESCRIPTION_CHARS: usize = 1000;
    /// Small enough to keep a Direct message under its 64 KiB content limit.
    pub const MAX_PREVIEW_IMAGE_BYTES: usize = 24 * 1024;
    pub const PREVIEW_IMAGE_TYPES: [&'static str; 3] = ["image/jpeg", "image/png", "image/webp"];

    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    /// Checks the extras against the message they ride on.
    pub fn validate(&self, content: &ChatContent) -> Result<(), String> {
        let is_text = content.kind == kind::TEXT;
        let is_attachment = content.kind == kind::ATTACHMENT;
        if !self.is_empty() && !is_text && !is_attachment {
            return Err("only visible Chat messages carry mentions, previews or marks".into());
        }
        if !self.mentions.is_empty() {
            let text = content
                .as_text()
                .ok_or("mentions belong to a text message")?
                .text;
            validate_mentions(&self.mentions, &text)?;
        }
        if let Some(preview) = &self.link_preview {
            let text = content
                .as_text()
                .ok_or("a link preview belongs to a text message")?
                .text;
            validate_preview(preview, &text)?;
        }
        if let Some(sticker) = &self.sticker {
            let attachment = content
                .as_attachment()
                .ok_or("a sticker is an image attachment")?;
            if attachment.media_class != crate::ChatMediaClassV1::Photo
                || !matches!(attachment.mime_type.as_str(), "image/webp" | "image/png")
                || attachment.plaintext_bytes > 512 * 1024
                || self.view_once
            {
                return Err("a sticker is a WebP or PNG image of at most 512 KiB".into());
            }
            if sticker.emoji.chars().count() > 8 || sticker.emoji.chars().any(char::is_control) {
                return Err("a sticker emoji is at most 8 characters".into());
            }
        }
        if self.view_once {
            let attachment = content
                .as_attachment()
                .ok_or("view-once belongs to an attachment")?;
            if !matches!(
                attachment.media_class,
                crate::ChatMediaClassV1::Photo | crate::ChatMediaClassV1::Video
            ) {
                return Err("only a photo or video can be view-once".into());
            }
        }
        Ok(())
    }
}

fn validate_mentions(mentions: &[MentionV1], text: &str) -> Result<(), String> {
    if mentions.len() > VisibleMessageExtrasV1::MAX_MENTIONS {
        return Err("a Chat message mentions at most 64 people".into());
    }
    let units = text.encode_utf16().count() as u64;
    let mut previous_end = 0u64;
    for mention in mentions {
        let start = u64::from(mention.start);
        let end = start + u64::from(mention.length);
        if mention.length == 0 || start < previous_end || end > units {
            return Err("Chat mentions must be ordered, non-overlapping ranges of the text".into());
        }
        previous_end = end;
        let address: AccountAddress = mention
            .member
            .parse()
            .map_err(|_| "Chat mention names an invalid account".to_string())?;
        if address.server.is_none() || address.canonical() != mention.member {
            return Err("Chat mention must name a canonical account".into());
        }
    }
    Ok(())
}

fn validate_preview(preview: &LinkPreviewV1, text: &str) -> Result<(), String> {
    if !preview.url.starts_with("https://")
        || preview.url.len() > VisibleMessageExtrasV1::MAX_URL_BYTES
        || preview
            .url
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
        || !text.contains(&preview.url)
    {
        return Err("a Chat link preview needs an https link that appears in the text".into());
    }
    if preview.title.trim().is_empty()
        || preview.title.chars().count() > VisibleMessageExtrasV1::MAX_TITLE_CHARS
        || preview.description.chars().count() > VisibleMessageExtrasV1::MAX_DESCRIPTION_CHARS
    {
        return Err("a Chat link preview needs a title of up to 300 characters and a description of up to 1000".into());
    }
    if let Some(image) = &preview.image {
        if !VisibleMessageExtrasV1::PREVIEW_IMAGE_TYPES.contains(&image.content_type.as_str()) {
            return Err("a Chat link preview image must be JPEG, PNG or WebP".into());
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&image.data)
            .map_err(|_| "a Chat link preview image must be base64".to_string())?;
        if bytes.is_empty()
            || bytes.len() > VisibleMessageExtrasV1::MAX_PREVIEW_IMAGE_BYTES
            || base64::engine::general_purpose::STANDARD.encode(&bytes) != image.data
        {
            return Err(
                "a Chat link preview image must be at most 24 KiB of canonical base64".into(),
            );
        }
    }
    Ok(())
}

impl ChatContent {
    /// Attaches `extras` to a text or attachment message, validated.
    pub fn with_extras(mut self, extras: &VisibleMessageExtrasV1) -> Result<Self, String> {
        extras.validate(&self)?;
        if !extras.mentions.is_empty() {
            self.extra
                .insert(MENTIONS_FIELD.into(), to_json(&extras.mentions)?);
        }
        if let Some(preview) = &extras.link_preview {
            self.extra
                .insert(LINK_PREVIEW_FIELD.into(), to_json(preview)?);
        }
        if extras.forwarded {
            self.extra
                .insert(FORWARDED_FIELD.into(), serde_json::Value::Bool(true));
        }
        if extras.view_once {
            self.extra
                .insert(VIEW_ONCE_FIELD.into(), serde_json::Value::Bool(true));
        }
        if let Some(sticker) = &extras.sticker {
            self.extra.insert(STICKER_FIELD.into(), to_json(sticker)?);
        }
        Ok(self)
    }

    /// The extras this message carries. A present but malformed field is an
    /// error: the message is refused rather than shown without it.
    pub fn extras(&self) -> Result<VisibleMessageExtrasV1, String> {
        let mut extras = VisibleMessageExtrasV1::default();
        if let Some(value) = self.extra.get(MENTIONS_FIELD) {
            extras.mentions = serde_json::from_value(value.clone())
                .map_err(|_| "Chat mentions are malformed".to_string())?;
            if extras.mentions.is_empty() {
                return Err("Chat mentions must not be empty when present".into());
            }
        }
        if let Some(value) = self.extra.get(LINK_PREVIEW_FIELD) {
            extras.link_preview = Some(
                serde_json::from_value(value.clone())
                    .map_err(|_| "Chat link preview is malformed".to_string())?,
            );
        }
        if let Some(value) = self.extra.get(STICKER_FIELD) {
            extras.sticker = Some(
                serde_json::from_value(value.clone())
                    .map_err(|_| "Chat sticker mark is malformed".to_string())?,
            );
        }
        for (field, flag) in [
            (FORWARDED_FIELD, &mut extras.forwarded),
            (VIEW_ONCE_FIELD, &mut extras.view_once),
        ] {
            if let Some(value) = self.extra.get(field) {
                if value != &serde_json::Value::Bool(true) {
                    return Err(format!("Chat {field} mark must be true when present"));
                }
                *flag = true;
            }
        }
        extras.validate(self)?;
        Ok(extras)
    }
}

fn to_json<T: Serialize>(value: &T) -> Result<serde_json::Value, String> {
    serde_json::to_value(value).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0b0f6a8e-35f5-4a8e-9f5a-0a8f3c2d1e4b";

    fn text(body: &str) -> ChatContent {
        ChatContent::text_with_id(ID, "t", 1, body)
    }

    #[test]
    fn mentions_round_trip_and_bound_to_the_text_in_utf16_units() {
        // "🙂" is two UTF-16 units.
        let extras = VisibleMessageExtrasV1 {
            mentions: vec![MentionV1 {
                start: 3,
                length: 4,
                member: "ali@a.test".into(),
            }],
            ..Default::default()
        };
        let content = text("🙂 @Ali hi").with_extras(&extras).unwrap();
        let wire: ChatContent =
            serde_json::from_slice(&serde_json::to_vec(&content).unwrap()).unwrap();
        assert_eq!(wire.extras().unwrap(), extras);
        for bad in [
            MentionV1 {
                start: 3,
                length: 40,
                member: "ali@a.test".into(),
            },
            MentionV1 {
                start: 3,
                length: 0,
                member: "ali@a.test".into(),
            },
            MentionV1 {
                start: 3,
                length: 4,
                member: "Ali@A.test".into(),
            },
            MentionV1 {
                start: 3,
                length: 4,
                member: "ali".into(),
            },
        ] {
            let extras = VisibleMessageExtrasV1 {
                mentions: vec![bad],
                ..Default::default()
            };
            assert!(text("🙂 @Ali hi").with_extras(&extras).is_err());
        }
        let overlapping = VisibleMessageExtrasV1 {
            mentions: vec![
                MentionV1 {
                    start: 0,
                    length: 4,
                    member: "ali@a.test".into(),
                },
                MentionV1 {
                    start: 2,
                    length: 4,
                    member: "bob@b.test".into(),
                },
            ],
            ..Default::default()
        };
        assert!(text("@Ali @Bob").with_extras(&overlapping).is_err());
    }

    #[test]
    fn a_preview_needs_its_https_link_in_the_text_and_a_small_image() {
        let preview = LinkPreviewV1 {
            url: "https://example.org/a".into(),
            title: "Example".into(),
            description: String::new(),
            image: Some(LinkPreviewImageV1 {
                content_type: "image/webp".into(),
                data: base64::engine::general_purpose::STANDARD.encode([1u8; 32]),
            }),
        };
        let extras = VisibleMessageExtrasV1 {
            link_preview: Some(preview.clone()),
            ..Default::default()
        };
        let content = text("see https://example.org/a")
            .with_extras(&extras)
            .unwrap();
        assert_eq!(content.extras().unwrap(), extras);
        assert!(text("no link here").with_extras(&extras).is_err());
        let http = VisibleMessageExtrasV1 {
            link_preview: Some(LinkPreviewV1 {
                url: "http://example.org/a".into(),
                ..preview.clone()
            }),
            ..Default::default()
        };
        assert!(text("see http://example.org/a").with_extras(&http).is_err());
        let big = VisibleMessageExtrasV1 {
            link_preview: Some(LinkPreviewV1 {
                image: Some(LinkPreviewImageV1 {
                    content_type: "image/png".into(),
                    data: base64::engine::general_purpose::STANDARD
                        .encode(vec![0u8; 24 * 1024 + 1]),
                }),
                ..preview
            }),
            ..Default::default()
        };
        assert!(text("see https://example.org/a").with_extras(&big).is_err());
    }

    #[test]
    fn marks_are_true_or_absent_and_fit_their_kind() {
        let forwarded = VisibleMessageExtrasV1 {
            forwarded: true,
            ..Default::default()
        };
        let content = text("fwd").with_extras(&forwarded).unwrap();
        assert_eq!(content.extras().unwrap(), forwarded);
        let mut tampered = content.clone();
        tampered
            .extra
            .insert(FORWARDED_FIELD.into(), serde_json::Value::Bool(false));
        assert!(tampered.extras().is_err());
        let view_once = VisibleMessageExtrasV1 {
            view_once: true,
            ..Default::default()
        };
        assert!(
            text("x").with_extras(&view_once).is_err(),
            "view-once is for photos and videos"
        );
        assert_eq!(
            text("plain").extras().unwrap(),
            VisibleMessageExtrasV1::default()
        );
    }
}
