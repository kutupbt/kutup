//! A pairwise group's avatar (docs/plans/pairwise-groups.md §11, "Avatar"):
//! the image is padded to a size bucket and sealed under a fresh key, the
//! blob goes to the home with `PutAvatar`, then a change names the blob's
//! SHA-256 in the clear and its key and type in the sealed attribute. The
//! home sees only the blob and its hash.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::group::{GroupActionV1, GroupAttribute, GroupAvatarV1, GROUP_FORMAT_VERSION};
use kutup_chat_proto::group_route::{pad_group_avatar, unpad_group_avatar, GroupOperationV1};
use kutup_crypto::chat_group::{
    avatar_blob_hash, open_group_avatar, seal_group_avatar, MAX_AVATAR_IMAGE_BYTES,
};
use rand::{CryptoRng, Rng};

use crate::engine::Engine;
use crate::error::{ChatError, Result};
use crate::group::{self, GroupRecordV1};
use crate::group_client::{self, RequestSigner, RouteFailure};
use crate::group_engine::{accepted_body, group_error, now_seconds};

/// A group's avatar, opened.
#[derive(Clone, PartialEq, Eq)]
pub struct GroupAvatarImage {
    pub data: Vec<u8>,
    pub content_type: String,
}

impl std::fmt::Debug for GroupAvatarImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupAvatarImage")
            .field("bytes", &self.data.len())
            .field("content_type", &self.content_type)
            .finish()
    }
}

/// The sealed avatar attribute `value`, opened under `record`'s key.
pub(crate) fn avatar_attribute(record: &GroupRecordV1, value: &str) -> Result<GroupAvatarV1> {
    let key = record.master().map_err(group_error)?.state_key();
    let sealed = STANDARD
        .decode(value)
        .map_err(|_| ChatError::Invalid("the group avatar is not base64".into()))?;
    let plain = key
        .open(kutup_crypto::chat_group::SealedField::Avatar, b"", &sealed)
        .map_err(|_| ChatError::Trust("the group avatar doesn't open".into()))?;
    GroupAvatarV1::from_canonical_bytes(&plain).map_err(ChatError::Invalid)
}

/// The avatar `body` the home served, opened with `attribute`'s key; checked
/// against `hash` when the state names one.
pub(crate) fn open_avatar_body(
    body: &[u8],
    attribute: &GroupAvatarV1,
    hash: Option<&str>,
) -> Result<GroupAvatarImage> {
    let blob = unpad_group_avatar(body).map_err(ChatError::Invalid)?;
    if let Some(hash) = hash {
        if STANDARD.encode(avatar_blob_hash(&blob)) != hash {
            return Err(ChatError::Trust(
                "the group's home served another avatar than the one the group names".into(),
            ));
        }
    }
    let key: [u8; 32] = STANDARD
        .decode(&attribute.key)
        .ok()
        .and_then(|key| key.try_into().ok())
        .ok_or_else(|| ChatError::Invalid("the group avatar key is malformed".into()))?;
    let data = open_group_avatar(&blob, &key)
        .map_err(|_| ChatError::Trust("the group avatar doesn't open".into()))?;
    Ok(GroupAvatarImage {
        data: data.to_vec(),
        content_type: attribute.content_type.clone(),
    })
}

impl Engine {
    /// Sets the group's avatar to `image` (JPEG, PNG or WebP, at most 40 KiB
    /// less one byte): uploaded first, then named by a change.
    pub async fn set_group_avatar<R: Rng + CryptoRng>(
        &mut self,
        group_id: &str,
        image: &[u8],
        content_type: &str,
        rng: &mut R,
    ) -> Result<()> {
        if image.is_empty() || image.len() > MAX_AVATAR_IMAGE_BYTES {
            return Err(ChatError::Invalid(
                "a group avatar is at most 40 KiB".into(),
            ));
        }
        let (blob, key) =
            seal_group_avatar(image).map_err(|error| ChatError::Invalid(error.to_string()))?;
        let attribute = GroupAvatarV1 {
            version: GROUP_FORMAT_VERSION,
            key: STANDARD.encode(*key),
            content_type: content_type.to_string(),
        };
        let plain =
            zeroize::Zeroizing::new(attribute.canonical_bytes().map_err(ChatError::Invalid)?);
        let mut record = self.load_group_record(group_id).await?;
        let value =
            group::seal_attribute(&record, GroupAttribute::Avatar, &plain).map_err(group_error)?;
        let body = pad_group_avatar(&blob).map_err(ChatError::Invalid)?;
        match self
            .group_request(&mut record, GroupOperationV1::PutAvatar, &body)
            .await?
        {
            Ok(response) => {
                accepted_body(response)?;
            }
            Err(failure) => {
                return Err(ChatError::Transport(format!(
                    "the group's server can't be reached: {failure:?}"
                )))
            }
        }
        self.change_group(
            group_id,
            vec![GroupActionV1::ModifyAttribute {
                attribute: GroupAttribute::Avatar,
                value: Some(value),
                avatar_hash: Some(STANDARD.encode(avatar_blob_hash(&blob))),
            }],
            rng,
        )
        .await
    }

    /// The group's avatar as its verified state names it: fetched from the
    /// home, checked against the hash the state names, and opened. `None`
    /// when the group has none.
    pub async fn group_avatar(
        &mut self,
        group_id: &str,
    ) -> Result<std::result::Result<Option<GroupAvatarImage>, RouteFailure>> {
        let mut record = self.load_group_record(group_id).await?;
        let Some((state, _)) = record.verified().map_err(group_error)? else {
            return Ok(Ok(None));
        };
        let (Some(value), Some(hash)) = (&state.attributes.avatar, &state.attributes.avatar_hash)
        else {
            return Ok(Ok(None));
        };
        let attribute = avatar_attribute(&record, value)?;
        let response = match self
            .group_request(&mut record, GroupOperationV1::GetAvatar, b"")
            .await?
        {
            Ok(response) => response,
            Err(failure) => return Ok(Err(failure)),
        };
        let body = accepted_body(response)?;
        Ok(Ok(Some(open_avatar_body(&body, &attribute, Some(hash))?)))
    }

    /// The avatar a link shows before joining: fetched under the link's
    /// proof and opened with the key its sealed attribute gives (an
    /// authenticated open; the join info names no hash). Best effort.
    pub(crate) async fn link_avatar(
        &mut self,
        record: &mut GroupRecordV1,
        password: &[u8; kutup_chat_proto::group::INVITE_LINK_PASSWORD_LEN],
        sealed: &str,
    ) -> Option<GroupAvatarImage> {
        let attribute = avatar_attribute(record, sealed).ok()?;
        let group_id = kutup_chat_proto::group::decode_group_id(&record.group_id).ok()?;
        let home = record.home.clone();
        let transport = std::rc::Rc::clone(&self.transport);
        let answer = group_client::call(
            transport.as_ref(),
            &mut record.gateway,
            &home,
            &group_id,
            GroupOperationV1::GetAvatar,
            b"",
            &RequestSigner::LinkPassword(password),
            now_seconds(),
        )
        .await
        .ok()?
        .ok()?;
        let body = accepted_body(answer).ok()?;
        open_avatar_body(&body, &attribute, None).ok()
    }

    /// Removes the group's avatar.
    pub async fn remove_group_avatar<R: Rng + CryptoRng>(
        &mut self,
        group_id: &str,
        rng: &mut R,
    ) -> Result<()> {
        self.change_group(
            group_id,
            vec![GroupActionV1::ModifyAttribute {
                attribute: GroupAttribute::Avatar,
                value: None,
                avatar_hash: None,
            }],
            rng,
        )
        .await
    }
}
