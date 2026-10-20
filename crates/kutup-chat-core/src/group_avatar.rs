//! A pairwise group's avatar (docs/plans/pairwise-groups.md §11, "Avatar"):
//! the image is padded to a size bucket and sealed under a fresh key, the
//! blob goes to the home with `PutAvatar`, then a change names the blob's
//! SHA-256 in the clear and its key and type in the sealed attribute. The
//! home sees only the blob and its hash.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kutup_chat_proto::group::{GroupActionV1, GroupAttribute, GroupAvatarV1, GROUP_FORMAT_VERSION};
use kutup_chat_proto::group_route::GroupOperationV1;
use kutup_crypto::chat_group::{avatar_blob_hash, seal_group_avatar, MAX_AVATAR_IMAGE_BYTES};
use rand::{CryptoRng, Rng};

use crate::engine::Engine;
use crate::error::{ChatError, Result};
use crate::group;
use crate::group_engine::{accepted_body, group_error};

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
        match self
            .group_request(&mut record, GroupOperationV1::PutAvatar, &blob)
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
