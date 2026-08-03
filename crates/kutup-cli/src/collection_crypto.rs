//! Canonical collection-record construction and verification for the CLI.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use rand::RngCore as _;
use uuid::Uuid;

use crate::api::{Collection, CreateCollectionRequest, RenameCollectionRequest};
use crate::session::Session;
use kutup_crypto::collection_epoch::CollectionEpochStatementV1;
use kutup_crypto::drive_envelope::{self, DriveEnvelopeContextV1, DriveEnvelopePurpose};
use kutup_crypto::identity::AccountIdentityKeysV1;
use kutup_crypto::named_share::NamedShareEnvelopeV1;

pub fn create_owned(
    name: &str,
    parent_collection_id: Option<String>,
    owner_user_id: &str,
    master_key: &[u8],
) -> Result<(CreateCollectionRequest, [u8; 32])> {
    let master_key: &[u8; 32] = master_key
        .try_into()
        .context("master key must be 32 bytes")?;
    let id = Uuid::new_v4().to_string();
    let mut collection_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut collection_key);
    let owner_key_envelope = drive_envelope::seal_b64(
        &collection_key,
        master_key,
        context(
            DriveEnvelopePurpose::CollectionKey,
            1,
            1,
            &id,
            owner_user_id,
        )?,
    )?;
    let name_envelope = drive_envelope::seal_b64(
        name.as_bytes(),
        &collection_key,
        context(
            DriveEnvelopePurpose::CollectionName,
            1,
            1,
            &id,
            owner_user_id,
        )?,
    )?;
    let identity = AccountIdentityKeysV1::derive(master_key)?;
    let epoch_statement = CollectionEpochStatementV1::create(
        &id,
        owner_user_id,
        1,
        None,
        &collection_key,
        identity.authority_signing_key(),
    )?
    .encode_b64();
    Ok((
        CreateCollectionRequest {
            id,
            name_envelope,
            owner_key_envelope,
            epoch_statement,
            parent_collection_id,
        },
        collection_key,
    ))
}

pub fn open_key(col: &Collection, master_key: &[u8], session: &Session) -> Result<Vec<u8>> {
    let master_key_array: &[u8; 32] = master_key
        .try_into()
        .context("master key must be 32 bytes")?;
    let collection_key = if col.is_shared {
        let envelope = NamedShareEnvelopeV1::decode_b64(
            col.named_share_envelope
                .as_deref()
                .ok_or_else(|| anyhow!("named share envelope is missing"))?,
        )?;
        let owner_account = col
            .owner_account
            .as_deref()
            .ok_or_else(|| anyhow!("share owner account is missing"))?;
        let owner_incarnation = col
            .owner_incarnation_id
            .as_deref()
            .ok_or_else(|| anyhow!("share owner incarnation is missing"))?;
        let sender_signing = decode_key(
            col.owner_drive_signing_public_key
                .as_deref()
                .ok_or_else(|| anyhow!("share owner signing key is missing"))?,
        )?;
        let identity = AccountIdentityKeysV1::derive(master_key_array)?;
        if envelope.recipient_incarnation_id != hex::decode(identity.incarnation_id())?.as_slice() {
            bail!("named share is intended for another account incarnation");
        }
        envelope.open(
            &col.id,
            col.key_epoch,
            owner_account,
            owner_incarnation,
            &sender_signing,
            &envelope.recipient_account,
            &identity.incarnation_id(),
            &session.private_key_bytes()?,
        )?
    } else {
        let owner_envelope = col
            .owner_key_envelope
            .as_deref()
            .ok_or_else(|| anyhow!("owner key envelope is missing"))?;
        drive_envelope::open_b64(
            owner_envelope,
            master_key,
            context(
                DriveEnvelopePurpose::CollectionKey,
                col.key_epoch,
                1,
                &col.id,
                &col.owner_user_id,
            )?,
        )?
    };
    verify_epoch(col, master_key_array, &collection_key)?;
    Ok(collection_key)
}

pub fn open_name(col: &Collection, collection_key: &[u8]) -> Result<String> {
    let plaintext = drive_envelope::open_b64(
        &col.name_envelope,
        collection_key,
        context(
            DriveEnvelopePurpose::CollectionName,
            col.key_epoch,
            col.name_revision,
            &col.id,
            &col.owner_user_id,
        )?,
    )?;
    String::from_utf8(plaintext).context("collection name is not UTF-8")
}

pub fn rename_request(
    col: &Collection,
    collection_key: &[u8],
    new_name: &str,
) -> Result<RenameCollectionRequest> {
    let name_revision = col
        .name_revision
        .checked_add(1)
        .ok_or_else(|| anyhow!("collection name revision exhausted"))?;
    let name_envelope = drive_envelope::seal_b64(
        new_name.as_bytes(),
        collection_key,
        context(
            DriveEnvelopePurpose::CollectionName,
            col.key_epoch,
            name_revision,
            &col.id,
            &col.owner_user_id,
        )?,
    )?;
    Ok(RenameCollectionRequest {
        name_envelope,
        name_revision,
    })
}

fn verify_epoch(col: &Collection, master_key: &[u8; 32], collection_key: &[u8]) -> Result<()> {
    let statement = CollectionEpochStatementV1::decode_b64(&col.epoch_statement)?;
    let authority = if col.is_shared {
        decode_key(
            col.owner_authority_public_key
                .as_deref()
                .ok_or_else(|| anyhow!("share owner authority key is missing"))?,
        )?
    } else {
        AccountIdentityKeysV1::derive(master_key)?
            .authority_public_key()
            .to_vec()
    };
    statement.verify_authority(&authority)?;
    statement.verify_current_binding(&col.id, &col.owner_user_id, col.key_epoch)?;
    statement.verify_collection_key(collection_key)?;
    if statement.statement_hash() != col.epoch_statement_hash {
        bail!("collection epoch statement hash mismatch");
    }
    Ok(())
}

fn context(
    purpose: DriveEnvelopePurpose,
    epoch: u32,
    revision: u64,
    object_id: &str,
    parent_id: &str,
) -> Result<DriveEnvelopeContextV1> {
    DriveEnvelopeContextV1::new(purpose, epoch, revision, object_id, parent_id).map_err(Into::into)
}

fn decode_key(value: &str) -> Result<Vec<u8>> {
    let bytes = STANDARD.decode(value)?;
    if bytes.len() != 32 || STANDARD.encode(&bytes) != value {
        bail!("identity key is not canonical base64");
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned_collection(master_key: &[u8; 32]) -> (Collection, [u8; 32]) {
        let owner_user_id = "11111111-1111-4111-8111-111111111111";
        let (created, collection_key) =
            create_owned("Design notes", None, owner_user_id, master_key).unwrap();
        let statement = CollectionEpochStatementV1::decode_b64(&created.epoch_statement).unwrap();
        (
            Collection {
                id: created.id,
                owner_user_id: owner_user_id.into(),
                name_envelope: created.name_envelope,
                owner_key_envelope: Some(created.owner_key_envelope),
                named_share_envelope: None,
                key_epoch: 1,
                name_revision: 1,
                epoch_statement: created.epoch_statement,
                epoch_statement_hash: statement.statement_hash(),
                owner_account: None,
                owner_incarnation_id: None,
                owner_drive_signing_public_key: None,
                owner_authority_public_key: None,
                parent_collection_id: None,
                color: None,
                is_shared: false,
                is_remote: false,
                can_upload: false,
                can_delete: false,
                upload_quota_bytes: None,
                name: String::new(),
            },
            collection_key,
        )
    }

    #[test]
    fn owned_record_round_trips_and_rename_advances_exactly_once() {
        let master_key = [7u8; 32];
        let (collection, expected_key) = owned_collection(&master_key);
        let opened_key = open_key(&collection, &master_key, &Session::default()).unwrap();
        assert_eq!(opened_key, expected_key);
        assert_eq!(open_name(&collection, &opened_key).unwrap(), "Design notes");

        let rename = rename_request(&collection, &opened_key, "Final design").unwrap();
        assert_eq!(rename.name_revision, 2);
        let renamed = drive_envelope::open_b64(
            &rename.name_envelope,
            &opened_key,
            context(
                DriveEnvelopePurpose::CollectionName,
                1,
                2,
                &collection.id,
                &collection.owner_user_id,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(renamed, b"Final design");
    }

    #[test]
    fn owned_record_rejects_wrong_master_and_epoch_hash() {
        let master_key = [8u8; 32];
        let (mut collection, _) = owned_collection(&master_key);
        assert!(open_key(&collection, &[9u8; 32], &Session::default()).is_err());

        collection.epoch_statement_hash = "00".repeat(32);
        assert!(open_key(&collection, &master_key, &Session::default()).is_err());
    }
}
