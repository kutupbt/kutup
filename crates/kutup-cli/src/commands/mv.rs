//! `kutup mv` — rename and/or move a file or folder
//! (docs/plans/drive-move.md).
//!
//! - Renaming re-seals the name (a file's under its file key, a folder's
//!   under the folder key); content is untouched.
//! - Moving a file re-seals only its file key for the destination folder.
//!   A file whose folder rotated its key since the file was last keyed (a
//!   member was removed) first gets a new key generation, so nobody removed
//!   from the source can follow it.
//! - Moving a folder changes nothing encrypted: its key is sealed to its
//!   owner, not to its parent.
//!
//! A move stays among one owner's folders on this server; across owners or
//! servers it is a copy (download and upload), never done silently here.

use crate::api::files::MoveOutcome;
use crate::api::{ApiError, Collection};
use crate::context::{require_session, Ctx as SessionContext};
use crate::cryptohelpers::{decrypt_collection_key, locate_file, rekey_if_behind};
use crate::errors::{NotFound, UsageError};
use anyhow::{bail, Context, Result};

/// What `kutup mv` was asked to do.
pub struct MvArgs<'a> {
    pub id: &'a str,
    /// The new name, if renaming.
    pub new_name: Option<&'a str>,
    /// `id` names a folder.
    pub folder: bool,
    /// The folder to move into.
    pub to: Option<&'a str>,
    /// Move the folder to the top level.
    pub root: bool,
}

/// Where a move puts the item.
enum Destination<'a> {
    Folder(&'a str),
    TopLevel,
}

pub fn run(profile: &str, json: bool, args: MvArgs<'_>) -> Result<()> {
    let destination = match (args.to, args.root) {
        (Some(_), true) => return Err(UsageError("use either --to or --root".into()).into()),
        (Some(to), false) => Some(Destination::Folder(to)),
        (None, true) if !args.folder => {
            return Err(UsageError(
                "a file always lives in a folder: use --to <FOLDER_ID> (--root is for folders)"
                    .into(),
            )
            .into())
        }
        (None, true) => Some(Destination::TopLevel),
        (None, false) => None,
    };
    if destination.is_none() && args.new_name.is_none() {
        return Err(UsageError(
            "nothing to do: give a new name, --to <FOLDER_ID>, or (for a folder) --root".into(),
        )
        .into());
    }
    if let Some(Destination::Folder(to)) = &destination {
        if *to == args.id {
            return Err(UsageError("cannot move an item into itself".into()).into());
        }
    }
    if args.new_name.is_some_and(str::is_empty) {
        return Err(UsageError("the new name is empty".into()).into());
    }

    let ctx = require_session(profile)?;
    let mut out = serde_json::json!({
        "id": args.id,
        "type": if args.folder { "folder" } else { "file" },
    });

    // A move never renames or overwrites (docs/plans/drive-move.md): an item
    // whose final name is already used in the destination stays put. Checked
    // before anything is sent; the answer also orders a rename + move.
    let rename_first = match &destination {
        Some(destination) => {
            check_names(&ctx, args.id, args.folder, destination, args.new_name)?.rename_first
        }
        None => false,
    };

    if args.folder {
        if rename_first {
            rename_folder_step(&ctx, json, &mut out, args.id, args.new_name)?;
        }
        if let Some(destination) = &destination {
            let parent = move_folder(&ctx, args.id, destination)?;
            out["parentId"] = parent.clone().into();
            if !json {
                match parent {
                    Some(parent) => println!("Moved folder {} into {parent}", args.id),
                    None => println!("Moved folder {} to the top level", args.id),
                }
            }
        }
        if !rename_first {
            rename_folder_step(&ctx, json, &mut out, args.id, args.new_name)?;
        }
    } else {
        if rename_first {
            rename_file_step(&ctx, json, &mut out, args.id, args.new_name)?;
        }
        if let Some(Destination::Folder(to)) = &destination {
            let collection_id = move_file(&ctx, args.id, to)?;
            out["collectionId"] = collection_id.clone().into();
            if !json {
                println!("Moved file {} into {collection_id}", args.id);
            }
        }
        if !rename_first {
            rename_file_step(&ctx, json, &mut out, args.id, args.new_name)?;
        }
    }

    if json {
        crate::output::print_json(&out)?;
    }
    Ok(())
}

fn rename_file_step(
    ctx: &SessionContext,
    json: bool,
    out: &mut serde_json::Value,
    id: &str,
    new_name: Option<&str>,
) -> Result<()> {
    let Some(new_name) = new_name else {
        return Ok(());
    };
    rename_file(ctx, id, new_name)?;
    out["name"] = new_name.into();
    if !json {
        println!("Renamed file {id} → {new_name}");
    }
    Ok(())
}

fn rename_folder_step(
    ctx: &SessionContext,
    json: bool,
    out: &mut serde_json::Value,
    id: &str,
    new_name: Option<&str>,
) -> Result<()> {
    let Some(new_name) = new_name else {
        return Ok(());
    };
    rename_folder(ctx, id, new_name)?;
    out["name"] = new_name.into();
    if !json {
        println!("Renamed folder {id} → {new_name}");
    }
    Ok(())
}

/// How a move's names check out.
struct NameCheck {
    /// Rename before moving: the current name is taken in the destination
    /// (the final one is not), so moving first could leave a duplicate there
    /// if the rename then failed. Otherwise the move goes first and a failed
    /// rename leaves the item, under its old name, where it went.
    rename_first: bool,
}

/// Refuses a move whose final name (the new one when renaming too) is
/// already used by a file or folder directly in the destination — the
/// top level for `--root`. Names that do not decrypt are ignored.
fn check_names(
    ctx: &SessionContext,
    id: &str,
    folder: bool,
    destination: &Destination<'_>,
    new_name: Option<&str>,
) -> Result<NameCheck> {
    let master_key = ctx.session.master_key_bytes()?;
    let cols = crate::cryptohelpers::decrypt_collections(
        ctx.client.list_collections()?,
        &master_key,
        &ctx.session,
    );
    let current = if folder {
        find_folder(&cols, id)?.name.clone()
    } else {
        let found = locate_file(&ctx.client, &master_key, &ctx.session, &cols, id)?;
        crate::file_crypto::open_metadata(&found.file, &found.file_key)
            .context("decrypt file metadata")?
            .name
    };
    let parent = match destination {
        Destination::Folder(to) => Some(*to),
        Destination::TopLevel => None,
    };
    // Subfolders directly in the destination (top-level folders for --root).
    let mut taken: Vec<String> = cols
        .iter()
        .filter(|c| c.id != id && c.parent_collection_id.as_deref() == parent)
        .map(|c| c.name.clone())
        .collect();
    // Files directly in the destination folder.
    if let Some(dest) = parent.and_then(|to| cols.iter().find(|c| c.id == to)) {
        if let Ok(keys) =
            crate::cryptohelpers::folder_keyring(&ctx.client, dest, &master_key, &ctx.session)
        {
            for f in ctx.client.list_files(&dest.id)? {
                if f.id != id {
                    taken.push(crate::cryptohelpers::decrypt_file_meta(&f, &keys).0);
                }
            }
        }
    }
    let taken: Vec<&str> = taken
        .iter()
        .map(String::as_str)
        .filter(|name| *name != UNREADABLE)
        .collect();

    let final_name = new_name.unwrap_or(&current);
    if name_taken(final_name, &taken) {
        let kind = if folder { "folder" } else { "file" };
        let place = match parent {
            Some(to) => format!("folder {to}"),
            None => "the top level".to_string(),
        };
        return Err(UsageError(format!(
            "{place} already has an item named {final_name:?}: the {kind} stays where it is \
             (rename it or the other item first)"
        ))
        .into());
    }
    Ok(NameCheck {
        rename_first: new_name.is_some() && name_taken(&current, &taken),
    })
}

/// What the decrypt helpers name an item whose name does not open.
const UNREADABLE: &str = "[encrypted]";

/// Whether `name` is already used among `taken`, ignoring case (as the web
/// app compares).
fn name_taken(name: &str, taken: &[&str]) -> bool {
    let name = name.to_lowercase();
    taken.iter().any(|other| other.to_lowercase() == name)
}

fn rename_file(ctx: &SessionContext, id: &str, new_name: &str) -> Result<()> {
    let master_key = ctx.session.master_key_bytes()?;
    let cols = ctx.client.list_collections()?;
    // A new name is new content: never under a key the folder has left.
    let found = rekey_if_behind(
        &ctx.client,
        locate_file(&ctx.client, &master_key, &ctx.session, &cols, id)?,
    )?;
    let mut meta = crate::file_crypto::open_metadata(&found.file, &found.file_key)
        .context("decrypt existing metadata")?;
    meta.name = new_name.to_string();
    let request = crate::file_crypto::rename_request(&found.file, &found.file_key, &meta)?;
    ctx.client.update_file_metadata(id, &request)
}

fn rename_folder(ctx: &SessionContext, id: &str, new_name: &str) -> Result<()> {
    let master_key = ctx.session.master_key_bytes()?;
    let cols = ctx.client.list_collections()?;
    let col = find_folder(&cols, id)?;
    // The server updates only owner-scoped rows; fail with a real reason
    // instead of its opaque 404.
    if col.is_shared {
        bail!("only the owner can rename a shared folder");
    }
    let collection_key =
        decrypt_collection_key(col, &master_key, &ctx.session).context("decrypt collection key")?;
    let rename = crate::collection_crypto::rename_request(col, &collection_key, new_name)
        .context("encrypt name")?;
    ctx.client
        .rename_collection(id, &rename)
        .context("rename folder")
}

/// Moves a folder under `destination`; returns its new parent.
fn move_folder(
    ctx: &SessionContext,
    id: &str,
    destination: &Destination<'_>,
) -> Result<Option<String>> {
    let cols = ctx.client.list_collections()?;
    let col = find_folder(&cols, id)?;
    if col.is_shared {
        bail!("only the owner can move a shared folder");
    }
    let parent = match destination {
        Destination::TopLevel => None,
        Destination::Folder(to) => {
            let Some(dest) = cols.iter().find(|c| c.id == *to) else {
                return Err(destination_not_found(ctx, to, "folder"));
            };
            if dest.is_shared || dest.owner_user_id != col.owner_user_id {
                return Err(UsageError(format!(
                    "folder {to} belongs to someone else: a folder moves only among your own \
                     folders (to put its contents there, download them and upload them there)"
                ))
                .into());
            }
            Some(dest.id.clone())
        }
    };
    if col.parent_collection_id == parent {
        bail!("the folder is already there");
    }
    // The server checks the destination is not the folder or anything in it.
    ctx.client
        .move_collection(id, parent.as_deref())
        .context("move folder")?;
    Ok(parent)
}

/// Moves a file into folder `to`; returns the folder it is now in.
fn move_file(ctx: &SessionContext, id: &str, to: &str) -> Result<String> {
    let master_key = ctx.session.master_key_bytes()?;
    // One reload on a conflict: another client re-keyed or moved the file,
    // or the destination's key rotated, between our read and the move.
    let mut attempt = 0;
    loop {
        attempt += 1;
        let cols = ctx.client.list_collections()?;
        let Some(dest) = cols.iter().find(|c| c.id == to) else {
            return Err(destination_not_found(ctx, to, "file"));
        };
        let found = locate_file(&ctx.client, &master_key, &ctx.session, &cols, id)?;
        check_file_move(&found.collection, dest)?;

        // A file behind its folder is re-keyed first, at the folder's
        // current epoch: its new key is what moves.
        let found = rekey_if_behind(&ctx.client, found)?;
        let dest_key = decrypt_collection_key(dest, &master_key, &ctx.session)
            .context("decrypt destination folder key")?;
        let request = crate::file_crypto::move_request(
            &found.file,
            &found.file_key,
            &dest.id,
            dest.key_epoch,
            &dest_key,
        )?;
        match ctx.client.move_file(id, &request)? {
            MoveOutcome::Moved(moved) => return Ok(moved.collection_id),
            MoveOutcome::Conflict(_) if attempt < 2 => continue,
            MoveOutcome::Conflict(message) => {
                return Err(anyhow::Error::new(ApiError {
                    status: 409,
                    message,
                })
                .context("move file (retried once after a conflict)"))
            }
        }
    }
}

/// Whether a file in `source` may move to `dest`, before anything is sealed.
fn check_file_move(source: &Collection, dest: &Collection) -> Result<()> {
    if source.id == dest.id {
        bail!("the file is already in that folder");
    }
    if source.owner_user_id != dest.owner_user_id {
        return Err(UsageError(
            "a file moves only between folders of the same owner; to put it in the other \
             folder, download it and upload it there"
                .into(),
        )
        .into());
    }
    for folder in [source, dest] {
        if folder.is_shared && !folder.can_upload {
            return Err(UsageError(format!(
                "moving needs edit access to both folders, and folder {} is read-only for you",
                folder.id
            ))
            .into());
        }
    }
    Ok(())
}

fn find_folder<'a>(cols: &'a [Collection], id: &str) -> Result<&'a Collection> {
    cols.iter()
        .find(|c| c.id == id)
        .ok_or_else(|| NotFound(format!("folder {id} not found")).into())
}

/// A destination not among this server's folders: a federated share gets a
/// clear refusal (a move never crosses servers), anything else is not found.
fn destination_not_found(ctx: &SessionContext, to: &str, what: &str) -> anyhow::Error {
    let federated = ctx.client.list_incoming_shares().is_ok_and(|shares| {
        shares
            .iter()
            .any(|s| s.id == to || s.remote_collection_id == to)
    });
    if federated {
        let hint = if what == "file" {
            " — download it and upload it with `kutup share upload <share-id> <path>`"
        } else {
            ""
        };
        return UsageError(format!(
            "{to} is a share on another server: a {what} cannot move across servers{hint}"
        ))
        .into();
    }
    NotFound(format!("folder {to} not found")).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folder(id: &str, owner: &str, shared: bool, can_upload: bool) -> Collection {
        Collection {
            id: id.into(),
            owner_user_id: owner.into(),
            name_envelope: String::new(),
            owner_key_envelope: None,
            named_share_envelope: None,
            key_epoch: 1,
            name_revision: 1,
            epoch_statement: String::new(),
            epoch_statement_hash: String::new(),
            owner_account: None,
            owner_incarnation_id: None,
            owner_drive_signing_public_key: None,
            owner_authority_public_key: None,
            parent_collection_id: None,
            color: None,
            is_shared: shared,
            is_remote: false,
            can_upload,
            can_delete: false,
            upload_quota_bytes: None,
            name: String::new(),
        }
    }

    #[test]
    fn names_clash_ignoring_case() {
        let taken = ["Report.pdf", "Photos", "ärger.txt"];
        assert!(name_taken("report.PDF", &taken));
        assert!(name_taken("photos", &taken));
        assert!(name_taken("ÄRGER.TXT", &taken));
        assert!(!name_taken("report.pdf.bak", &taken));
        assert!(!name_taken("Photo", &taken));
        assert!(!name_taken("anything", &[]));
    }

    #[test]
    fn a_file_moves_only_within_one_owner_with_edit_access() {
        let mine = folder("a", "me", false, false);
        let also_mine = folder("b", "me", false, false);
        assert!(check_file_move(&mine, &also_mine).is_ok());
        assert!(check_file_move(&mine, &mine).is_err());

        let theirs = folder("c", "them", true, true);
        let err = check_file_move(&mine, &theirs).unwrap_err();
        assert!(err.downcast_ref::<UsageError>().is_some());

        // Two of someone else's folders: fine as their editor, not as a viewer.
        let theirs_too = folder("d", "them", true, true);
        assert!(check_file_move(&theirs, &theirs_too).is_ok());
        let read_only = folder("e", "them", true, false);
        assert!(check_file_move(&theirs, &read_only).is_err());
        assert!(check_file_move(&read_only, &theirs).is_err());
    }
}
