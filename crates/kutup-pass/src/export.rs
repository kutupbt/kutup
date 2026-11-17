//! Exporting a vault in the clear (docs/plans/pass-gaps-2.md P5): CSV in
//! KeePassXC's columns (`src/format/CsvExporter.cpp`), which KeePassXC and
//! most password managers read. The website asks for the account's
//! password first and warns that the file is not encrypted; nothing here
//! goes to a server.

use keepass::db::{GroupId, Icon};
use keepass::Database;

use crate::view::{format_time, group_in_recycle_bin};

/// KeePassXC's header row.
pub const CSV_COLUMNS: [&str; 10] = [
    "Group",
    "Title",
    "Username",
    "Password",
    "URL",
    "Notes",
    "TOTP",
    "Icon",
    "Last Modified",
    "Created",
];

/// The vault as CSV, every value quoted, groups as paths from the top
/// group ("Kişisel/İş"), in the vault's order. Unlike KeePassXC, the
/// recycle bin is left out: deleted entries don't belong in a file in the
/// clear.
pub fn csv(db: &Database) -> String {
    let mut out = String::new();
    let line = |out: &mut String, values: &[&str]| {
        let quoted: Vec<String> = values
            .iter()
            .map(|v| format!("\"{}\"", v.replace('"', "\"\"")))
            .collect();
        out.push_str(&quoted.join(","));
        out.push('\n');
    };
    line(&mut out, &CSV_COLUMNS);
    let mut stack: Vec<(GroupId, String)> = vec![(db.root, String::new())];
    while let Some((id, parent_path)) = stack.pop() {
        let Some(group) = db.groups.get(&id) else {
            continue;
        };
        if group_in_recycle_bin(db, id) {
            continue;
        }
        let path = if parent_path.is_empty() {
            group.name.clone()
        } else {
            format!("{parent_path}/{}", group.name)
        };
        for entry in group.entries.iter().filter_map(|e| db.entries.get(e)) {
            let get = |key: &str| entry.fields.get(key).map_or("", |v| v.get().as_str());
            let icon = match entry.icon {
                Some(Icon::BuiltIn(n)) => n,
                _ => 0,
            };
            let time = |t: Option<chrono::NaiveDateTime>| t.map(format_time).unwrap_or_default();
            line(
                &mut out,
                &[
                    &path,
                    get("Title"),
                    get("UserName"),
                    get("Password"),
                    get("URL"),
                    get("Notes"),
                    get("otp"),
                    &icon.to_string(),
                    &time(entry.times.last_modification),
                    &time(entry.times.creation),
                ],
            );
        }
        for child in group.groups.iter().rev() {
            stack.push((*child, path.clone()));
        }
    }
    out
}
