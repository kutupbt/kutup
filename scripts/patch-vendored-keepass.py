#!/usr/bin/env python3
"""Apply Kutup's patch to the vendored `keepass` crate
(crates/kutup-pass/vendor/keepass).

The patch widens visibility: the database model's internal fields and two
id constructors become public, so `crates/kutup-pass` can read and write a
vault completely (custom icons keep their UUIDs, history items keep their
attachments, entries keep their previous group). It adds one constructor,
`DatabaseKey::with_password_hash`, which takes the password part of the
composite key (SHA-256 of the password) instead of the password, so a vault
opens with what Kutup Pass keeps without the password itself
(docs/plans/pass.md, "Vault secrets"), and exports `key_file_element`, the
key element KeePass derives from a key file, so a key file is kept as exactly
that element. Nothing else changes behaviour.
It then formats the crate with the workspace's rustfmt settings (upstream's
own formatting is not consistent, and `cargo fmt --all` checks local path
dependencies too); formatting changes no behaviour.
Re-run after replacing the vendored crate with a new upstream release; every
replacement must apply exactly once, or the script fails.
"""
import pathlib, re, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent / "crates" / "kutup-pass" / "vendor" / "keepass" / "src" / "db" / "types"

FIELDS = {
    "mod.rs": ["root: GroupId", "attachments: HashMap<AttachmentId, Attachment>",
               "custom_icons: HashMap<CustomIconId, CustomIcon>", "entries: HashMap<EntryId, Entry>",
               "groups: HashMap<GroupId, Group>"],
    "entry.rs": ["id: EntryId", "parent: GroupId", "icon: Option<Icon>",
                 "attachments: HashMap<String, AttachmentId>", "previous_parent_group: Option<GroupId>"],
    "group.rs": ["id: GroupId", "parent: Option<GroupId>", "icon: Option<Icon>", "groups: IndexSet<GroupId>",
                 "entries: IndexSet<EntryId>", "last_top_visible_entry: Option<EntryId>",
                 "previous_parent_group: Option<GroupId>"],
    "attachment.rs": ["id: AttachmentId", "entries: HashSet<(EntryId, Option<usize>)>"],
    "icon.rs": ["id: CustomIconId", "entries: HashSet<(EntryId, Option<usize>)>", "groups: HashSet<GroupId>"],
    "history.rs": ["entries: Vec<Entry>"],
}
FUNCTIONS = {
    "icon.rs": ["const fn from_uuid(uuid: Uuid) -> Self"],
    "attachment.rs": ["fn new(id: usize) -> Self"],
}

DOC = "/// Public in Kutup's copy, for crates/kutup-pass (vendor/keepass/KUTUP.md)."

def widen(text, needle, kind, name):
    pattern = re.compile(r"(\n(\s*))pub\(crate\) (" + re.escape(needle) + ")")
    new, count = pattern.subn(lambda m: f"{m.group(1)}{DOC}{m.group(1)}pub {m.group(3)}", text, count=1)
    if count != 1:
        sys.exit(f"patch-vendored-keepass: {kind} `{needle}` not found once in {name}")
    return new

for name in sorted(set(FIELDS) | set(FUNCTIONS)):
    path = ROOT / name
    text = path.read_text()
    for needle in FIELDS.get(name, []):
        text = widen(text, needle + ",", "field", name)
    for needle in FUNCTIONS.get(name, []):
        text = widen(text, needle, "function", name)
    path.write_text(text)
# DatabaseKey::with_password_hash: the password's part of the composite key,
# given as KeePass computes it (SHA-256 of the password).
KEY = ROOT.parents[1] / "key" / "mod.rs"
key = KEY.read_text()
def once(text, old, new):
    if text.count(old) != 1:
        sys.exit(f"patch-vendored-keepass: `{old.strip()[:60]}` not found once in key/mod.rs")
    return text.replace(old, new, 1)
key = once(key, "    password: Option<String>,\n    keyfile: Option<Vec<u8>>,\n",
    "    password: Option<String>,\n"
    "    /// Kutup's copy (vendor/keepass/KUTUP.md): the password's part of the\n"
    "    /// composite key, SHA-256 of the password, given instead of it.\n"
    "    password_hash: Option<Vec<u8>>,\n"
    "    keyfile: Option<Vec<u8>>,\n")
key = once(key, "    /// Modify the database key to include a password\n",
    "    /// Kutup's copy (vendor/keepass/KUTUP.md): modify the database key to\n"
    "    /// include a password given as its SHA-256, the password's part of the\n"
    "    /// composite key.\n"
    "    pub fn with_password_hash(mut self, hash: &[u8; 32]) -> Self {\n"
    "        self.password_hash = Some(hash.to_vec());\n"
    "        self\n"
    "    }\n\n"
    "    /// Modify the database key to include a password\n")
key = once(key, "        if let Some(p) = &self.password {\n            out.push(calculate_sha256(&[p.as_bytes()]).to_vec());\n        }\n",
    "        if let Some(p) = &self.password {\n            out.push(calculate_sha256(&[p.as_bytes()]).to_vec());\n"
    "        } else if let Some(hash) = &self.password_hash {\n            out.push(hash.clone());\n        }\n")
key = once(key, "        if self.password.is_some() || self.keyfile.is_some() {\n            return false;\n",
    "        if self.password.is_some() || self.password_hash.is_some() || self.keyfile.is_some() {\n            return false;\n")
key = once(key, "/// A KeePass key, which might consist of a password and/or a keyfile\n",
    "/// Kutup's copy (vendor/keepass/KUTUP.md): the key element KeePass derives\n"
    "/// from a key file's contents (what the composite key uses), so a key file\n"
    "/// can be kept as that element.\n"
    "pub fn key_file_element(contents: &[u8]) -> Option<Vec<u8>> {\n"
    "    parse_keyfile(contents).ok()\n"
    "}\n\n"
    "/// A KeePass key, which might consist of a password and/or a keyfile\n")
KEY.write_text(key)
LIB = ROOT.parents[1] / "lib.rs"
lib = LIB.read_text()
if lib.count("pub use self::key::DatabaseKey;\n") != 1:
    sys.exit("patch-vendored-keepass: the DatabaseKey export not found once in lib.rs")
LIB.write_text(lib.replace("pub use self::key::DatabaseKey;\n",
    "pub use self::key::DatabaseKey;\n/// Public in Kutup's copy (vendor/keepass/KUTUP.md).\npub use self::key::key_file_element;\n", 1))
# The README is the crate's rustdoc; its relative links point into upstream's
# repository, which the published crate does not include.
readme = ROOT.parents[2] / "README.md"
readme.write_text(readme.read_text().replace("](./examples)", "](https://github.com/sseemayer/keepass-rs/tree/master/examples)"))
subprocess.run(["cargo", "fmt", "--manifest-path", str(ROOT.parents[2] / "Cargo.toml")], check=True)
print("patch-vendored-keepass: applied and formatted")
