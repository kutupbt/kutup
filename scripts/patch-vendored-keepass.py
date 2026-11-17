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
that element. It also adds plain KeePass XML (`from_plain_xml`,
`to_plain_xml`): values marked `ProtectInMemory` read and written in the
clear, attachments in Meta/Binaries, for Kutup Pass's XML import and export
(docs/plans/pass-gaps-2.md P5b); the KDBX paths are unchanged. Nothing else
changes behaviour.
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
# Applied after the first formatting, so its anchors match formatted code.
# Plain KeePass XML (docs/plans/pass-gaps-2.md P5b): reading and writing a
# vault as an unencrypted KeePass XML file, as KeePassXC's and KeePass's XML
# exports are: protected values in the clear marked `ProtectInMemory="True"`,
# attachments in Meta/Binaries so the file stands alone.
XML_DB = ROOT.parents[1] / "format" / "xml_db"
def once_in(path, old, new):
    text = path.read_text()
    if text.count(old) != 1:
        sys.exit(f"patch-vendored-keepass: `{old.strip()[:60]}` not found once in {path.name}")
    path.write_text(text.replace(old, new, 1))
ENTRY = XML_DB / "entry.rs"
once_in(ENTRY,
    "    #[serde(default, rename = \"@Protected\", with = \"cs_bool\")]\n    protected: bool,\n",
    "    #[serde(default, rename = \"@Protected\", with = \"cs_bool\")]\n    protected: bool,\n\n"
    "    /// Kutup's copy (vendor/keepass/KUTUP.md): a value in the clear that\n"
    "    /// KeePass keeps protected (plain XML exports).\n"
    "    #[serde(default, rename = \"@ProtectInMemory\", with = \"cs_bool\")]\n"
    "    protect_in_memory: bool,\n")
once_in(ENTRY,
    "                crate::db::Value::protected(fval)\n            } else {\n                crate::db::Value::unprotected(fval)\n            };\n",
    "                crate::db::Value::protected(fval)\n            } else if field.value.protect_in_memory {\n"
    "                crate::db::Value::protected(fval)\n            } else {\n                crate::db::Value::unprotected(fval)\n            };\n")
once_in(ENTRY,
    "                StringValue {\n                    protected: true,\n                    value: Some(encoded),\n                }\n",
    "                StringValue {\n                    protected: true,\n                    protect_in_memory: false,\n                    value: Some(encoded),\n                }\n")
once_in(ENTRY,
    "                StringValue {\n                    protected: false,\n                    value: Some(v.as_str().to_string()),\n                }\n",
    "                StringValue {\n                    protected: false,\n                    protect_in_memory: false,\n                    value: Some(v.as_str().to_string()),\n                }\n")
once_in(ENTRY,
    "        if self.protected {\n            let mut state = serializer.serialize_struct(\"StringValue\", 2)?;\n",
    "        if self.protect_in_memory && !self.protected {\n"
    "            let mut state = serializer.serialize_struct(\"StringValue\", 2)?;\n"
    "            state.serialize_field(\"@ProtectInMemory\", \"True\")?;\n"
    "            state.serialize_field(\"$value\", self.value.as_deref().unwrap_or(\"\"))?;\n"
    "            state.end()\n"
    "        } else if self.protected {\n            let mut state = serializer.serialize_struct(\"StringValue\", 2)?;\n")
once_in(ENTRY,
    "impl Serialize for StringValue {\n",
    "impl StringValue {\n"
    "    /// Kutup's copy: a value written by a plain cipher made readable again,\n"
    "    /// marked `ProtectInMemory` (plain XML exports).\n"
    "    pub(crate) fn unprotect_plain(&mut self) {\n"
    "        if self.protected {\n"
    "            let raw = base64_engine::STANDARD.decode(self.value.as_deref().unwrap_or(\"\")).unwrap_or_default();\n"
    "            self.value = Some(String::from_utf8_lossy(&raw).into_owned());\n"
    "            self.protected = false;\n"
    "            self.protect_in_memory = true;\n"
    "        }\n"
    "    }\n"
    "}\n\n"
    "impl Serialize for StringValue {\n")
MOD = XML_DB / "mod.rs"
mod_text = MOD.read_text()
mod_text += '''
/// Kutup's copy (vendor/keepass/KUTUP.md): reads an unencrypted KeePass XML
/// file (KeePassXC's or KeePass's XML export): values marked
/// `ProtectInMemory` come back protected, attachments from Meta/Binaries.
pub fn from_plain_xml(data: &[u8]) -> Result<crate::db::Database, ParseXmlError> {
    let mut plain = crate::crypt::ciphers::PlainCipher;
    parse_xml(data, &[], &mut plain)
}

/// Kutup's copy (vendor/keepass/KUTUP.md): writes the database as an
/// unencrypted KeePass XML file that stands alone: protected values in the
/// clear marked `ProtectInMemory="True"`, every attachment in Meta/Binaries.
#[cfg(feature = "save_kdbx4")]
pub fn to_plain_xml(db: &crate::db::Database) -> Result<Vec<u8>, DatabaseSaveError> {
    let renumbered;
    let db = if db.has_dense_attachment_ids() {
        db
    } else {
        renumbered = db.with_dense_attachment_ids();
        &renumbered
    };
    let mut plain = crate::crypt::ciphers::PlainCipher;
    let mut kdbx = KeePassFile::db_to_xml(db, &mut plain)?;
    fn unprotect_group(group: &mut Group) {
        for child in &mut group.children {
            match child {
                group::GroupOrEntry::Group(g) => unprotect_group(g),
                group::GroupOrEntry::Entry(e) => unprotect_entry(e),
            }
        }
    }
    fn unprotect_entry(entry: &mut entry::Entry) {
        for field in &mut entry.string_fields {
            field.value.unprotect_plain();
        }
        if let Some(history) = &mut entry.history {
            for item in &mut history.entries {
                unprotect_entry(item);
            }
        }
    }
    unprotect_group(&mut kdbx.root.group);
    let mut attachments: Vec<(usize, &crate::db::Value<Vec<u8>>)> = db
        .attachments
        .iter()
        .map(|(id, attachment)| (id.id(), &attachment.data))
        .collect();
    attachments.sort_by_key(|(id, _)| *id);
    kdbx.meta.binaries = Some(meta::Binaries {
        binaries: attachments
            .into_iter()
            .map(|(id, data)| meta::Binary {
                value: base64_engine::STANDARD.encode(data.get()),
                id,
                compressed: Some(false),
                protected: Some(data.is_protected()),
            })
            .collect(),
    });
    let xml = quick_xml::se::to_string_with_root("KeePassFile", &kdbx)?;
    Ok(format!("<?xml version=\\"1.0\\" encoding=\\"utf-8\\" standalone=\\"yes\\"?>\\n{xml}").into_bytes())
}
'''
MOD.write_text(mod_text)
LIB2 = ROOT.parents[1] / "lib.rs"
lib2 = LIB2.read_text()
if lib2.count("pub use self::key::key_file_element;\n") != 1:
    sys.exit("patch-vendored-keepass: the key_file_element export not found once in lib.rs")
LIB2.write_text(lib2.replace("pub use self::key::key_file_element;\n",
    "pub use self::key::key_file_element;\n/// Public in Kutup's copy (vendor/keepass/KUTUP.md): plain KeePass XML.\n"
    "pub use self::format::xml_db::from_plain_xml;\n#[cfg(feature = \"save_kdbx4\")]\n"
    "/// Public in Kutup's copy (vendor/keepass/KUTUP.md): plain KeePass XML.\n"
    "pub use self::format::xml_db::to_plain_xml;\n", 1))
# The crate's own unit tests, kept compiling and passing with the patch
# (scripts/test-vendored-keepass.sh runs them in the rust gate): the new
# fields in two test initializers, and the two tests that read upstream's
# tests/resources (not in the published crate) ignored with that reason.
SRC = ROOT.parents[1]
def once_src(rel, old, new):
    path = SRC / rel
    text = path.read_text()
    if text.count(old) != 1:
        sys.exit(f"patch-vendored-keepass: `{old.strip()[:60]}` not found once in {rel}")
    path.write_text(text.replace(old, new, 1))
once_src("format/xml_db/entry.rs",
    '                protected: false,\n                value: Some("user123".to_string()),\n',
    '                protected: false,\n                protect_in_memory: false,\n                value: Some("user123".to_string()),\n')
once_src("format/xml_db/entry.rs",
    '                protected: true,\n                value: Some("cGFzc3dvcmQ=".to_string()),\n',
    '                protected: true,\n                protect_in_memory: false,\n                value: Some("cGFzc3dvcmQ=".to_string()),\n')
once_src("key/mod.rs",
    "        assert!(DatabaseKey {\n            password: None,\n            keyfile: None,\n",
    "        assert!(DatabaseKey {\n            password: None,\n            password_hash: None,\n            keyfile: None,\n")
RESOURCES = '    #[test]\n    #[ignore = "reads upstream\'s tests/resources, which the published crate leaves out"]\n'
once_src("db/mod.rs", "    #[test]\n    fn test_xml() -> Result<(), DatabaseOpenError> {\n",
    RESOURCES + "    fn test_xml() -> Result<(), DatabaseOpenError> {\n")
once_src("db/otp.rs", "    #[test]\n    fn kdbx4_entry() -> Result<(), Box<dyn std::error::Error>> {\n",
    RESOURCES + "    fn kdbx4_entry() -> Result<(), Box<dyn std::error::Error>> {\n")
subprocess.run(["cargo", "fmt", "--manifest-path", str(ROOT.parents[2] / "Cargo.toml")], check=True)
print("patch-vendored-keepass: applied and formatted")
