#!/usr/bin/env python3
"""Apply Kutup's patch to the vendored `keepass` crate
(crates/kutup-pass/vendor/keepass).

The patch only widens visibility: the database model's internal fields and two
id constructors become public, so `crates/kutup-pass` can read and write a
vault completely (custom icons keep their UUIDs, history items keep their
attachments, entries keep their previous group). No behaviour changes.
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
# The README is the crate's rustdoc; its relative links point into upstream's
# repository, which the published crate does not include.
readme = ROOT.parents[2] / "README.md"
readme.write_text(readme.read_text().replace("](./examples)", "](https://github.com/sseemayer/keepass-rs/tree/master/examples)"))
subprocess.run(["cargo", "fmt", "--manifest-path", str(ROOT.parents[2] / "Cargo.toml")], check=True)
print("patch-vendored-keepass: applied and formatted")
