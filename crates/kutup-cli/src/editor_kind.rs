//! Which files a Kutup editor keeps as collaboration state (Yjs) rather than
//! as whole-file versions: the text editor's kinds and Maps' place lists.
//! Their editors read the newest version as Yjs, so new content for them is
//! never stored as a `file` version: sync leaves them alone until the CLI
//! edits them as a Yjs peer (docs/plans/cli-yjs-sync.md).

/// Mirrors `TEXT_EXT` in `frontend/packages/drive-core/src/editorKind.ts`
/// exactly; change both together.
const TEXT_EXT: &[&str] = &[
    "md",
    "markdown",
    "txt", //
    "go",
    "js",
    "mjs",
    "cjs",
    "jsx",
    "ts",
    "tsx", //
    "py",
    "rs",
    "json",
    "yaml",
    "yml", //
    "html",
    "htm",
    "css",
    "toml",
    "sh",
    "sql", //
    "dockerfile",
    "containerfile",
    "nix", //
    // C / C++
    "c",
    "h",
    "cpp",
    "cc",
    "cxx",
    "c++",
    "hpp",
    "hh",
    "hxx",
    "h++", //
    // Other
    "java",
    "php",
    "phtml", //
    "xml",
    "xsl",
    "xsd", //
    "bash",
    "zsh",
    "fish", //
    "rb",
    "rake",
    "gemspec", //
    "pl",
    "pm", //
    "ps1",
    "psm1", //
    "lua",
    "swift",
];

/// Maps' place lists (`kinds.ts`: `kutupmap`), also kept as Yjs.
const PLACE_LIST_EXT: &str = "kutupmap";

/// The extension as `extensionOf` in `editorKind.ts` reads it: after the
/// last dot, lower case; a name without a dot ("Dockerfile") is its own.
fn extension_of(name: &str) -> String {
    match name.rfind('.') {
        Some(dot) => name[dot + 1..].to_lowercase(),
        None => name.to_lowercase(),
    }
}

/// Whether `name` is a place list, as `isListName` in `map/src/list.ts`
/// reads it: ending in `.kutupmap` (a name that is only "kutupmap" is not).
pub(crate) fn is_place_list(name: &str) -> bool {
    name.to_lowercase().ends_with(&format!(".{PLACE_LIST_EXT}"))
}

/// Whether `name`'s content lives as Yjs state, never as `file` versions.
pub(crate) fn edits_as_yjs(name: &str) -> bool {
    is_place_list(name) || TEXT_EXT.contains(&extension_of(name).as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_and_place_lists_are_yjs_others_are_files() {
        for name in [
            "notes.md",
            "README.TXT",
            "main.rs",
            "Dockerfile",
            "a.json",
            "trip.kutupmap",
        ] {
            assert!(edits_as_yjs(name), "{name}");
        }
        for name in [
            "photo.jpg",
            "data.dat",
            "vault.kdbx",
            "board.excalidraw",
            "report.docx",
            "x.svg",
            // Not a list without its dot (`isListName`), nor a text kind.
            "kutupmap",
        ] {
            assert!(!edits_as_yjs(name), "{name}");
        }
    }
}
