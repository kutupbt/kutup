//! Extension → MIME lookup, shared by every upload path. Replaces the three
//! hand-rolled tables (upload/share/syncengine) that had drifted apart.
//! The value is E2E-encrypted metadata only clients ever read.

use std::path::Path;

pub fn guess_mime(path: &Path) -> String {
    mime_guess::from_path(path)
        .first_or_octet_stream()
        .essence_str()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::guess_mime;
    use std::path::Path;

    #[test]
    fn common_extensions() {
        // .zip is the case the old hand tables disagreed on.
        assert_eq!(guess_mime(Path::new("a.zip")), "application/zip");
        assert_eq!(guess_mime(Path::new("photo.JPG")), "image/jpeg");
        assert_eq!(guess_mime(Path::new("doc.pdf")), "application/pdf");
        assert_eq!(
            guess_mime(Path::new("no-extension")),
            "application/octet-stream"
        );
    }
}
