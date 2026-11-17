//! Reading the files of a ZIP archive (1Password's `.1pux`, Proton Pass's
//! export), as much as an import needs: stored and deflated files, found
//! through the central directory. Nothing is ever written to disk, and the
//! sizes are bounded so a small archive can't unpack into gigabytes.

use std::io::Read as _;

/// The most one file may unpack to.
pub const MAX_FILE_BYTES: usize = 64 * 1024 * 1024;
/// The most all files read from one archive may unpack to.
pub const MAX_TOTAL_BYTES: usize = 256 * 1024 * 1024;
/// The most files an archive may list.
pub const MAX_FILES: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ZipError {
    #[error("not a ZIP archive this can read: {0}")]
    Unreadable(&'static str),
    #[error("a file in the archive is larger than allowed")]
    TooLarge,
    #[error("the archive is encrypted")]
    Encrypted,
}

/// One file the central directory lists.
#[derive(Debug, Clone)]
pub struct ZipEntry {
    pub name: String,
    method: u16,
    flags: u16,
    compressed: usize,
    size: usize,
    local_offset: usize,
}

/// An archive's directory, and its bytes to read files from.
pub struct Zip<'a> {
    bytes: &'a [u8],
    pub entries: Vec<ZipEntry>,
    read_total: usize,
}

fn u16_at(b: &[u8], at: usize) -> Result<u16, ZipError> {
    b.get(at..at + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or(ZipError::Unreadable("cut short"))
}

fn u32_at(b: &[u8], at: usize) -> Result<usize, ZipError> {
    b.get(at..at + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize)
        .ok_or(ZipError::Unreadable("cut short"))
}

/// Whether `bytes` start as a ZIP archive does.
pub fn is_zip(bytes: &[u8]) -> bool {
    bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06")
}

impl<'a> Zip<'a> {
    pub fn open(bytes: &'a [u8]) -> Result<Self, ZipError> {
        // The end of central directory record: within the last 64 KiB + 22.
        let floor = bytes.len().saturating_sub(65_535 + 22);
        let end = (floor..bytes.len().saturating_sub(21))
            .rev()
            .find(|&i| bytes[i..].starts_with(b"PK\x05\x06"))
            .ok_or(ZipError::Unreadable("no central directory"))?;
        let count = u16_at(bytes, end + 10)? as usize;
        let mut at = u32_at(bytes, end + 16)?;
        if count == 0xFFFF || at == 0xFFFF_FFFF {
            return Err(ZipError::Unreadable("ZIP64 archives are not read"));
        }
        if count > MAX_FILES {
            return Err(ZipError::TooLarge);
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            if !bytes
                .get(at..)
                .is_some_and(|b| b.starts_with(b"PK\x01\x02"))
            {
                return Err(ZipError::Unreadable("a bad directory entry"));
            }
            let flags = u16_at(bytes, at + 8)?;
            let method = u16_at(bytes, at + 10)?;
            let compressed = u32_at(bytes, at + 20)?;
            let size = u32_at(bytes, at + 24)?;
            let name_len = u16_at(bytes, at + 28)? as usize;
            let extra_len = u16_at(bytes, at + 30)? as usize;
            let comment_len = u16_at(bytes, at + 32)? as usize;
            let local_offset = u32_at(bytes, at + 42)?;
            let name = bytes
                .get(at + 46..at + 46 + name_len)
                .ok_or(ZipError::Unreadable("cut short"))?;
            entries.push(ZipEntry {
                name: String::from_utf8_lossy(name).into_owned(),
                method,
                flags,
                compressed,
                size,
                local_offset,
            });
            at += 46 + name_len + extra_len + comment_len;
        }
        Ok(Self {
            bytes,
            entries,
            read_total: 0,
        })
    }

    /// The file named `name`, if the archive has it.
    pub fn find(&self, name: &str) -> Option<&ZipEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// The contents of `entry`, unpacked.
    pub fn read(&mut self, entry: &ZipEntry) -> Result<Vec<u8>, ZipError> {
        if entry.flags & 1 != 0 {
            return Err(ZipError::Encrypted);
        }
        if entry.size > MAX_FILE_BYTES || self.read_total + entry.size > MAX_TOTAL_BYTES {
            return Err(ZipError::TooLarge);
        }
        let at = entry.local_offset;
        if !self
            .bytes
            .get(at..)
            .is_some_and(|b| b.starts_with(b"PK\x03\x04"))
        {
            return Err(ZipError::Unreadable("a bad file header"));
        }
        let start =
            at + 30 + u16_at(self.bytes, at + 26)? as usize + u16_at(self.bytes, at + 28)? as usize;
        let data = self
            .bytes
            .get(start..start + entry.compressed)
            .ok_or(ZipError::Unreadable("cut short"))?;
        let out = match entry.method {
            0 => data.to_vec(),
            8 => {
                // Never more than the directory says, plus one byte to tell.
                let mut out = Vec::with_capacity(entry.size.min(MAX_FILE_BYTES));
                flate2::read::DeflateDecoder::new(data)
                    .take(entry.size as u64 + 1)
                    .read_to_end(&mut out)
                    .map_err(|_| ZipError::Unreadable("a damaged file"))?;
                out
            }
            _ => return Err(ZipError::Unreadable("a compression method this can't read")),
        };
        if out.len() != entry.size {
            return Err(ZipError::Unreadable(
                "a file's size isn't what the directory says",
            ));
        }
        self.read_total += out.len();
        Ok(out)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write as _;

    /// A ZIP of `files`, each deflated or stored.
    pub(crate) fn make(files: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut directory = Vec::new();
        for (name, data, deflate) in files {
            let packed = if *deflate {
                let mut e =
                    flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
                e.write_all(data).unwrap();
                e.finish().unwrap()
            } else {
                data.to_vec()
            };
            let offset = out.len() as u32;
            let method: u16 = if *deflate { 8 } else { 0 };
            let header = |sig: &[u8], central: bool| {
                let mut h = Vec::new();
                h.extend_from_slice(sig);
                if central {
                    h.extend_from_slice(&20u16.to_le_bytes());
                }
                h.extend_from_slice(&20u16.to_le_bytes());
                h.extend_from_slice(&0u16.to_le_bytes());
                h.extend_from_slice(&method.to_le_bytes());
                h.extend_from_slice(&[0; 8]);
                h.extend_from_slice(&(packed.len() as u32).to_le_bytes());
                h.extend_from_slice(&(data.len() as u32).to_le_bytes());
                h.extend_from_slice(&(name.len() as u16).to_le_bytes());
                h.extend_from_slice(&0u16.to_le_bytes());
                if central {
                    // Comment length, disk, internal and external attributes.
                    h.extend_from_slice(&[0; 10]);
                    h.extend_from_slice(&offset.to_le_bytes());
                }
                h.extend_from_slice(name.as_bytes());
                h
            };
            out.extend(header(b"PK\x03\x04", false));
            out.extend(&packed);
            directory.extend(header(b"PK\x01\x02", true));
        }
        let at = out.len() as u32;
        out.extend(&directory);
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&(files.len() as u16).to_le_bytes());
        out.extend_from_slice(&(files.len() as u16).to_le_bytes());
        out.extend_from_slice(&(directory.len() as u32).to_le_bytes());
        out.extend_from_slice(&at.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[test]
    fn stored_and_deflated_files_read_back() {
        let zip = make(&[
            ("a.txt", b"hello", false),
            ("dir/b.json", b"{\"x\":1}", true),
        ]);
        assert!(is_zip(&zip));
        let mut archive = Zip::open(&zip).unwrap();
        let names: Vec<_> = archive.entries.iter().map(|e| e.name.clone()).collect();
        assert_eq!(names, ["a.txt", "dir/b.json"]);
        let b = archive.find("dir/b.json").unwrap().clone();
        assert_eq!(archive.read(&b).unwrap(), b"{\"x\":1}");
        let a = archive.find("a.txt").unwrap().clone();
        assert_eq!(archive.read(&a).unwrap(), b"hello");
    }

    #[test]
    fn lies_and_damage_are_refused() {
        assert!(Zip::open(b"PK\x03\x04 nothing").is_err());
        // A file that unpacks to more than its directory says.
        let mut zip = make(&[("big", &[7u8; 4096], true)]);
        let mut archive = Zip::open(&zip).unwrap();
        let mut lie = archive.entries[0].clone();
        lie.size = 10;
        assert!(archive.read(&lie).is_err());
        // Cut short.
        zip.truncate(zip.len() / 2);
        assert!(Zip::open(&zip).is_err());
    }
}
