//! Bounded-memory streaming encrypt-upload / download-decrypt helpers —
//! mirrors `internal/upload/stream.go` and `internal/download/stream.go`.
//!
//! Wire framing matches the frontend/server exactly: a 24-byte secretstream
//! header followed by 5 MiB plaintext chunks, each producing `5 MiB + 17 B`
//! ciphertext. The final chunk carries `TAG_FINAL`.

use std::io::{self, ErrorKind, Read, Write};

use anyhow::{bail, Result};

use kutup_crypto::stream::{
    StreamDecryptor, StreamEncryptor, ABYTES, CHUNK_SIZE, HEADER_BYTES, TAG_FINAL, TAG_MESSAGE,
};

/// Total ciphertext byte count for `plain_bytes` of plaintext, given the
/// secretstream framing (24-byte header + 17 B per chunk). Used as the tus
/// `Upload-Length`. An empty plaintext is just the header. Mirrors `CipherSize`.
pub fn cipher_size(plain_bytes: i64) -> i64 {
    if plain_bytes <= 0 {
        return HEADER_BYTES as i64;
    }
    let chunk = CHUNK_SIZE as i64;
    let num_chunks = (plain_bytes + chunk - 1) / chunk;
    HEADER_BYTES as i64 + plain_bytes + ABYTES as i64 * num_chunks
}

/// Reads into `buf` until full or EOF; returns the number of bytes read
/// (`< buf.len()` ⇒ EOF reached). Like Go's `io.ReadFull` but tolerant of a
/// short final read.
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Iterates ciphertext chunks for a tus upload. The first chunk has the 24-byte
/// header prepended; the final chunk carries `TAG_FINAL`. Mirrors the Go
/// `StreamEncryptor` / `NextChunk`.
pub struct StreamUploader<R: Read> {
    enc: StreamEncryptor,
    header: Option<[u8; HEADER_BYTES]>,
    reader: R,
    plain_total: i64,
    plain_read: i64,
    buf: Vec<u8>,
    done: bool,
}

impl<R: Read> StreamUploader<R> {
    pub fn new(reader: R, key: &[u8], plain_total: i64) -> Result<Self> {
        let (enc, header) = StreamEncryptor::new(key)?;
        Ok(Self {
            enc,
            header: Some(header),
            reader,
            plain_total,
            plain_read: 0,
            buf: vec![0u8; CHUNK_SIZE],
            done: false,
        })
    }

    /// Plaintext bytes consumed so far (for progress reporting).
    pub fn plain_read(&self) -> i64 {
        self.plain_read
    }

    /// Returns the next ciphertext chunk to ship, or `None` at end of stream.
    pub fn next_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        if self.done {
            return Ok(None);
        }
        let remaining = self.plain_total - self.plain_read;

        // Empty-file edge: emit just the header once, then end.
        if remaining <= 0 {
            self.done = true;
            return Ok(self.header.take().map(|h| h.to_vec()));
        }

        let to_read = remaining.min(CHUNK_SIZE as i64) as usize;
        let n = read_full(&mut self.reader, &mut self.buf[..to_read])?;
        self.plain_read += n as i64;

        let is_last = self.plain_read == self.plain_total;
        let tag = if is_last { TAG_FINAL } else { TAG_MESSAGE };
        let cipher = self.enc.push(&self.buf[..n], tag)?;

        let out = match self.header.take() {
            Some(h) => {
                let mut v = Vec::with_capacity(h.len() + cipher.len());
                v.extend_from_slice(&h);
                v.extend_from_slice(&cipher);
                v
            }
            None => cipher,
        };
        if is_last {
            self.done = true;
        }
        Ok(Some(out))
    }
}

/// Reads the encrypted stream from `src`, decrypts each 5 MiB + 17 B chunk, and
/// writes plaintext to `dst`. Returns total plaintext bytes written. Memory
/// stays bounded (~10 MiB) regardless of size. Mirrors `download.Stream`.
pub fn stream_download(
    mut src: impl Read,
    key: &[u8],
    dst: &mut impl Write,
    mut on_progress: impl FnMut(i64),
) -> Result<i64> {
    let mut header = [0u8; HEADER_BYTES];
    if read_full(&mut src, &mut header)? < HEADER_BYTES {
        bail!("stream header truncated");
    }
    let mut dec = StreamDecryptor::new(key, &header)?;

    let mut buf = vec![0u8; CHUNK_SIZE + ABYTES];
    let mut plain_written = 0i64;
    loop {
        let n = read_full(&mut src, &mut buf)?;
        let at_eof = n < buf.len();
        if n == 0 {
            // Clean EOF without a trailing chunk: header-only (empty file) or
            // the prior chunk was already FINAL.
            return Ok(plain_written);
        }
        let (plain, tag) = dec.pull(&buf[..n])?;
        dst.write_all(&plain)?;
        plain_written += plain.len() as i64;
        on_progress(plain_written);

        let is_final = tag == TAG_FINAL;
        if is_final && at_eof {
            return Ok(plain_written);
        }
        if at_eof && !is_final {
            bail!("stream cut before FINAL chunk");
        }
        if is_final && !at_eof {
            bail!("FINAL chunk seen but bytes remain on wire");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_download_roundtrip() {
        let key = [9u8; 32];
        // Spans two chunks to exercise framing.
        let plain: Vec<u8> = (0..CHUNK_SIZE + 1234).map(|i| (i % 251) as u8).collect();

        let mut up = StreamUploader::new(&plain[..], &key, plain.len() as i64).unwrap();
        let mut wire = Vec::new();
        while let Some(chunk) = up.next_chunk().unwrap() {
            wire.extend_from_slice(&chunk);
        }
        assert_eq!(wire.len() as i64, cipher_size(plain.len() as i64));

        let mut out = Vec::new();
        let n = stream_download(&wire[..], &key, &mut out, |_| {}).unwrap();
        assert_eq!(n, plain.len() as i64);
        assert_eq!(out, plain);
    }

    #[test]
    fn empty_file_roundtrip() {
        let key = [3u8; 32];
        let mut up = StreamUploader::new(&[][..], &key, 0).unwrap();
        let mut wire = Vec::new();
        while let Some(c) = up.next_chunk().unwrap() {
            wire.extend_from_slice(&c);
        }
        assert_eq!(wire.len(), HEADER_BYTES); // header only
        let mut out = Vec::new();
        assert_eq!(
            stream_download(&wire[..], &key, &mut out, |_| {}).unwrap(),
            0
        );
        assert!(out.is_empty());
    }
}
