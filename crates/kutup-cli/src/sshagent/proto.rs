//! The SSH agent protocol (draft-miller-ssh-agent), the part an agent that
//! holds its keys needs: listing keys, signing, and OpenSSH's
//! `session-bind@openssh.com` extension. Everything else is refused.

use anyhow::{anyhow, bail, Result};

pub const FAILURE: u8 = 5;
pub const SUCCESS: u8 = 6;
pub const REQUEST_IDENTITIES: u8 = 11;
pub const IDENTITIES_ANSWER: u8 = 12;
pub const SIGN_REQUEST: u8 = 13;
pub const SIGN_RESPONSE: u8 = 14;
pub const ADD_IDENTITY: u8 = 17;
pub const ADD_ID_CONSTRAINED: u8 = 25;
pub const EXTENSION: u8 = 27;

pub const CONSTRAIN_LIFETIME: u8 = 1;
pub const CONSTRAIN_CONFIRM: u8 = 2;

/// The largest message accepted (OpenSSH's own limit).
pub const MAX_MESSAGE: usize = 256 * 1024;

/// A request from a client.
#[derive(Debug, PartialEq, Eq)]
pub enum Request {
    Identities,
    Sign {
        key: Vec<u8>,
        data: Vec<u8>,
        flags: u32,
    },
    SessionBind {
        host_key: Vec<u8>,
        session_id: Vec<u8>,
        signature: Vec<u8>,
        forwarding: bool,
    },
    /// Anything else: answered with failure.
    Other(u8),
}

pub struct Reader<'a>(pub &'a [u8]);

impl<'a> Reader<'a> {
    pub fn u8(&mut self) -> Result<u8> {
        let (&first, rest) = self
            .0
            .split_first()
            .ok_or_else(|| anyhow!("short message"))?;
        self.0 = rest;
        Ok(first)
    }
    pub fn u32(&mut self) -> Result<u32> {
        if self.0.len() < 4 {
            bail!("short message");
        }
        let value = u32::from_be_bytes(self.0[..4].try_into()?);
        self.0 = &self.0[4..];
        Ok(value)
    }
    pub fn string(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        if self.0.len() < len {
            bail!("short message");
        }
        let (value, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(value)
    }
}

pub fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub fn put_string(out: &mut Vec<u8>, value: &[u8]) {
    put_u32(out, value.len() as u32);
    out.extend_from_slice(value);
}

/// A message on the wire: its length, then its body.
pub fn frame(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    put_string(&mut out, body);
    out
}

pub fn parse(body: &[u8]) -> Result<Request> {
    let mut r = Reader(body);
    let kind = r.u8()?;
    Ok(match kind {
        REQUEST_IDENTITIES => Request::Identities,
        SIGN_REQUEST => {
            let key = r.string()?.to_vec();
            let data = r.string()?.to_vec();
            let flags = r.u32()?;
            Request::Sign { key, data, flags }
        }
        EXTENSION => {
            let name = r.string()?;
            if name != b"session-bind@openssh.com" {
                return Ok(Request::Other(EXTENSION));
            }
            let host_key = r.string()?.to_vec();
            let session_id = r.string()?.to_vec();
            let signature = r.string()?.to_vec();
            let forwarding = r.u8()? != 0;
            Request::SessionBind {
                host_key,
                session_id,
                signature,
                forwarding,
            }
        }
        other => Request::Other(other),
    })
}

/// What a signature is for, read from the data to be signed.
#[derive(Debug, PartialEq, Eq)]
pub enum Purpose {
    /// An SSH login as `user` (RFC 4252 public-key authentication).
    Login {
        user: String,
    },
    /// An SSHSIG signature (`ssh-keygen -Y sign`), `git` for commits and tags.
    Signature {
        namespace: String,
    },
    Unknown,
}

pub fn purpose(data: &[u8]) -> Purpose {
    if let Some(rest) = data.strip_prefix(b"SSHSIG") {
        let mut r = Reader(rest);
        if let Ok(namespace) = r.string() {
            return Purpose::Signature {
                namespace: String::from_utf8_lossy(namespace).into_owned(),
            };
        }
        return Purpose::Unknown;
    }
    let mut r = Reader(data);
    let login = (|| -> Result<Option<String>> {
        let _session_id = r.string()?;
        if r.u8()? != 50 {
            return Ok(None); // SSH_MSG_USERAUTH_REQUEST
        }
        let user = r.string()?;
        let _service = r.string()?;
        let method = r.string()?;
        Ok((method == b"publickey").then(|| String::from_utf8_lossy(user).into_owned()))
    })();
    match login {
        Ok(Some(user)) => Purpose::Login { user },
        _ => Purpose::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_parse() {
        assert_eq!(parse(&[REQUEST_IDENTITIES]).unwrap(), Request::Identities);
        let mut sign = vec![SIGN_REQUEST];
        put_string(&mut sign, b"key");
        put_string(&mut sign, b"data");
        put_u32(&mut sign, 4);
        assert_eq!(
            parse(&sign).unwrap(),
            Request::Sign {
                key: b"key".to_vec(),
                data: b"data".to_vec(),
                flags: 4
            }
        );
        let mut bind = vec![EXTENSION];
        put_string(&mut bind, b"session-bind@openssh.com");
        put_string(&mut bind, b"hk");
        put_string(&mut bind, b"sid");
        put_string(&mut bind, b"sig");
        bind.push(1);
        assert_eq!(
            parse(&bind).unwrap(),
            Request::SessionBind {
                host_key: b"hk".to_vec(),
                session_id: b"sid".to_vec(),
                signature: b"sig".to_vec(),
                forwarding: true
            }
        );
        assert_eq!(
            parse(&[ADD_IDENTITY]).unwrap(),
            Request::Other(ADD_IDENTITY)
        );
        assert!(parse(&[SIGN_REQUEST, 0, 0]).is_err());
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn purposes_are_read_from_the_data() {
        let mut login = Vec::new();
        put_string(&mut login, b"session-id");
        login.push(50);
        put_string(&mut login, b"ayse");
        put_string(&mut login, b"ssh-connection");
        put_string(&mut login, b"publickey");
        login.push(1);
        assert_eq!(
            purpose(&login),
            Purpose::Login {
                user: "ayse".into()
            }
        );
        let mut sig = b"SSHSIG".to_vec();
        put_string(&mut sig, b"git");
        assert_eq!(
            purpose(&sig),
            Purpose::Signature {
                namespace: "git".into()
            }
        );
        assert_eq!(purpose(b"random bytes"), Purpose::Unknown);
    }
}
