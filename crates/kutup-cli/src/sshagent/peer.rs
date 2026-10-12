//! Who is on the other end of the socket: only the agent's own user is
//! served, and the requesting process is named in the approval prompt.

use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

use anyhow::{bail, Result};

/// Checks the peer is this user; returns its process, when known.
pub fn check(stream: &UnixStream) -> Result<Option<String>> {
    let fd = stream.as_raw_fd();
    // SAFETY: getuid has no preconditions.
    let me = unsafe { libc::getuid() };
    #[cfg(target_os = "linux")]
    {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: `cred` and `len` are valid for writes of the sizes given.
        let ok = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        } == 0;
        if !ok {
            bail!("could not tell who connected");
        }
        if cred.uid != me {
            bail!("refused a connection from another user (uid {})", cred.uid);
        }
        Ok(process(cred.pid))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: `uid` and `gid` are valid for writes.
        if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
            bail!("could not tell who connected");
        }
        if uid != me {
            bail!("refused a connection from another user (uid {uid})");
        }
        Ok(None)
    }
}

#[cfg(target_os = "linux")]
fn process(pid: libc::pid_t) -> Option<String> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let args: Vec<String> = raw
        .split(|b| *b == 0)
        .filter(|a| !a.is_empty())
        .take(4)
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .collect();
    if args.is_empty() {
        return None;
    }
    let mut text = args.join(" ");
    if text.chars().count() > 80 {
        text = text.chars().take(77).collect::<String>() + "...";
    }
    Some(format!("{text} (pid {pid})"))
}
