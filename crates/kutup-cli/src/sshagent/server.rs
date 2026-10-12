//! The agent's Unix socket: one thread per connection, the shared key
//! state behind a mutex, and a timer that forgets decrypted keys when unused.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};

use super::approval::Approver;
use super::{handle, peer, proto, Connection, LoadedKey, Policy, State};

/// `$XDG_RUNTIME_DIR/kutup/ssh-agent.sock`, else `~/.kutup/ssh-agent.sock`.
pub fn default_socket() -> PathBuf {
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(|dir| PathBuf::from(dir).join("kutup"))
        .or_else(|| dirs::home_dir().map(|home| home.join(".kutup")))
        .unwrap_or_else(|| std::env::temp_dir().join("kutup"));
    dir.join("ssh-agent.sock")
}

/// Binds `socket` in a directory only this user can enter. A live agent
/// there is left alone; a stale socket is replaced.
pub fn bind(socket: &Path) -> Result<UnixListener> {
    let dir = socket.parent().context("socket path has no directory")?;
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    if socket.exists() {
        if UnixStream::connect(socket).is_ok() {
            bail!("an agent already serves {}", socket.display());
        }
        std::fs::remove_file(socket)
            .with_context(|| format!("remove stale {}", socket.display()))?;
    }
    let listener =
        UnixListener::bind(socket).with_context(|| format!("bind {}", socket.display()))?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

fn read_message(stream: &mut UnixStream) -> Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match stream.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > proto::MAX_MESSAGE {
        bail!("message of {len} bytes refused");
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body)?;
    Ok(Some(body))
}

/// Keys to serve again when a vault changed on disk (`None`: unchanged).
pub type Reload = dyn Fn() -> Option<Vec<LoadedKey>> + Send + Sync;

/// Serves until the process ends.
pub fn serve(
    listener: UnixListener,
    state: Arc<Mutex<State>>,
    policy: Arc<Policy>,
    approver: Arc<dyn Approver>,
    reload: Arc<Reload>,
) -> Result<()> {
    let log = |message: String| eprintln!("kutup ssh-agent: {message}");
    {
        let state = state.clone();
        let idle = policy.idle;
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(15).min(idle));
            let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
            if state.lock_if_idle(idle) {
                eprintln!(
                    "kutup ssh-agent: unused for a while; decrypted keys and approvals forgotten"
                );
            }
        });
    }
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let process = match peer::check(&stream) {
            Ok(process) => process,
            Err(error) => {
                log(format!("{error:#}"));
                continue;
            }
        };
        let (state, policy, approver, reload) = (
            state.clone(),
            policy.clone(),
            approver.clone(),
            reload.clone(),
        );
        std::thread::spawn(move || {
            let mut connection = Connection {
                process,
                ..Connection::default()
            };
            loop {
                let body = match read_message(&mut stream) {
                    Ok(Some(body)) => body,
                    Ok(None) => break,
                    Err(error) => {
                        log(format!("{error:#}"));
                        break;
                    }
                };
                let response = match proto::parse(&body) {
                    Ok(request) => {
                        if matches!(
                            request,
                            proto::Request::Identities | proto::Request::Sign { .. }
                        ) {
                            if let Some(keys) = reload() {
                                let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
                                state.keys = keys;
                                state.lock();
                                log("a vault changed; its keys were read again".into());
                            }
                        }
                        handle(
                            request,
                            &mut connection,
                            &state,
                            &policy,
                            approver.as_ref(),
                            &log,
                        )
                    }
                    Err(_) => vec![proto::FAILURE],
                };
                if stream.write_all(&proto::frame(&response)).is_err() {
                    break;
                }
            }
        });
    }
    Ok(())
}
