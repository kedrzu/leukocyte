//! The daemon's unix socket: one JSON request and one JSON response per connection, each a
//! single line.
//!
//! `status` is answered from a copy the scan thread publishes after every tick; every other
//! request is run on the scan thread between ticks (the rules' Luau states never leave it), and
//! the socket thread waits for the answer at most [`COMMAND_TIMEOUT`].

use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::config::{ConfigMode, Paths};

/// How long the socket waits for the scan thread to answer a request.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a connection may take to send its request or read the response.
const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// The largest request accepted: a `check` carries a whole rules file.
const MAX_REQUEST_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case")]
pub enum Request {
    Status,
    /// Explains where the processes matched by rules stand. With `rules`, that text is
    /// evaluated as a rules file scoped to `repo_path` (every process without one); without
    /// it, the registered rules of `repo_path`, or all of them.
    Check {
        #[serde(default)]
        repo_path: Option<String>,
        #[serde(default)]
        rules: Option<String>,
    },
    /// Keeps the running process `pid` (until it exits or the daemon restarts).
    Keep {
        pid: i32,
    },
    /// Sets `mode` in `config.toml`.
    Mode {
        mode: ConfigMode,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "response", rename_all = "snake_case")]
pub enum Response {
    Status(Box<StatusReply>),
    Check(CheckReply),
    Kept { pid: i32, start: u64 },
    Mode { mode: ConfigMode },
    Error { message: String },
}

impl Response {
    pub fn error(message: impl Into<String>) -> Self {
        Self::Error {
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StatusReply {
    pub pid: i32,
    pub version: String,
    pub mode: ConfigMode,
    /// Why `config.toml` was rejected; the previous config stays in force.
    pub config_error: Option<String>,
    pub repos: Vec<RepoStatus>,
    pub personal: SourceStatus,
    pub last_scan: Option<ScanStatus>,
    pub in_flight: Vec<InFlightStatus>,
    /// The last time the fuse tripped.
    pub fuse: Option<FuseStatus>,
    /// Rule evaluations failing as of the last scan.
    pub eval_errors: Vec<EvalErrorStatus>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RepoStatus {
    /// As written in `config.toml`.
    pub path: String,
    /// Why the path could not be registered (not a git checkout, missing).
    pub register_error: Option<String>,
    pub rules: SourceStatus,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SourceStatus {
    pub file: String,
    /// Whether rules from the file are in force (the last version that loaded).
    pub loaded: bool,
    pub rule_count: usize,
    /// Why the current version of the file did not load.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatus {
    /// RFC 3339.
    pub at: String,
    pub duration_ms: u64,
    pub processes: usize,
    /// Why the last scan failed, if it did.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InFlightStatus {
    pub pid: i32,
    pub rule: String,
    pub source: String,
    pub subtree: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuseStatus {
    pub at: String,
    pub kills: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalErrorStatus {
    pub source: String,
    pub rule: String,
    pub message: String,
    /// When the error was first seen.
    pub since: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CheckReply {
    pub explanations: Vec<ExplanationReply>,
    pub eval_errors: Vec<CheckEvalError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplanationReply {
    pub pid: i32,
    pub start: u64,
    pub exe: Option<String>,
    /// Redacted.
    pub argv: Option<Vec<String>>,
    /// `kill_ready`, `would_kill`, `quarantined`, `protected`, `report_only`, `no_verdict`.
    pub state: String,
    /// What the state depends on: the time left in quarantine, what protects, why no verdict.
    pub detail: Option<String>,
    pub rule: String,
    pub source: String,
    pub reason: Option<String>,
    pub matched: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckEvalError {
    pub source: String,
    pub rule: String,
    pub pid: i32,
    pub message: String,
}

/// A request for the scan thread, with where to send the answer.
pub struct Command {
    pub request: Request,
    pub reply: Sender<Response>,
}

/// Binds the socket at `path` (0600). A socket file left by a dead daemon is replaced; one a
/// live daemon answers on is an error.
pub fn bind(path: &Path) -> io::Result<UnixListener> {
    if path.exists() {
        if UnixStream::connect(path).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("a daemon is already listening on {}", path.display()),
            ));
        }
        fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Serves connections on `listener` until it fails: `status` from `status`, everything else
/// through `commands` to the scan thread.
pub fn serve(
    listener: &UnixListener,
    status: &Arc<Mutex<StatusReply>>,
    commands: &impl Fn(Command) -> bool,
) {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(e) = handle(stream, status, commands) {
                    eprintln!("leukocyte: socket: {e}");
                }
            }
            Err(e) => eprintln!("leukocyte: socket accept: {e}"),
        }
    }
}

fn handle(
    stream: UnixStream,
    status: &Arc<Mutex<StatusReply>>,
    commands: &impl Fn(Command) -> bool,
) -> io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut line = String::new();
    BufReader::new((&stream).take(MAX_REQUEST_BYTES)).read_line(&mut line)?;
    let response = match serde_json::from_str::<Request>(line.trim()) {
        Err(e) => Response::error(format!("bad request: {e}")),
        Ok(Request::Status) => {
            let status = status.lock().unwrap_or_else(PoisonError::into_inner);
            Response::Status(Box::new(status.clone()))
        }
        Ok(request) => {
            let (reply, answer) = mpsc::channel();
            if commands(Command { request, reply }) {
                answer
                    .recv_timeout(COMMAND_TIMEOUT)
                    .unwrap_or_else(|_| Response::error("the daemon did not answer in time"))
            } else {
                Response::error("the daemon is shutting down")
            }
        }
    };
    write_line(&stream, &response)
}

fn write_line(mut stream: &UnixStream, value: &impl Serialize) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    bytes.push(b'\n');
    stream.write_all(&bytes)?;
    stream.flush()
}

/// Sends one request to the daemon at the paths from the environment and returns its answer.
pub fn request(request: &Request) -> io::Result<Response> {
    request_at(&Paths::from_env()?.socket(), request)
}

/// Sends one request to the daemon listening on `socket`.
pub fn request_at(socket: &Path, request: &Request) -> io::Result<Response> {
    let stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(COMMAND_TIMEOUT + IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    write_line(&stream, request)?;
    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line)?;
    serde_json::from_str(line.trim()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_tagged_json() {
        let r: Request = serde_json::from_str(r#"{"request":"status"}"#).unwrap();
        assert_eq!(r, Request::Status);
        let r: Request = serde_json::from_str(r#"{"request":"check"}"#).unwrap();
        assert_eq!(
            r,
            Request::Check {
                repo_path: None,
                rules: None
            }
        );
        let r: Request = serde_json::from_str(r#"{"request":"mode","mode":"enforce"}"#).unwrap();
        assert_eq!(
            r,
            Request::Mode {
                mode: ConfigMode::Enforce
            }
        );
        let r: Request = serde_json::from_str(r#"{"request":"keep","pid":42}"#).unwrap();
        assert_eq!(r, Request::Keep { pid: 42 });
    }

    #[test]
    fn the_socket_is_0600_and_a_stale_one_is_replaced() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("s.sock");
        drop(bind(&path).unwrap());
        // The listener is gone, the file stays: a dead daemon's socket.
        assert!(path.exists());
        // A process another test forks at the same moment holds a copy of the listening fd
        // until it execs; wait for it to let go.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while UnixStream::connect(&path).is_ok() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let listener = bind(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        // A live one is not taken over.
        assert!(bind(&path).is_err());
        drop(listener);
    }

    #[test]
    fn status_is_served_without_the_scan_thread_and_commands_go_to_it() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("s.sock");
        let listener = bind(&path).unwrap();
        let status = Arc::new(Mutex::new(StatusReply {
            pid: 7,
            ..StatusReply::default()
        }));
        let served = Arc::clone(&status);
        std::thread::spawn(move || {
            serve(&listener, &served, &|cmd: Command| {
                let answer = match cmd.request {
                    Request::Keep { pid } => Response::Kept { pid, start: 1 },
                    _ => Response::error("unexpected"),
                };
                cmd.reply.send(answer).is_ok()
            });
        });
        let Response::Status(s) = request_at(&path, &Request::Status).unwrap() else {
            panic!("not a status");
        };
        assert_eq!(s.pid, 7);
        let kept = request_at(&path, &Request::Keep { pid: 9 }).unwrap();
        assert!(matches!(kept, Response::Kept { pid: 9, start: 1 }));
    }
}
