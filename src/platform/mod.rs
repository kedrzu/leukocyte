//! The only OS-specific code: reading processes, signalling them, notifying the user and
//! installing the LaunchAgent.
//!
//! The seam for another OS is this module's function set (`list_pids`, `base_info`, `cmdline`,
//! `cwd`, `sockets`, `signal`, `alive`, `current_pid`, `current_uid`, `release_free_memory`,
//! `notify`, `launchd`), implemented per OS in a submodule; the types below are shared.
//! This is the only module allowed `unsafe`.
//!
//! Every fact the OS refuses (another uid's process, a pid that vanished) is `None`, never a
//! default value: the rules treat unknown as protective.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[cfg(target_os = "macos")]
pub mod launchd;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub mod notify;
#[cfg(target_os = "macos")]
pub use macos::{
    alive, base_info, cmdline, current_pid, current_uid, cwd, list_pids, release_free_memory,
    signal, sockets,
};

/// The identity of a process: a pid whose current start time differs is a different process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcKey {
    pub pid: i32,
    /// Start time as the kernel reports it, in microseconds since the Unix epoch.
    pub start: u64,
}

/// The facts read eagerly for every pid in a snapshot.
#[derive(Debug, Clone)]
pub struct BaseInfo {
    pub key: ProcKey,
    pub ppid: i32,
    /// Effective uid.
    pub uid: u32,
    /// The controlling terminal's device number; `None` when the process has no controlling
    /// terminal. The kernel reports it for every process, so this is never an unknown.
    pub tty: Option<u32>,
    /// Session id (`getsid`); `None` when refused.
    pub session: Option<i32>,
    /// Resident set size in bytes; `None` for another uid's process.
    pub rss: Option<u64>,
    /// CPU and disk counters; `None` for another uid's process.
    pub usage: Option<Usage>,
}

/// Cumulative resource counters of one process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Usage {
    /// User + system CPU of the process itself.
    pub cpu: Duration,
    /// User + system CPU of its children that exited and were reaped.
    pub children_cpu: Duration,
    pub disk_read: u64,
    pub disk_written: u64,
}

/// What a process was started with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cmdline {
    /// The executable path the kernel recorded at exec.
    pub exe: String,
    pub argv: Vec<String>,
    /// Only the variables whose names the caller allowed; the others are skipped while parsing
    /// and never stored. `None` when the kernel withholds the environment (platform binaries
    /// such as `/bin/zsh`), so a missing variable there is unknown, not absent.
    pub env: Option<BTreeMap<String, String>>,
}

/// The TCP sockets a process holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sockets {
    /// Local ports of its listening TCP sockets.
    pub listening: BTreeSet<u16>,
    /// Established TCP connections, in either direction.
    pub established: usize,
    /// Established TCP connections whose local port is one of `listening`: clients connected
    /// to it.
    pub inbound: usize,
}

/// Whether the system lets the daemon show notifications.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "reason")]
pub enum NotifyState {
    Allowed,
    Denied,
    /// The user has not answered the permission request yet.
    NotAsked,
    /// Notifications cannot work here, and why.
    Unavailable(String),
}

impl NotifyState {
    /// The state from its [`fmt::Display`] form, as `request-notifications` prints it.
    pub fn parse(line: &str) -> Option<Self> {
        match line.trim() {
            "allowed" => Some(Self::Allowed),
            "denied" => Some(Self::Denied),
            "not asked" => Some(Self::NotAsked),
            other => other
                .strip_prefix("unavailable (")
                .and_then(|rest| rest.strip_suffix(')'))
                .map(|reason| Self::Unavailable(reason.to_owned())),
        }
    }
}

impl fmt::Display for NotifyState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allowed => f.write_str("allowed"),
            Self::Denied => f.write_str("denied"),
            Self::NotAsked => f.write_str("not asked"),
            Self::Unavailable(reason) => write!(f, "unavailable ({reason})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notify_states_print_and_parse_back() {
        for state in [
            NotifyState::Allowed,
            NotifyState::Denied,
            NotifyState::NotAsked,
            NotifyState::Unavailable("not running from Leukocyte.app".to_owned()),
        ] {
            assert_eq!(NotifyState::parse(&state.to_string()), Some(state));
        }
        assert_eq!(NotifyState::parse("allowed\n"), Some(NotifyState::Allowed));
        assert_eq!(NotifyState::parse("Usage: leukocyte"), None);
    }
}
