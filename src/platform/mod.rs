//! The only OS-specific code: reading processes and signalling them.
//!
//! The seam for another OS is this module's function set (`list_pids`, `base_info`, `cmdline`,
//! `cwd`, `sockets`, `signal`, `alive`, `current_pid`, `current_uid`), implemented per OS in a submodule;
//! the types below are shared.
//! This is the only module allowed `unsafe`.
//!
//! Every fact the OS refuses (another uid's process, a pid that vanished) is `None`, never a
//! default value: the rules treat unknown as protective.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{
    alive, base_info, cmdline, current_pid, current_uid, cwd, list_pids, signal, sockets,
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
