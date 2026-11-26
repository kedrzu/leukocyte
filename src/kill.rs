//! The kill executor: terminates the subtree of an engine kill, off the scan thread.
//!
//! The engine is not trusted. Every member is checked again against the hard guards on a fresh
//! snapshot, and every signal goes through [`platform::signal`], which re-verifies the member's
//! start time right before `kill(2)`, so a reused pid is never signalled. The anchor guard reads
//! the process itself (argv0, session, tty), never the fact store's origin records.
//!
//! One kill: the first signal to the members, leaves first; up to `grace` for them to exit;
//! then `SIGKILL` to the survivors and to their current descendants, enumerated on a second
//! fresh snapshot and guarded the same way.

#![deny(unsafe_code)]

use std::collections::HashSet;
use std::fmt;
use std::io;
use std::path::{Component, Path};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

use crate::engine::{Action, ActionKind, Own};
use crate::facts::ProcKey;
use crate::facts::origin;
use crate::facts::table::{Process, ProcessTable};
use crate::platform;
use crate::rules::Signal;

/// Executables under these directories are never signalled: the system's and installed apps'.
pub const PROTECTED_EXE_DIRS: [&str; 3] = ["/System", "/usr/libexec", "/Applications"];

/// How often members are polled for exit during `grace`.
const POLL: Duration = Duration::from_millis(100);
/// How long a kill waits after `SIGKILL` before it reports who survived. The kernel tears a
/// killed process down within milliseconds; this only bounds a pathological case.
const SETTLE: Duration = Duration::from_secs(2);

/// Why a member was not signalled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardReason {
    /// pid 0 or 1.
    Init,
    OtherUser,
    /// The daemon itself or one of its ancestors.
    Daemon,
    /// An agent process: its argv0 basename is one of [`origin::AGENTS`].
    Agent,
    /// A terminal session leader: it leads its session and has a controlling terminal.
    TerminalLeader,
    /// Its executable lies under one of [`PROTECTED_EXE_DIRS`].
    ProtectedExe,
    /// Its executable path is unreadable, relative, or does not resolve: unknown protects.
    UnknownExe,
    /// A guarded process `pid` lies between it and the kill's root.
    Below {
        pid: i32,
    },
    /// Not in the fresh snapshot: it exited, or its pid now belongs to another process.
    Gone,
    /// No fresh snapshot could be taken, or it lacks the daemon itself, so no guard could be
    /// checked.
    Unverified,
}

impl fmt::Display for GuardReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Init => f.write_str("init"),
            Self::OtherUser => f.write_str("another user's process"),
            Self::Daemon => f.write_str("the daemon or its ancestor"),
            Self::Agent => f.write_str("an agent"),
            Self::TerminalLeader => f.write_str("a terminal session leader"),
            Self::ProtectedExe => f.write_str("a system or application executable"),
            Self::UnknownExe => f.write_str("an unknown executable"),
            Self::Below { pid } => write!(f, "below guarded pid {pid}"),
            Self::Gone => f.write_str("gone"),
            Self::Unverified => f.write_str("guards could not be checked"),
        }
    }
}

/// One kill: the subtree of an engine [`ActionKind::Kill`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillJob {
    pub root: ProcKey,
    /// The processes to terminate, root first, parents before their children.
    pub subtree: Vec<ProcKey>,
    pub signal: Signal,
    pub grace: Duration,
}

impl KillJob {
    /// The job of an engine kill; `None` for any other action.
    pub fn from_action(action: &Action) -> Option<Self> {
        let ActionKind::Kill { signal, grace } = action.kind else {
            return None;
        };
        Some(Self {
            root: action.key,
            subtree: action.subtree.clone(),
            signal,
            grace,
        })
    }

    /// The root, then every other member once, in subtree order.
    fn members(&self) -> Vec<ProcKey> {
        let mut seen = HashSet::from([self.root]);
        std::iter::once(self.root)
            .chain(self.subtree.iter().copied().filter(|k| seen.insert(*k)))
            .collect()
    }
}

/// What one kill did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillReport {
    pub root: ProcKey,
    /// Members sent the first signal.
    pub signalled: Vec<ProcKey>,
    /// Processes sent `SIGKILL` after `grace`: surviving members and their descendants.
    pub escalated: Vec<ProcKey>,
    /// Processes left alone, and why. When the root is among them the kill was aborted.
    pub skipped: Vec<(ProcKey, GuardReason)>,
    /// Signalled or escalated processes still running when the kill ended.
    pub survivors_after: Vec<ProcKey>,
    /// Signals the kernel refused, with its error.
    pub failed: Vec<(ProcKey, String)>,
}

impl KillReport {
    fn new(root: ProcKey) -> Self {
        Self {
            root,
            signalled: Vec::new(),
            escalated: Vec::new(),
            skipped: Vec::new(),
            survivors_after: Vec::new(),
            failed: Vec::new(),
        }
    }

    /// Whether the root was guarded, so nothing was signalled.
    pub fn aborted(&self) -> bool {
        self.skipped.iter().any(|(key, _)| *key == self.root)
    }
}

/// Runs kills on worker threads and hands back their reports.
///
/// One thread per job: a rule's `grace` is unbounded, so a sequential worker would let one
/// long grace hold back every other kill. Jobs are few, since the engine issues at most
/// [`FUSE_LIMIT`](crate::engine::FUSE_LIMIT) kills a scan and none for a process already in
/// flight.
#[derive(Debug)]
pub struct Executor {
    own: Own,
    done_tx: Sender<KillReport>,
    done_rx: Receiver<KillReport>,
}

impl Executor {
    pub fn new(own: Own) -> Self {
        let (done_tx, done_rx) = mpsc::channel();
        Self {
            own,
            done_tx,
            done_rx,
        }
    }

    /// Starts `job` on its own thread. An error means no thread started and no report will
    /// come.
    pub fn submit(&self, job: KillJob) -> io::Result<()> {
        let own = self.own;
        let done = self.done_tx.clone();
        std::thread::Builder::new()
            .name(format!("kill-{}", job.root.pid))
            .spawn(move || {
                // The receiver lives in `self`; once the executor is dropped nobody waits for
                // the report.
                let _ = done.send(kill(&job, own));
            })?;
        Ok(())
    }

    /// Reports of the kills finished since the last call, without blocking.
    pub fn completed(&self) -> impl Iterator<Item = KillReport> + '_ {
        self.done_rx.try_iter()
    }

    /// The next finished kill's report, waiting up to `timeout`.
    pub fn wait(&self, timeout: Duration) -> Option<KillReport> {
        self.done_rx.recv_timeout(timeout).ok()
    }
}

/// Runs one kill on the calling thread; it blocks for up to `grace` plus a little.
pub fn kill(job: &KillJob, own: Own) -> KillReport {
    let mut report = KillReport::new(job.root);

    // 1. Guards, on a fresh snapshot.
    let Some(table) = snapshot() else {
        report.skipped.push((job.root, GuardReason::Unverified));
        return report;
    };
    let Some(guards) = Guards::new(&table, own) else {
        report.skipped.push((job.root, GuardReason::Unverified));
        return report;
    };
    let mut targets = Vec::new();
    for key in job.members() {
        match guards.check(key, job.root) {
            Some(reason) => report.skipped.push((key, reason)),
            None => targets.push(key),
        }
    }
    drop(table);
    if report.aborted() {
        return report;
    }

    // 2. The first signal, leaves first: the reverse of parents-before-children order.
    for &key in targets.iter().rev() {
        send(
            key,
            job.signal.raw(),
            &mut report.signalled,
            &mut report.failed,
        );
    }

    // 3. Grace.
    wait_until(Instant::now() + job.grace, POLL, || {
        targets.iter().all(|k| !platform::alive(*k))
    });

    // 4. SIGKILL to the survivors and their current descendants.
    let survivors: Vec<ProcKey> = targets
        .iter()
        .copied()
        .filter(|k| platform::alive(*k))
        .collect();
    let mut escalate = Vec::new();
    if !survivors.is_empty() {
        let Some(table) = snapshot() else {
            report
                .skipped
                .extend(survivors.iter().map(|k| (*k, GuardReason::Unverified)));
            report.survivors_after = survivors;
            return report;
        };
        let Some(guards) = Guards::new(&table, own) else {
            report
                .skipped
                .extend(survivors.iter().map(|k| (*k, GuardReason::Unverified)));
            report.survivors_after = survivors;
            return report;
        };
        escalate = guards.escalation(&survivors, job.root, &mut report.skipped);
    }
    for &key in escalate.iter().rev() {
        send(
            key,
            libc::SIGKILL,
            &mut report.escalated,
            &mut report.failed,
        );
    }

    // 5. Who survived.
    let mut touched: Vec<ProcKey> = targets;
    let mut seen: HashSet<ProcKey> = touched.iter().copied().collect();
    touched.extend(escalate.into_iter().filter(|k| seen.insert(*k)));
    wait_until(Instant::now() + SETTLE, Duration::from_millis(20), || {
        touched.iter().all(|k| !platform::alive(*k))
    });
    report.survivors_after = touched
        .into_iter()
        .filter(|k| platform::alive(*k))
        .collect();
    report
}

fn snapshot() -> Option<ProcessTable> {
    ProcessTable::snapshot(Vec::<String>::new()).ok()
}

/// Sends `sig` to `key` through the identity re-check, recording a sent signal in `sent` and a
/// refused one in `failed`.
fn send(
    key: ProcKey,
    sig: libc::c_int,
    sent: &mut Vec<ProcKey>,
    failed: &mut Vec<(ProcKey, String)>,
) {
    match platform::signal(key, sig) {
        Ok(true) => sent.push(key),
        Ok(false) => {}
        Err(err) => failed.push((key, err.to_string())),
    }
}

/// Polls `done` every `every` until it holds or `deadline` passes.
fn wait_until(deadline: Instant, every: Duration, mut done: impl FnMut() -> bool) {
    while !done() {
        let now = Instant::now();
        if now >= deadline {
            return;
        }
        std::thread::sleep(every.min(deadline - now));
    }
}

/// The hard guards on one fresh snapshot.
struct Guards<'a> {
    table: &'a ProcessTable,
    own: Own,
    /// The daemon and its ancestors.
    daemon: HashSet<ProcKey>,
}

impl<'a> Guards<'a> {
    /// `None` when the daemon itself is not in the snapshot: its ancestors are then unknown.
    fn new(table: &'a ProcessTable, own: Own) -> Option<Self> {
        let me = table.by_pid(own.pid)?;
        let daemon = std::iter::once(me)
            .chain(table.ancestors_of(me))
            .map(Process::key)
            .collect();
        Some(Self { table, own, daemon })
    }

    /// Why `key`, a member of the kill rooted at `root`, may not be signalled: a guard of its
    /// own, or a guarded process between it and the root.
    fn check(&self, key: ProcKey, root: ProcKey) -> Option<GuardReason> {
        let Some(process) = self.table.get(key) else {
            return Some(GuardReason::Gone);
        };
        if let Some(reason) = self.reason(process) {
            return Some(reason);
        }
        if key == root {
            return None;
        }
        // A member reparented to launchd has no path to the root; the walk ends at launchd.
        self.table
            .ancestors_of(process)
            .take_while(|a| a.key() != root && a.key().pid > 1)
            .find(|a| self.reason(a).is_some())
            .map(|a| GuardReason::Below { pid: a.key().pid })
    }

    /// The guard of the process itself.
    fn reason(&self, process: &Process) -> Option<GuardReason> {
        let key = process.key();
        if key.pid <= 1 {
            Some(GuardReason::Init)
        } else if process.info.uid != self.own.uid {
            Some(GuardReason::OtherUser)
        } else if key.pid == self.own.pid || self.daemon.contains(&key) {
            Some(GuardReason::Daemon)
        } else if origin::is_agent(process) {
            Some(GuardReason::Agent)
        } else if process.info.session == Some(key.pid) && process.info.tty.is_some() {
            Some(GuardReason::TerminalLeader)
        } else {
            match process.cmdline() {
                None => Some(GuardReason::UnknownExe),
                Some(cmdline) => exe_guard(&cmdline.exe),
            }
        }
    }

    /// The survivors that pass the guards, each followed by its current descendants, stopping
    /// at a guarded one. What is left out is recorded in `skipped`.
    fn escalation(
        &self,
        survivors: &[ProcKey],
        root: ProcKey,
        skipped: &mut Vec<(ProcKey, GuardReason)>,
    ) -> Vec<ProcKey> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for &survivor in survivors {
            if !seen.insert(survivor) {
                continue;
            }
            let Some(process) = self.table.get(survivor) else {
                // Exited since the poll.
                continue;
            };
            if let Some(reason) = self.check(survivor, root) {
                skipped.push((survivor, reason));
                continue;
            }
            out.push(survivor);
            let mut stack: Vec<&Process> = self.table.children_of(process).collect();
            while let Some(child) = stack.pop() {
                let key = child.key();
                if !seen.insert(key) {
                    continue;
                }
                if let Some(reason) = self.reason(child) {
                    skipped.push((key, reason));
                    continue;
                }
                out.push(key);
                stack.extend(self.table.children_of(child));
            }
        }
        out
    }
}

/// The guard of an executable path: under a protected directory, or not resolvable.
fn exe_guard(exe: &str) -> Option<GuardReason> {
    let path = Path::new(exe);
    let plain = path.is_absolute()
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)));
    if !plain {
        return Some(GuardReason::UnknownExe);
    }
    if is_protected(path) {
        return Some(GuardReason::ProtectedExe);
    }
    // Through symlinks and firmlinks to the file itself.
    match std::fs::canonicalize(path) {
        Ok(real) if is_protected(&real) => Some(GuardReason::ProtectedExe),
        Ok(_) => None,
        Err(_) => Some(GuardReason::UnknownExe),
    }
}

/// Whether `path` lies under a protected directory. Compared case-insensitively: the default
/// macOS volume is, so `/applications/X.app` execs the same file.
fn is_protected(path: &Path) -> bool {
    PROTECTED_EXE_DIRS.iter().any(|dir| {
        let mut components = path.components();
        Path::new(dir).components().all(|want| {
            components.next().is_some_and(|got| {
                got.as_os_str()
                    .to_str()
                    .zip(want.as_os_str().to_str())
                    .is_some_and(|(got, want)| got.eq_ignore_ascii_case(want))
            })
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::table::SyntheticProcess;
    use crate::platform::{BaseInfo, Cmdline};
    use std::time::SystemTime;

    const UID: u32 = 501;
    const OWN: Own = Own { pid: 100, uid: UID };

    fn proc(pid: i32, ppid: i32, argv0: &str, exe: &str) -> SyntheticProcess {
        SyntheticProcess {
            info: BaseInfo {
                key: ProcKey {
                    pid,
                    start: u64::try_from(pid).unwrap(),
                },
                ppid,
                uid: UID,
                tty: None,
                session: Some(1),
                rss: None,
                usage: None,
            },
            cmdline: Some(Cmdline {
                exe: exe.to_owned(),
                argv: vec![argv0.to_owned()],
                env: None,
            }),
            cwd: None,
        }
    }

    fn key(pid: i32) -> ProcKey {
        ProcKey {
            pid,
            start: u64::try_from(pid).unwrap(),
        }
    }

    #[test]
    fn protected_dirs_match_by_component_and_case() {
        for path in [
            "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
            "/usr/libexec/trustd",
            "/Applications/Visual Studio Code.app/Contents/MacOS/Electron",
            "/applications/x.app/x",
            "/SYSTEM/x",
        ] {
            assert!(is_protected(Path::new(path)), "{path}");
        }
        for path in [
            "/Applications2/x",
            "/usr/libexecx/y",
            "/usr/bin/sleep",
            "/Users/x/Applications/y",
        ] {
            assert!(!is_protected(Path::new(path)), "{path}");
        }
    }

    #[test]
    fn an_unresolvable_or_relative_exe_protects() {
        assert_eq!(exe_guard("node"), Some(GuardReason::UnknownExe));
        assert_eq!(exe_guard("./node"), Some(GuardReason::UnknownExe));
        assert_eq!(
            exe_guard("/usr/bin/../libexec/trustd"),
            Some(GuardReason::UnknownExe)
        );
        assert_eq!(
            exe_guard("/nonexistent/leukocyte/bin"),
            Some(GuardReason::UnknownExe)
        );
        assert_eq!(
            exe_guard("/usr/libexec/nonexistent"),
            Some(GuardReason::ProtectedExe)
        );
        assert_eq!(exe_guard("/bin/sleep"), None);
    }

    #[test]
    fn a_symlink_into_a_protected_dir_protects() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("tool");
        std::os::unix::fs::symlink("/usr/libexec/PlistBuddy", &link).unwrap();
        assert_eq!(
            exe_guard(link.to_str().unwrap()),
            Some(GuardReason::ProtectedExe)
        );
    }

    /// Must protect: every hard guard, decided on the process itself, never on origin records.
    #[test]
    fn guards_classify_every_kind_of_protected_process() {
        let mut other = proc(30, 20, "node", "/bin/sleep");
        other.info.uid = 0;
        let mut leader = proc(31, 20, "zsh", "/bin/zsh");
        leader.info.session = Some(31);
        leader.info.tty = Some(7);
        let mut no_tty_leader = proc(32, 20, "sh", "/bin/sh");
        no_tty_leader.info.session = Some(32);
        let mut unreadable = proc(33, 20, "x", "/bin/sh");
        unreadable.cmdline = None;
        let table = ProcessTable::synthetic(
            SystemTime::now(),
            vec![
                proc(1, 0, "launchd", "/sbin/launchd"),
                proc(10, 1, "zsh", "/bin/zsh"),
                proc(OWN.pid, 10, "leukocyte", "/bin/sleep"),
                proc(20, 1, "sh", "/bin/sh"),
                other,
                leader,
                no_tty_leader,
                unreadable,
                proc(34, 20, "/opt/bin/claude", "/bin/sleep"),
                proc(35, 34, "node", "/bin/sleep"),
                proc(36, 20, "Electron", "/Applications/X.app/Contents/MacOS/X"),
                proc(37, 20, "trustd", "/usr/libexec/trustd"),
            ],
        );
        let guards = Guards::new(&table, OWN).unwrap();
        let root = key(20);
        let check = |pid| guards.check(key(pid), root);

        assert_eq!(check(20), None);
        assert_eq!(check(1), Some(GuardReason::Init));
        assert_eq!(check(OWN.pid), Some(GuardReason::Daemon));
        assert_eq!(check(10), Some(GuardReason::Daemon));
        assert_eq!(check(30), Some(GuardReason::OtherUser));
        assert_eq!(check(31), Some(GuardReason::TerminalLeader));
        assert_eq!(check(32), None);
        assert_eq!(check(33), Some(GuardReason::UnknownExe));
        assert_eq!(check(34), Some(GuardReason::Agent));
        assert_eq!(check(35), Some(GuardReason::Below { pid: 34 }));
        assert_eq!(check(36), Some(GuardReason::ProtectedExe));
        assert_eq!(check(37), Some(GuardReason::ProtectedExe));
        assert_eq!(
            guards.check(
                ProcKey {
                    pid: 20,
                    start: 999
                },
                root
            ),
            Some(GuardReason::Gone)
        );
    }

    /// Must protect: the classification on a real snapshot, for processes this test did not
    /// start and never signals.
    #[test]
    fn real_system_processes_are_guarded() {
        let table = snapshot().unwrap();
        let own = Own::current();
        let guards = Guards::new(&table, own).unwrap();
        for process in table.iter() {
            let exe = process.cmdline().map(|c| c.exe.as_str());
            let system = exe.is_some_and(|e| is_protected(Path::new(e)));
            if process.info.uid != own.uid {
                assert!(guards.reason(process).is_some(), "{:?}", process.key());
            }
            if system {
                assert!(guards.reason(process).is_some(), "{exe:?}");
            }
            if system && process.info.uid == own.uid && !origin::is_agent(process) {
                assert!(
                    matches!(
                        guards.reason(process),
                        Some(
                            GuardReason::ProtectedExe
                                | GuardReason::Daemon
                                | GuardReason::TerminalLeader
                        )
                    ),
                    "{exe:?}"
                );
            }
        }
        let launchd = table.by_pid(1).unwrap();
        assert_eq!(guards.reason(launchd), Some(GuardReason::Init));
    }
}
