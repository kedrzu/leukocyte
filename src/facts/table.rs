//! The process table: one snapshot of the machine's processes, keyed by identity, with
//! parent/child links.
//!
//! The snapshot reads the cheap facts of every pid eagerly ([`BaseInfo`]); argv/env, cwd and
//! sockets are read on first use and memoised for the life of the snapshot.

use std::cell::OnceCell;
use std::collections::{BTreeSet, HashMap};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use crate::facts::ProcKey;
use crate::platform::{self, BaseInfo, Cmdline, Sockets};

/// Environment variables that identify the agent that started a process. They are read from
/// every process on top of the variables the rules ask for.
pub const IDENTITY_ENV: [&str; 3] = ["CLAUDE_PID", "PASEO_AGENT_ID", "CLAUDE_CODE_SESSION_ID"];

/// One process in a snapshot.
#[derive(Debug)]
pub struct Process {
    pub info: BaseInfo,
    parent: Option<ProcKey>,
    children: Vec<ProcKey>,
    env_allow: Arc<BTreeSet<String>>,
    cmdline: OnceCell<Option<Cmdline>>,
    cwd: OnceCell<Option<PathBuf>>,
    sockets: OnceCell<Option<Sockets>>,
}

impl Process {
    pub fn key(&self) -> ProcKey {
        self.info.key
    }

    /// The parent, when it is in the same snapshot and older than this process (a `ppid` reused
    /// by a newer process is not the parent).
    pub fn parent(&self) -> Option<ProcKey> {
        self.parent
    }

    pub fn children(&self) -> &[ProcKey] {
        &self.children
    }

    /// Executable, argv and the allowed environment; `None` when the OS refuses or the process
    /// is gone.
    pub fn cmdline(&self) -> Option<&Cmdline> {
        self.cmdline
            .get_or_init(|| platform::cmdline(self.info.key, &self.env_allow))
            .as_ref()
    }

    pub fn cwd(&self) -> Option<&Path> {
        self.cwd
            .get_or_init(|| platform::cwd(self.info.key))
            .as_deref()
    }

    pub fn sockets(&self) -> Option<&Sockets> {
        self.sockets
            .get_or_init(|| platform::sockets(self.info.key))
            .as_ref()
    }
}

/// A made-up process for [`ProcessTable::synthetic`].
#[cfg(test)]
pub(crate) struct SyntheticProcess {
    pub info: BaseInfo,
    pub cmdline: Option<Cmdline>,
    pub cwd: Option<PathBuf>,
}

/// A snapshot of every process on the machine.
#[derive(Debug)]
pub struct ProcessTable {
    procs: HashMap<ProcKey, Process>,
    by_pid: HashMap<i32, ProcKey>,
    taken_at: SystemTime,
}

impl ProcessTable {
    /// Reads every process. `rule_env` names the environment variables the rules read;
    /// [`IDENTITY_ENV`] is added to it, and every other variable is never read.
    pub fn snapshot<I, S>(rule_env: I) -> io::Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut env_allow: BTreeSet<String> = rule_env.into_iter().map(Into::into).collect();
        env_allow.extend(IDENTITY_ENV.iter().map(|name| (*name).to_owned()));
        let env_allow = Arc::new(env_allow);

        let taken_at = SystemTime::now();
        let infos: Vec<BaseInfo> = platform::list_pids()?
            .into_iter()
            .filter_map(platform::base_info)
            .collect();
        Ok(Self::link(infos, taken_at, |info| Process {
            parent: None,
            children: Vec::new(),
            env_allow: Arc::clone(&env_allow),
            cmdline: OnceCell::new(),
            cwd: OnceCell::new(),
            sockets: OnceCell::new(),
            info,
        }))
    }

    /// A table of made-up processes whose lazy facts are given up front, so nothing is read
    /// from the OS (the pids may belong to real processes).
    #[cfg(test)]
    pub(crate) fn synthetic(taken_at: SystemTime, procs: Vec<SyntheticProcess>) -> Self {
        let mut lazy: HashMap<ProcKey, SyntheticProcess> =
            procs.into_iter().map(|p| (p.info.key, p)).collect();
        let infos = lazy.values().map(|p| p.info.clone()).collect();
        Self::link(infos, taken_at, |info| {
            let given = lazy.remove(&info.key);
            let (cmdline, cwd) = given.map_or((None, None), |p| (p.cmdline, p.cwd));
            Process {
                parent: None,
                children: Vec::new(),
                env_allow: Arc::default(),
                cmdline: OnceCell::from(cmdline),
                cwd: OnceCell::from(cwd),
                sockets: OnceCell::from(None),
                info,
            }
        })
    }

    /// Builds the table from the processes' base facts, linking each to its parent and
    /// children.
    fn link(
        infos: Vec<BaseInfo>,
        taken_at: SystemTime,
        mut make: impl FnMut(BaseInfo) -> Process,
    ) -> Self {
        let by_pid: HashMap<i32, ProcKey> = infos.iter().map(|i| (i.key.pid, i.key)).collect();
        let parent_of = |info: &BaseInfo| {
            by_pid
                .get(&info.ppid)
                .copied()
                .filter(|parent| parent.pid != info.key.pid && parent.start <= info.key.start)
        };

        let mut children: HashMap<ProcKey, Vec<ProcKey>> = HashMap::new();
        for info in &infos {
            if let Some(parent) = parent_of(info) {
                children.entry(parent).or_default().push(info.key);
            }
        }

        let procs = infos
            .into_iter()
            .map(|info| {
                let mut kids = children.remove(&info.key).unwrap_or_default();
                kids.sort_unstable();
                let parent = parent_of(&info);
                let mut process = make(info);
                process.parent = parent;
                process.children = kids;
                (process.info.key, process)
            })
            .collect();

        Self {
            procs,
            by_pid,
            taken_at,
        }
    }

    pub fn get(&self, key: ProcKey) -> Option<&Process> {
        self.procs.get(&key)
    }

    pub fn by_pid(&self, pid: i32) -> Option<&Process> {
        self.by_pid.get(&pid).and_then(|key| self.procs.get(key))
    }

    pub fn iter(&self) -> impl Iterator<Item = &Process> {
        self.procs.values()
    }

    pub fn parent_of(&self, process: &Process) -> Option<&Process> {
        process.parent.and_then(|key| self.procs.get(&key))
    }

    /// The parent, its parent and so on, nearest first. Bounded by the table's size, so equal
    /// start times cannot make it loop.
    pub fn ancestors_of<'a>(&'a self, process: &'a Process) -> impl Iterator<Item = &'a Process> {
        std::iter::successors(self.parent_of(process), |p| self.parent_of(p)).take(self.procs.len())
    }

    pub fn children_of<'a>(&'a self, process: &'a Process) -> impl Iterator<Item = &'a Process> {
        process
            .children
            .iter()
            .filter_map(|key| self.procs.get(key))
    }

    /// When the snapshot started.
    pub fn taken_at(&self) -> SystemTime {
        self.taken_at
    }
}
