//! Origin: the agent or terminal that started a process, recorded when the process is first seen
//! and kept after it is reparented to launchd.

use std::path::Path;

use crate::facts::ProcKey;
use crate::facts::table::{Process, ProcessTable};

/// argv0 basenames of agent processes.
pub const AGENTS: [&str; 5] = ["claude", "codex", "cursor-agent", "aider", "opencode"];

/// The pid of the Claude Code process a process descends from (one of
/// [`IDENTITY_ENV`](crate::facts::table::IDENTITY_ENV)).
const CLAUDE_PID: &str = "CLAUDE_PID";
/// The Paseo agent a process descends from; every process of that agent carries the same value.
const PASEO_AGENT_ID: &str = "PASEO_AGENT_ID";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginKind {
    Agent,
    Terminal,
}

/// Who started a process. Holds the origin's identity only: the identity environment it may
/// have been derived from is never stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OriginRecord {
    pub(crate) origin: ProcKey,
    pub(crate) kind: OriginKind,
}

/// The origin of `process`, seen for the first time.
///
/// `parent_record` gives the origin recorded for an already tracked process. Processes are
/// first seen in start order, so a parent is tracked before its children.
pub(crate) fn first_sight(
    table: &ProcessTable,
    process: &Process,
    parent_record: impl Fn(ProcKey) -> Option<OriginRecord>,
) -> Option<OriginRecord> {
    let parent = table.parent_of(process).filter(|_| process.info.ppid != 1);
    let Some(parent) = parent else {
        return from_identity_env(table, process);
    };
    if is_agent(parent) {
        return Some(agent(parent));
    }
    // The parent's record already reflects its whole chain, including the part lost if an
    // ancestor exited since.
    parent_record(parent.key()).or_else(|| from_chain(table, process))
}

/// The whole live chain: the nearest agent ancestor; without one, the topmost of the process
/// and its ancestors that has a controlling terminal. Topmost, not nearest: nx gives each task
/// its own pty below the terminal's shell.
fn from_chain(table: &ProcessTable, process: &Process) -> Option<OriginRecord> {
    if let Some(found) = table.ancestors_of(process).find(|a| is_agent(a)) {
        return Some(agent(found));
    }
    std::iter::once(process)
        .chain(table.ancestors_of(process))
        .filter(|p| p.info.tty.is_some())
        .last()
        .map(terminal)
}

/// For a process whose parent chain is already broken: the agent named by its identity
/// environment, accepted only when that agent started before the process (a pid can be
/// reused).
fn from_identity_env(table: &ProcessTable, process: &Process) -> Option<OriginRecord> {
    let env = process.cmdline()?.env.as_ref()?;
    let started_before = |p: &&Process| p.key().start < process.key().start;

    let by_pid = env
        .get(CLAUDE_PID)
        .and_then(|pid| pid.parse::<i32>().ok())
        .and_then(|pid| table.by_pid(pid))
        .filter(started_before);
    if let Some(found) = by_pid {
        return Some(agent(found));
    }

    let id = env.get(PASEO_AGENT_ID)?;
    table
        .iter()
        .filter(started_before)
        .filter(|p| p.info.uid == process.info.uid && is_agent(p))
        .filter(|p| {
            p.cmdline()
                .and_then(|c| c.env.as_ref())
                .and_then(|env| env.get(PASEO_AGENT_ID))
                == Some(id)
        })
        // The newest one: a sub-agent inherits its parent agent's id.
        .max_by_key(|p| p.key().start)
        .map(agent)
}

/// Whether argv0 names an agent; an unreadable argv is not an agent.
pub(crate) fn is_agent(process: &Process) -> bool {
    process
        .cmdline()
        .and_then(|c| c.argv.first())
        .and_then(|argv0| Path::new(argv0).file_name())
        .and_then(|name| name.to_str())
        .is_some_and(|name| AGENTS.contains(&name))
}

fn agent(process: &Process) -> OriginRecord {
    OriginRecord {
        origin: process.key(),
        kind: OriginKind::Agent,
    }
}

fn terminal(process: &Process) -> OriginRecord {
    OriginRecord {
        origin: process.key(),
        kind: OriginKind::Terminal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::table::IDENTITY_ENV;

    #[test]
    fn the_identity_variables_are_read_by_the_table() {
        assert!(IDENTITY_ENV.contains(&CLAUDE_PID));
        assert!(IDENTITY_ENV.contains(&PASEO_AGENT_ID));
    }
}
