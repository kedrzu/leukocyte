//! The engine: turns the rules' verdicts on one scan into actions.
//!
//! Per scan it prefilters every rule over the processes in its scope, evaluates the hits, merges
//! the verdicts of each process (protect > kill > report), folds kills into process trees that
//! stop at origin anchors and are vetoed by a protect on any member, downgrades kills that may not
//! be enforced, holds every kill in quarantine and caps the kills of one scan with a fuse.
//!
//! The engine is not the last line: the kill executor re-checks the hard guards. It still never
//! emits a kill whose subtree holds pid 1, another user's process, an origin anchor, or the
//! daemon or one of its ancestors.

#![deny(unsafe_code)]

mod merge;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::time::{Duration, SystemTime};

use crate::facts::{FactView, ProcFacts, ProcKey, RepoId};
use crate::platform;
use crate::rules::{EvalError, Rule, RuleSet, Signal, Verdict, When, command_line};
use merge::{Decision, KillPick};

/// The most kills one scan may issue; a scan that would issue more issues none.
pub const FUSE_LIMIT: usize = 10;

/// Whether kills are carried out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Every kill is downgraded to a "would kill" report.
    Observe,
    /// Kills of rules with `enforce = true` are carried out.
    Enforce,
}

/// Which processes a rule source judges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// A registered repo's rules file: only processes attributed to that repo.
    Repo(RepoId),
    /// The user's personal rules file: every process.
    Personal,
}

/// A loaded rules file and the processes it judges.
#[derive(Debug, Clone, Copy)]
pub struct Source<'a> {
    pub scope: &'a Scope,
    pub rules: &'a RuleSet,
}

/// Everything one scan is judged on.
#[derive(Debug, Clone, Copy)]
pub struct ScanInput<'a> {
    /// The facts of the scan; its table is the scan's snapshot.
    pub view: FactView<'a>,
    pub sources: &'a [Source<'a>],
    pub mode: Mode,
    /// Processes the owner chose to keep: treated as protected.
    pub keep: &'a HashSet<ProcKey>,
    /// Processes with a kill in flight: neither judged nor counted, and left out of subtrees.
    pub in_flight: &'a HashSet<ProcKey>,
}

/// The daemon's own identity, for the hard guards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Own {
    pub pid: i32,
    pub uid: u32,
}

impl Own {
    pub fn current() -> Self {
        Self {
            pid: platform::current_pid(),
            uid: platform::current_uid(),
        }
    }
}

/// A rule, named by its rules file ([`RuleSet::name`]) and its own name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RuleRef {
    pub source: String,
    pub rule: String,
}

impl fmt::Display for RuleRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\" ({})", self.rule, self.source)
    }
}

/// What stops a kill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blocker {
    /// A rule's protect verdict on process `pid`.
    Rule { by: RuleRef, pid: i32 },
    /// The owner kept process `pid`.
    Keep { pid: i32 },
    /// A hard guard on process `pid`.
    Guard { pid: i32, guard: Guard },
    /// Process `pid` is an origin anchor (an agent, or a terminal session's tty holder).
    Anchor { pid: i32 },
    /// The scan would have issued more than [`FUSE_LIMIT`] kills.
    Fuse,
}

impl fmt::Display for Blocker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rule { by, pid } => write!(f, "protect {by} on pid {pid}"),
            Self::Keep { pid } => write!(f, "kept by owner on pid {pid}"),
            Self::Guard { pid, guard } => write!(f, "guard ({guard}) on pid {pid}"),
            Self::Anchor { pid } => write!(f, "origin anchor on pid {pid}"),
            Self::Fuse => write!(f, "fuse: more than {FUSE_LIMIT} kills in one scan"),
        }
    }
}

/// The hard guards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Guard {
    /// pid 0 or 1.
    Init,
    OtherUser,
    /// The daemon itself or one of its ancestors.
    Daemon,
    /// Not in the snapshot, so nothing about it can be checked.
    Gone,
}

impl fmt::Display for Guard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Init => "init",
            Self::OtherUser => "another user's process",
            Self::Daemon => "the daemon or its ancestor",
            Self::Gone => "not in the snapshot",
        })
    }
}

/// What the engine asks for, about one process.
#[derive(Debug, Clone)]
pub struct Action {
    pub kind: ActionKind,
    pub rule: RuleRef,
    pub key: ProcKey,
    /// For [`ActionKind::Kill`], the processes to terminate, `key` first; for
    /// [`ActionKind::WouldKill`], the ones that would be. Empty otherwise.
    pub subtree: Vec<ProcKey>,
    /// The daemon's reason, the `judge` reason after it, and for a blocked kill what blocked it.
    pub reason: String,
    pub facts: ActionFacts,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionKind {
    /// Send `signal` to the subtree, then `SIGKILL` after `grace`.
    Kill {
        signal: Signal,
        grace: Duration,
    },
    Report,
    /// A kill downgraded by `mode = observe` or `enforce = false`.
    WouldKill,
    /// A kill out of quarantine that a protect, a guard, an anchor or the fuse stopped.
    Blocked {
        by: Blocker,
    },
}

/// The facts of the acted-on process that matter for the record.
#[derive(Clone, PartialEq, Eq)]
pub struct ActionFacts {
    pub pid: i32,
    pub exe: Option<String>,
    /// The raw argv: it may hold secrets, so it is redacted before it is logged or shown, and
    /// `Debug` prints only its length.
    pub argv_unredacted: Option<Vec<String>>,
}

impl fmt::Debug for ActionFacts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActionFacts")
            .field("pid", &self.pid)
            .field("exe", &self.exe)
            .field(
                "argv_unredacted",
                &self
                    .argv_unredacted
                    .as_ref()
                    .map(|a| format!("<{} args>", a.len())),
            )
            .finish()
    }
}

/// The fuse tripped this scan: no kill was issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuseEvent {
    /// The kills the scan would have issued.
    pub kills: usize,
    /// The previous scan did not trip the fuse: a new episode starts.
    pub new_episode: bool,
}

/// A rule evaluation that failed, so it gave no verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceEvalError {
    /// The rules file ([`RuleSet::name`]).
    pub source: String,
    pub key: ProcKey,
    pub error: EvalError,
}

/// The result of one scan.
#[derive(Debug, Clone, Default)]
pub struct ScanOutput {
    pub actions: Vec<Action>,
    pub fuse: Option<FuseEvent>,
    pub eval_errors: Vec<SourceEvalError>,
}

/// Where a process matched by at least one rule stands, as `check` explains it.
#[derive(Debug, Clone)]
pub struct Explanation {
    pub key: ProcKey,
    pub state: CandidateState,
    /// The rule behind the state; for no verdict, the first rule that matched.
    pub rule: RuleRef,
    /// The verdict's reason, when there is a verdict.
    pub reason: Option<String>,
    /// Every rule whose matcher hit the process.
    pub matched: Vec<RuleRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateState {
    /// The next scan kills it (unless the fuse trips).
    KillReady,
    /// Out of quarantine, but `mode = observe` or `enforce = false`: reported as "would kill".
    WouldKill,
    /// A kill verdict that must hold `remaining` longer.
    Quarantined {
        remaining: Duration,
    },
    Protected {
        by: Blocker,
    },
    ReportOnly,
    NoVerdict {
        why: NoVerdictWhy,
    },
}

/// Why a rule that matched gave no verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoVerdictWhy {
    /// The structural condition does not hold.
    WhenNotMet(When),
    /// The subtree has not been idle long enough.
    IdleBelow { idle: Duration, need: Duration },
    /// The evaluation failed.
    EvalError(String),
    /// The daemon has no facts about the process yet, or its command line changed.
    FactsUnknown,
}

/// The quarantine clock of one kill verdict.
type QuarantineKey = (RuleRef, ProcKey);

/// The engine's memory across scans: the quarantine clocks and whether the fuse tripped last.
#[derive(Debug)]
pub struct Engine {
    own: Own,
    /// When each live kill verdict was first seen, held continuously since.
    kill_since: HashMap<QuarantineKey, SystemTime>,
    fuse_tripped: bool,
}

impl Engine {
    pub fn new(own: Own) -> Self {
        Self {
            own,
            kill_since: HashMap::new(),
            fuse_tripped: false,
        }
    }

    /// Judges one scan and returns what to do. Advances the quarantine clocks: a kill verdict
    /// seen for the first time starts its clock, one that lapsed or whose process vanished is
    /// forgotten. A process with a kill in flight keeps its clocks.
    pub fn scan(&mut self, input: &ScanInput<'_>) -> ScanOutput {
        let table = input.view.table();
        let now = table.taken_at();
        let run = self.run(input);

        let mut kill_since: HashMap<QuarantineKey, SystemTime> = run
            .kill_verdicts
            .into_iter()
            .map(|k| {
                let since = self.kill_since.get(&k).copied().unwrap_or(now);
                (k, since)
            })
            .collect();
        for (k, since) in self.kill_since.drain() {
            if input.in_flight.contains(&k.1) && table.get(k.1).is_some() {
                kill_since.entry(k).or_insert(since);
            }
        }
        self.kill_since = kill_since;

        let mut actions: Vec<Action> = run
            .outcomes
            .iter()
            .filter_map(|o| action(input.view, o))
            .collect();
        let kills = actions
            .iter()
            .filter(|a| matches!(a.kind, ActionKind::Kill { .. }))
            .count();
        let tripped = kills > FUSE_LIMIT;
        let fuse = tripped.then_some(FuseEvent {
            kills,
            new_episode: !self.fuse_tripped,
        });
        self.fuse_tripped = tripped;
        if tripped {
            for a in &mut actions {
                if matches!(a.kind, ActionKind::Kill { .. }) {
                    a.kind = ActionKind::Blocked { by: Blocker::Fuse };
                    a.reason = format!("{} · blocked by {}", a.reason, Blocker::Fuse);
                    a.subtree.clear();
                }
            }
        }
        ScanOutput {
            actions,
            fuse,
            eval_errors: run.eval_errors,
        }
    }

    /// Explains where every process some rule matched stands, through the same pipeline as
    /// [`scan`](Self::scan) but without touching the quarantine clocks or the fuse. The
    /// sources may include a rules file that is not registered yet, scoped to a repo.
    pub fn explain(&self, input: &ScanInput<'_>) -> (Vec<Explanation>, Vec<SourceEvalError>) {
        let run = self.run(input);
        let explanations = run
            .outcomes
            .into_iter()
            .map(|o| Explanation {
                key: o.key,
                state: o.candidate_state(),
                rule: o.rule,
                reason: o.reason,
                matched: o.matched,
            })
            .collect();
        (explanations, run.eval_errors)
    }

    /// The pipeline, read-only on the engine's state.
    fn run(&self, input: &ScanInput<'_>) -> Run {
        let now = input.view.table().taken_at();
        let (candidates, eval_errors) = judge(input, self.own);
        let kill_verdicts: Vec<QuarantineKey> = candidates
            .values()
            .flat_map(|c| c.kills().map(|j| (j.at.clone(), c.key)))
            .collect();
        let held = |at: &RuleRef, key: ProcKey| {
            self.kill_since
                .get(&(at.clone(), key))
                .and_then(|since| now.duration_since(*since).ok())
                .unwrap_or_default()
        };
        let decisions: BTreeMap<ProcKey, Decision<'_>> = candidates
            .values()
            .map(|c| (c.key, merge::decide(c, input.keep, input.mode, &held)))
            .collect();
        let outcomes = merge::outcomes(input, self.own, &candidates, &decisions);
        Run {
            outcomes,
            kill_verdicts,
            eval_errors,
        }
    }
}

struct Run {
    outcomes: Vec<merge::Outcome>,
    kill_verdicts: Vec<QuarantineKey>,
    eval_errors: Vec<SourceEvalError>,
}

/// A process some rule matched, with every verdict on it.
struct Candidate<'a> {
    key: ProcKey,
    matched: Vec<RuleRef>,
    verdicts: Vec<Judged<'a>>,
    /// Why the first matching rule without a verdict gave none.
    no_verdict: Option<(RuleRef, NoVerdictWhy)>,
}

impl Candidate<'_> {
    fn kills(&self) -> impl Iterator<Item = &Judged<'_>> {
        self.verdicts
            .iter()
            .filter(|j| j.verdict.verb == crate::rules::Verb::Kill)
    }
}

/// One rule's verdict on a process.
struct Judged<'a> {
    at: RuleRef,
    rule: &'a Rule,
    verdict: Verdict,
}

impl Judged<'_> {
    fn reason(&self) -> String {
        match &self.verdict.judge_reason {
            Some(judge) => format!("{} · {judge}", self.verdict.reason),
            None => self.verdict.reason.clone(),
        }
    }
}

/// Prefilters and evaluates every rule over the processes in its scope. A process with a kill
/// in flight, of another user, pid 0 or 1, or without facts is not judged. The command line
/// is built only for a process some source scopes.
fn judge<'a>(
    input: &ScanInput<'a>,
    own: Own,
) -> (BTreeMap<ProcKey, Candidate<'a>>, Vec<SourceEvalError>) {
    let view = input.view;
    let mut candidates = BTreeMap::new();
    let mut errors = Vec::new();
    for process in view.table().iter() {
        let key = process.key();
        if key.pid <= 1 || process.info.uid != own.uid || input.in_flight.contains(&key) {
            continue;
        }
        let Some(facts) = view.facts(key) else {
            continue;
        };
        let mut cmd: Option<Option<String>> = None;
        let mut candidate = Candidate {
            key,
            matched: Vec::new(),
            verdicts: Vec::new(),
            no_verdict: None,
        };
        for source in input.sources {
            let in_scope = match source.scope {
                Scope::Personal => true,
                Scope::Repo(repo) => facts.repo.as_ref() == Some(repo),
            };
            if !in_scope {
                continue;
            }
            let Some(cmd) = cmd.get_or_insert_with(|| process.cmdline().map(command_line)) else {
                break;
            };
            for (idx, rule) in source.rules.rules().iter().enumerate() {
                if !rule.matcher.is_match(cmd) {
                    continue;
                }
                let at = RuleRef {
                    source: source.rules.name().to_owned(),
                    rule: rule.name.clone(),
                };
                candidate.matched.push(at.clone());
                match source.rules.evaluate(idx, view, key) {
                    Ok(Some(verdict)) => candidate.verdicts.push(Judged { at, rule, verdict }),
                    Ok(None) => {
                        candidate
                            .no_verdict
                            .get_or_insert_with(|| (at, why_none(rule, &facts)));
                    }
                    Err(error) => {
                        let why = NoVerdictWhy::EvalError(error.message.clone());
                        candidate.no_verdict.get_or_insert((at, why));
                        errors.push(SourceEvalError {
                            source: source.rules.name().to_owned(),
                            key,
                            error,
                        });
                    }
                }
            }
        }
        if !candidate.matched.is_empty() {
            candidates.insert(key, candidate);
        }
    }
    (candidates, errors)
}

/// Why a rule that matched and evaluated cleanly gave no verdict.
fn why_none(rule: &Rule, facts: &ProcFacts) -> NoVerdictWhy {
    if !rule.when.holds(facts) {
        return NoVerdictWhy::WhenNotMet(rule.when);
    }
    match rule.idle {
        Some(need) if facts.idle < need => NoVerdictWhy::IdleBelow {
            idle: facts.idle,
            need,
        },
        _ => NoVerdictWhy::FactsUnknown,
    }
}

/// The action an outcome asks for this scan, if any.
fn action(view: FactView<'_>, o: &merge::Outcome) -> Option<Action> {
    let reason = o.reason.clone().unwrap_or_default();
    let (kind, subtree, reason) = match &o.state {
        merge::State::Kill(KillPick {
            enforced,
            remaining,
            signal,
            grace,
        }) if remaining.is_zero() && o.folded_into.is_none() => {
            let kind = if *enforced {
                ActionKind::Kill {
                    signal: *signal,
                    grace: *grace,
                }
            } else {
                ActionKind::WouldKill
            };
            (kind, o.subtree.clone(), reason)
        }
        merge::State::Blocked { by, ready: true } => (
            ActionKind::Blocked { by: by.clone() },
            Vec::new(),
            format!("{reason} · blocked by {by}"),
        ),
        merge::State::Report => (ActionKind::Report, Vec::new(), reason),
        _ => return None,
    };
    let cmdline = view.table().get(o.key).and_then(|p| p.cmdline());
    Some(Action {
        kind,
        rule: o.rule.clone(),
        key: o.key,
        subtree,
        reason,
        facts: ActionFacts {
            pid: o.key.pid,
            exe: cmdline.map(|c| c.exe.clone()),
            argv_unredacted: cmdline.map(|c| c.argv.clone()),
        },
    })
}
