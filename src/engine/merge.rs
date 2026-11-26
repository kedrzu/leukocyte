//! Merging the verdicts of one process, and folding kills into process trees.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;

use crate::engine::{
    Blocker, Candidate, CandidateState, Guard, Judged, Mode, NoVerdictWhy, Own, RuleRef, ScanInput,
};
use crate::facts::table::Process;
use crate::facts::{FactView, ProcKey};
use crate::rules::{Signal, Verb};

/// The kill verdict that speaks for a process, with the rule's flags applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct KillPick {
    /// Neither `mode = observe` nor `enforce = false` downgrades it.
    pub enforced: bool,
    /// How much longer the verdict must hold; zero once out of quarantine.
    pub remaining: Duration,
    pub signal: Signal,
    pub grace: Duration,
}

/// The merged verdict of one process: protect > kill > report.
pub(super) enum Decision<'a> {
    /// A kill verdict, and the protect that outranks it on the process itself, if any.
    Kill {
        judged: &'a Judged<'a>,
        pick: KillPick,
        protect: Option<Blocker>,
    },
    /// A protect with no kill verdict to stop.
    Protected {
        by: Blocker,
    },
    Report(&'a Judged<'a>),
    None,
}

/// Merges the verdicts on `c`. Of several kill verdicts the one out of quarantine and enforced
/// speaks first, then the one closest to it. `held` is how long a rule's kill verdict has held.
pub(super) fn decide<'a>(
    c: &'a Candidate<'a>,
    keep: &HashSet<ProcKey>,
    mode: Mode,
    held: &impl Fn(&RuleRef, ProcKey) -> Duration,
) -> Decision<'a> {
    let protect = protect_of(c, keep);
    let kill = c
        .kills()
        .map(|judged| {
            let pick = KillPick {
                enforced: mode == Mode::Enforce && judged.rule.enforce,
                remaining: judged
                    .rule
                    .quarantine
                    .saturating_sub(held(&judged.at, c.key)),
                signal: judged.rule.signal,
                grace: judged.rule.grace,
            };
            (judged, pick)
        })
        .min_by_key(|(_, p)| (!p.remaining.is_zero(), !p.enforced, p.remaining));
    match (kill, protect) {
        (Some((judged, pick)), protect) => Decision::Kill {
            judged,
            pick,
            protect,
        },
        (None, Some(by)) => Decision::Protected { by },
        (None, None) => c
            .verdicts
            .iter()
            .find(|j| j.verdict.verb == Verb::Report)
            .map_or(Decision::None, Decision::Report),
    }
}

/// The protect on `c` itself: the owner's keep, or a rule's protect verdict.
fn protect_of(c: &Candidate<'_>, keep: &HashSet<ProcKey>) -> Option<Blocker> {
    let pid = c.key.pid;
    if keep.contains(&c.key) {
        return Some(Blocker::Keep { pid });
    }
    c.verdicts
        .iter()
        .find(|j| j.verdict.verb == Verb::Protect)
        .map(|j| Blocker::Rule {
            by: j.at.clone(),
            pid,
        })
}

/// Where one candidate stands after merging and folding.
pub(super) struct Outcome {
    pub key: ProcKey,
    pub rule: RuleRef,
    pub reason: Option<String>,
    pub matched: Vec<RuleRef>,
    pub state: State,
    /// For a kill that is not blocked: the processes it takes, `key` first.
    pub subtree: Vec<ProcKey>,
    /// A kill out of quarantine inside the subtree of another one, which issues it.
    pub folded_into: Option<ProcKey>,
}

pub(super) enum State {
    Kill(KillPick),
    /// A kill stopped by a protect on a member of its tree, a guard or an anchor. `ready`: it
    /// is out of quarantine.
    Blocked {
        by: Blocker,
        ready: bool,
    },
    /// A protect with no kill verdict.
    Protected(Blocker),
    Report,
    NoVerdict(NoVerdictWhy),
}

impl Outcome {
    pub(super) fn candidate_state(&self) -> CandidateState {
        match &self.state {
            State::Kill(pick) if !pick.remaining.is_zero() => CandidateState::Quarantined {
                remaining: pick.remaining,
            },
            State::Kill(pick) if pick.enforced => CandidateState::KillReady,
            State::Kill(_) => CandidateState::WouldKill,
            State::Blocked { by, .. } | State::Protected(by) => {
                CandidateState::Protected { by: by.clone() }
            }
            State::Report => CandidateState::ReportOnly,
            State::NoVerdict(why) => CandidateState::NoVerdict { why: why.clone() },
        }
    }
}

/// Turns the decisions into outcomes: builds each kill's tree, vetoes it on a protect of any
/// member, and folds a kill inside another kill's tree into that one.
pub(super) fn outcomes(
    input: &ScanInput<'_>,
    own: Own,
    candidates: &BTreeMap<ProcKey, Candidate<'_>>,
    decisions: &BTreeMap<ProcKey, Decision<'_>>,
) -> Vec<Outcome> {
    let guards = Guards::new(input, own);
    let member_protect = |key: ProcKey| match candidates.get(&key) {
        Some(c) => protect_of(c, input.keep),
        None => input
            .keep
            .contains(&key)
            .then_some(Blocker::Keep { pid: key.pid }),
    };

    let mut outcomes: Vec<Outcome> = candidates
        .values()
        .filter_map(|c| {
            // A candidate is matched by at least one rule.
            let first = c.matched.first()?;
            let mut outcome = Outcome {
                key: c.key,
                rule: first.clone(),
                reason: None,
                matched: c.matched.clone(),
                state: State::NoVerdict(NoVerdictWhy::FactsUnknown),
                subtree: Vec::new(),
                folded_into: None,
            };
            match decisions.get(&c.key).unwrap_or(&Decision::None) {
                Decision::Kill {
                    judged,
                    pick,
                    protect,
                } => {
                    outcome.rule = judged.at.clone();
                    outcome.reason = Some(judged.reason());
                    let root_blocker = protect.clone().or_else(|| guards.root_blocker(c.key));
                    let blocked = match root_blocker {
                        Some(by) => Some(by),
                        None => {
                            outcome.subtree = guards.subtree(c.key);
                            outcome.subtree.iter().find_map(|m| member_protect(*m))
                        }
                    };
                    outcome.state = match blocked {
                        Some(by) => {
                            outcome.subtree.clear();
                            State::Blocked {
                                by,
                                ready: pick.remaining.is_zero(),
                            }
                        }
                        None => State::Kill(*pick),
                    };
                }
                Decision::Protected { by } => {
                    if let Blocker::Rule { by: at, .. } = by {
                        outcome.rule = at.clone();
                    }
                    outcome.state = State::Protected(by.clone());
                }
                Decision::Report(judged) => {
                    outcome.rule = judged.at.clone();
                    outcome.reason = Some(judged.reason());
                    outcome.state = State::Report;
                }
                Decision::None => {
                    if let Some((at, why)) = &c.no_verdict {
                        outcome.rule = at.clone();
                        outcome.state = State::NoVerdict(why.clone());
                    }
                }
            }
            Some(outcome)
        })
        .collect();
    fold(&mut outcomes);
    outcomes
}

/// Marks each kill out of quarantine that lies in the tree of another such kill as folded into
/// the topmost of them. A real kill never folds into a "would kill".
fn fold(outcomes: &mut [Outcome]) {
    let ready = |o: &Outcome| match o.state {
        State::Kill(pick) if pick.remaining.is_zero() => Some(pick.enforced),
        _ => None,
    };
    let roots: HashMap<ProcKey, bool> = outcomes
        .iter()
        .filter_map(|o| Some((o.key, ready(o)?)))
        .collect();
    // Folded key -> (root, the root's tree size); the biggest tree is the topmost.
    let mut folded: HashMap<ProcKey, (ProcKey, usize)> = HashMap::new();
    for o in outcomes.iter() {
        let Some(enforced) = ready(o) else {
            continue;
        };
        for member in o.subtree.iter().skip(1) {
            let Some(&member_enforced) = roots.get(member) else {
                continue;
            };
            if member_enforced && !enforced {
                continue;
            }
            let entry = folded.entry(*member).or_insert((o.key, o.subtree.len()));
            if o.subtree.len() > entry.1 {
                *entry = (o.key, o.subtree.len());
            }
        }
    }
    for o in outcomes.iter_mut() {
        o.folded_into = folded.get(&o.key).map(|(root, _)| *root);
    }
}

/// The hard guards and anchors of one scan.
struct Guards<'a> {
    view: FactView<'a>,
    own: Own,
    /// The daemon and its ancestors.
    daemon: HashSet<ProcKey>,
    in_flight: &'a HashSet<ProcKey>,
}

impl<'a> Guards<'a> {
    fn new(input: &ScanInput<'a>, own: Own) -> Self {
        let table = input.view.table();
        let daemon = table
            .by_pid(own.pid)
            .map(|me| {
                std::iter::once(me)
                    .chain(table.ancestors_of(me))
                    .map(Process::key)
                    .collect()
            })
            .unwrap_or_default();
        Self {
            view: input.view,
            own,
            daemon,
            in_flight: input.in_flight,
        }
    }

    /// What stops `key` from being killed or being part of a killed tree.
    fn blocker(&self, process: &Process) -> Option<Blocker> {
        let key = process.key();
        let pid = key.pid;
        let guard = |guard| Some(Blocker::Guard { pid, guard });
        if pid <= 1 {
            guard(Guard::Init)
        } else if process.info.uid != self.own.uid {
            guard(Guard::OtherUser)
        } else if self.daemon.contains(&key) {
            guard(Guard::Daemon)
        } else if self.view.is_anchor(key) {
            Some(Blocker::Anchor { pid })
        } else {
            None
        }
    }

    fn root_blocker(&self, key: ProcKey) -> Option<Blocker> {
        let Some(process) = self.view.table().get(key) else {
            return Some(Blocker::Guard {
                pid: key.pid,
                guard: Guard::Gone,
            });
        };
        self.blocker(process)
    }

    /// `root` and its descendants, stopping at guarded processes, anchors and processes with a
    /// kill in flight: none of them, nor anything below them, is a member.
    fn subtree(&self, root: ProcKey) -> Vec<ProcKey> {
        let table = self.view.table();
        let Some(process) = table.get(root) else {
            return Vec::new();
        };
        let mut members = vec![root];
        let mut seen: HashSet<ProcKey> = HashSet::from([root]);
        let mut stack: Vec<&Process> = table.children_of(process).collect();
        stack.reverse();
        while let Some(child) = stack.pop() {
            let key = child.key();
            if !seen.insert(key) || self.in_flight.contains(&key) || self.blocker(child).is_some() {
                continue;
            }
            members.push(key);
            let mut children: Vec<&Process> = table.children_of(child).collect();
            children.reverse();
            stack.extend(children);
        }
        members
    }
}
