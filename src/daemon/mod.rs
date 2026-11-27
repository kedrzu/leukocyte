//! The daemon: the scan loop, reloading of the config and rules, the unix socket, the action log
//! and notifications.
//!
//! One thread owns every rules file (their Luau states never leave it), the fact store, the
//! engine and the kill executor, and runs a scan every [`SCAN_INTERVAL`]. Between scans it
//! reloads on file-system events and answers the socket's requests. The socket thread answers
//! `status` from a copy published after every scan, so a slow scan never stalls it.

#![deny(unsafe_code)]

pub mod config;
pub mod ipc;
mod log;
mod redact;
mod watch;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use crate::engine::{
    Action, ActionKind, CandidateState, Engine, Explanation, Mode, NoVerdictWhy, Own, RuleRef,
    ScanInput, Scope, Source,
};
use crate::facts::table::ProcessTable;
use crate::facts::{FactStore, ProcKey, RepoId, Repos};
use crate::kill::{Executor, KillJob, KillReport};
use crate::platform;
use crate::rules::{Human, RuleSet};

pub use config::{Config, ConfigMode, Paths, SCAN_INTERVAL};
use ipc::{
    CheckEvalError, CheckReply, Command, EvalErrorStatus, ExplanationReply, FuseStatus,
    InFlightStatus, RepoStatus, Request, Response, ScanStatus, SourceStatus, StatusReply,
};
use log::{ActionLog, Event, Failed, KillReportFields, Skipped, rfc3339};
use redact::Redactor;
use watch::{Fingerprint, Refresh, RulesFile, Watches};

/// Runs the daemon until the process is killed: the paths and scan interval from the
/// environment, the socket, the file-system watch, and the scan loop on the calling thread.
/// Returns only when it cannot start.
pub fn run_daemon() -> io::Result<()> {
    let paths = Paths::from_env()?;
    let interval = config::scan_interval(paths.isolated, std::env::var_os(config::INTERVAL_ENV));
    let (wake_tx, wake_rx) = mpsc::channel::<Wake>();

    let fs_tx = wake_tx.clone();
    let watches = Watches::new(move |changed| {
        if watch::is_relevant(&changed) {
            // The loop outlives the watcher; a send fails only during shutdown.
            let _ = fs_tx.send(Wake::Changed);
        }
    })
    .unwrap_or_else(|e| {
        eprintln!("leukocyte: no file-system watch ({e}); changes are found every scan");
        Watches::none()
    });
    // A test or end-to-end run (LEUKOCYTE_HOME) does not show notifications.
    let notifier = if paths.isolated {
        Notifier::Silent
    } else {
        Notifier::System
    };
    let mut daemon = Daemon::new(paths.clone(), notifier, watches)?;

    let listener = ipc::bind(&paths.socket())?;
    let status = daemon.status_handle();
    let cmd_tx = wake_tx.clone();
    std::thread::Builder::new()
        .name("socket".to_owned())
        .spawn(move || {
            ipc::serve(&listener, &status, &|cmd| {
                cmd_tx.send(Wake::Command(cmd)).is_ok()
            });
        })?;
    eprintln!(
        "leukocyte: daemon {} started, pid {}, scanning every {}ms",
        env!("CARGO_PKG_VERSION"),
        platform::current_pid(),
        interval.as_millis()
    );

    loop {
        let started = Instant::now();
        daemon.tick();
        let next = started + interval;
        while let Some(left) = next.checked_duration_since(Instant::now()) {
            match wake_rx.recv_timeout(left) {
                Ok(Wake::Changed) => daemon.reload(),
                Ok(Wake::Command(cmd)) => {
                    // The socket thread gave up waiting; nobody reads the answer.
                    let _ = cmd.reply.send(daemon.handle(cmd.request));
                }
                Err(RecvTimeoutError::Timeout) => break,
                // `wake_tx` lives in this frame, so the channel cannot disconnect.
                Err(RecvTimeoutError::Disconnected) => std::thread::sleep(left),
            }
        }
    }
}

/// What wakes the scan loop between scans.
enum Wake {
    /// A rules file or the config may have changed.
    Changed,
    Command(Command),
}

/// Where notifications go.
#[derive(Debug)]
pub(crate) enum Notifier {
    /// The system's notifications, through `osascript`.
    System,
    /// Only the daemon's stderr.
    Silent,
    #[cfg(test)]
    Record(Vec<(String, String)>),
}

impl Notifier {
    fn send(&mut self, title: &str, body: &str) {
        eprintln!("{title}: {body}");
        match self {
            Self::System => {
                if let Err(e) = platform::notify(title, body) {
                    eprintln!("leukocyte: notification failed: {e}");
                }
            }
            Self::Silent => {}
            #[cfg(test)]
            Self::Record(sent) => sent.push((title.to_owned(), body.to_owned())),
        }
    }
}

/// A repo from `config.toml`.
struct RepoSource {
    /// As written in the config.
    path: PathBuf,
    /// The repo and its rules file; an error when the path could not be registered.
    registered: Result<(Scope, RulesFile), String>,
}

/// A kill handed to the executor and not reported yet.
struct InFlight {
    rule: RuleRef,
    members: Vec<ProcKey>,
}

/// The daemon's state, owned by the scan thread.
pub(crate) struct Daemon {
    paths: Paths,
    redactor: Redactor,
    log: ActionLog,
    notifier: Notifier,
    watches: Watches,

    config: Config,
    config_seen: Option<Fingerprint>,
    config_error: Option<String>,
    registry: Repos,
    repos: Vec<RepoSource>,
    personal_scope: Scope,
    personal: RulesFile,

    store: FactStore,
    engine: Engine,
    executor: Executor,
    /// The last scan's snapshot, which `check` explains.
    table: Option<ProcessTable>,
    keep: HashSet<ProcKey>,
    /// Kills in flight, by root.
    in_flight: HashMap<ProcKey, InFlight>,
    /// Failing evaluations by (rules file, rule, message), with when each was first seen.
    eval_errors: BTreeMap<(String, String, String), SystemTime>,
    last_scan: Option<ScanStatus>,
    last_fuse: Option<FuseStatus>,
    status: Arc<Mutex<StatusReply>>,
}

impl Daemon {
    /// Creates the directories (0700), the default config when there is none, opens the action
    /// log (0600) and loads the config and every rules file.
    pub fn new(paths: Paths, notifier: Notifier, watches: Watches) -> io::Result<Self> {
        paths.create_dirs()?;
        Config::create_default(&paths.config_file())?;
        let log = ActionLog::open(&paths.action_log())?;
        let redactor = Redactor::new().map_err(io::Error::other)?;
        let own = Own::current();
        let mut daemon = Self {
            personal: RulesFile::new(paths.personal_rules()),
            paths,
            redactor,
            log,
            notifier,
            watches,
            config: Config::default(),
            config_seen: None,
            config_error: None,
            registry: Repos::default(),
            repos: Vec::new(),
            personal_scope: Scope::Personal,
            store: FactStore::new(Repos::default()),
            engine: Engine::new(own),
            executor: Executor::new(own),
            table: None,
            keep: HashSet::new(),
            in_flight: HashMap::new(),
            eval_errors: BTreeMap::new(),
            last_scan: None,
            last_fuse: None,
            status: Arc::default(),
        };
        daemon.reload();
        Ok(daemon)
    }

    /// The status the socket serves, updated after every scan and reload.
    pub fn status_handle(&self) -> Arc<Mutex<StatusReply>> {
        Arc::clone(&self.status)
    }

    /// Re-reads the config and every rules file, and applies what changed. A file that fails
    /// keeps the previous version in force; its error is logged and notified once, and shown
    /// by `status` until it is fixed.
    pub fn reload(&mut self) {
        self.reload_config();
        let refresh = self.personal.refresh();
        let name = self.personal.path().display().to_string();
        self.report_refresh(&name, refresh);
        for i in 0..self.repos.len() {
            let Some(RepoSource {
                registered: Ok((_, file)),
                ..
            }) = self.repos.get_mut(i)
            else {
                continue;
            };
            let refresh = file.refresh();
            let name = file.path().display().to_string();
            self.report_refresh(&name, refresh);
        }
        let mut dirs = vec![self.paths.config.clone()];
        dirs.extend(self.repos.iter().filter_map(|r| {
            let (_, file) = r.registered.as_ref().ok()?;
            file.path().parent().map(Path::to_path_buf)
        }));
        for (dir, e) in self.watches.sync(&dirs) {
            eprintln!("leukocyte: cannot watch {}: {e}", dir.display());
        }
        self.publish_status();
    }

    fn reload_config(&mut self) {
        let path = self.paths.config_file();
        let content = match watch::read_optional(&path) {
            Ok(content) => content,
            Err(e) => {
                self.config_failed(format!("{}: {e}", path.display()));
                return;
            }
        };
        let print = watch::fingerprint(content.as_deref());
        if self.config_seen == Some(print) {
            return;
        }
        self.config_seen = Some(print);
        let parsed = match content {
            Some(bytes) => String::from_utf8(bytes)
                .map_err(|e| e.to_string())
                .and_then(|text| Config::parse(&text)),
            // Deleted: the defaults, written back.
            None => {
                if let Err(e) = Config::create_default(&path) {
                    eprintln!("leukocyte: cannot recreate {}: {e}", path.display());
                }
                Ok(Config::default())
            }
        };
        match parsed {
            Ok(config) => {
                self.config_error = None;
                self.apply_config(config);
            }
            Err(e) => self.config_failed(format!("{}: {e}", path.display())),
        }
    }

    fn config_failed(&mut self, message: String) {
        if self.config_error.as_deref() == Some(&message) {
            return;
        }
        let mut event = Event::new("config_error");
        event.message = Some(message.clone());
        self.record(&event);
        self.notifier.send(
            "leukocyte: config not loaded, the previous one stays",
            &message,
        );
        self.config_error = Some(message);
    }

    /// Applies a config that parsed: the mode, and the repos registered again from scratch.
    /// A repo that stays keeps its loaded rules.
    fn apply_config(&mut self, config: Config) {
        let mut registry = Repos::default();
        let mut previous: HashMap<RepoId, RulesFile> = self
            .repos
            .drain(..)
            .filter_map(|r| match r.registered {
                Ok((Scope::Repo(id), file)) => Some((id, file)),
                _ => None,
            })
            .collect();
        let mut seen: HashMap<RepoId, PathBuf> = HashMap::new();
        for path in &config.repos {
            let registered = match registry.register(path) {
                Err(e) => Err(e.to_string()),
                Ok(id) => match seen.get(&id) {
                    Some(first) => Err(format!("the same repo as {}", first.display())),
                    None => {
                        seen.insert(id.clone(), path.clone());
                        let file = previous.remove(&id).unwrap_or_else(|| {
                            RulesFile::new(id.root().join(watch::RULES_DIR).join(watch::RULES_FILE))
                        });
                        Ok((Scope::Repo(id), file))
                    }
                },
            };
            self.repos.push(RepoSource {
                path: path.clone(),
                registered,
            });
        }
        self.store.set_repos(registry.clone());
        self.registry = registry;
        let mut event = Event::new("config_loaded");
        event.message = Some(format!(
            "mode {:?}, {} repos",
            config.mode,
            config.repos.len()
        ));
        self.record(&event);
        self.config = config;
    }

    fn report_refresh(&mut self, file: &str, refresh: Refresh) {
        match refresh {
            Refresh::Unchanged => {}
            Refresh::Loaded => {
                let mut event = Event::new("rules_loaded");
                event.source = Some(file.to_owned());
                self.record(&event);
            }
            Refresh::Removed => {
                let mut event = Event::new("rules_removed");
                event.source = Some(file.to_owned());
                self.record(&event);
            }
            Refresh::Failed(error) => {
                let message = error.message;
                let mut event = Event::new("rules_error");
                event.source = Some(file.to_owned());
                event.message = Some(message.clone());
                self.record(&event);
                self.notifier.send(
                    "leukocyte: rules not loaded, the previous ones stay",
                    &format!("{file}: {message}"),
                );
            }
        }
    }

    /// One scan: reload what changed, snapshot, update the facts, judge, act and log.
    pub fn tick(&mut self) {
        self.reload();
        let started = Instant::now();
        // Nothing reads the previous snapshot during a scan; dropping it first keeps one table
        // alive at a time instead of two. A failed snapshot leaves none for `check`.
        self.table = None;
        let env: Vec<String> = self
            .sources()
            .iter()
            .flat_map(|s| s.rules.env().iter().cloned())
            .collect();
        let table = match ProcessTable::snapshot(env) {
            Ok(table) => table,
            Err(e) => {
                let message = format!("snapshot failed: {e}");
                if self.last_scan.as_ref().and_then(|s| s.error.as_deref()) != Some(&message) {
                    let mut event = Event::new("scan_error");
                    event.message = Some(message.clone());
                    self.record(&event);
                }
                self.last_scan = Some(ScanStatus {
                    at: rfc3339(SystemTime::now()),
                    duration_ms: millis(started.elapsed()),
                    processes: 0,
                    error: Some(message),
                });
                self.publish_status();
                return;
            }
        };
        self.store.update(&table);
        let reports: Vec<KillReport> = self.executor.completed().collect();
        for report in reports {
            self.record_kill_report(&report);
        }
        self.keep.retain(|k| table.get(*k).is_some());

        let in_flight = self.in_flight_keys();
        let output = {
            let sources = sources(&self.personal_scope, &self.personal, &self.repos);
            let input = ScanInput {
                view: self.store.view(&table),
                sources: &sources,
                mode: Mode::from(self.config.mode),
                keep: &self.keep,
                in_flight: &in_flight,
            };
            self.engine.scan(&input)
        };

        for action in &output.actions {
            self.act(action);
        }
        if let Some(fuse) = output.fuse {
            let mut event = Event::new("fuse");
            event.kills = Some(fuse.kills);
            event.message = Some(format!(
                "more than {} kills in one scan: none issued",
                crate::engine::FUSE_LIMIT
            ));
            self.record(&event);
            self.last_fuse = Some(FuseStatus {
                at: event.ts.clone(),
                kills: fuse.kills,
            });
            if fuse.new_episode {
                self.notifier.send(
                    "leukocyte: fuse tripped",
                    &format!("{} kills in one scan; none were issued", fuse.kills),
                );
            }
        }
        self.track_eval_errors(&output.eval_errors);

        self.last_scan = Some(ScanStatus {
            at: rfc3339(table.taken_at()),
            duration_ms: millis(started.elapsed()),
            processes: table.iter().count(),
            error: None,
        });
        self.table = Some(table);
        self.publish_status();
        platform::release_free_memory();
    }

    /// The loaded rules files, personal first.
    fn sources(&self) -> Vec<Source<'_>> {
        sources(&self.personal_scope, &self.personal, &self.repos)
    }

    fn in_flight_keys(&self) -> HashSet<ProcKey> {
        self.in_flight
            .iter()
            .flat_map(|(root, f)| std::iter::once(*root).chain(f.members.iter().copied()))
            .collect()
    }

    /// Logs an action and hands a kill to the executor.
    fn act(&mut self, action: &Action) {
        let mut event = self.action_event("action", action);
        event.kind = Some(match action.kind {
            ActionKind::Kill { .. } => "kill",
            ActionKind::Report => "report",
            ActionKind::WouldKill => "would_kill",
            ActionKind::Blocked { .. } => "blocked",
        });
        if !action.subtree.is_empty() {
            event.subtree = Some(action.subtree.iter().map(|k| k.pid).collect());
        }
        self.record(&event);
        let Some(job) = KillJob::from_action(action) else {
            return;
        };
        let members = job.subtree.clone();
        match self.executor.submit(job) {
            Ok(()) => {
                self.in_flight.insert(
                    action.key,
                    InFlight {
                        rule: action.rule.clone(),
                        members,
                    },
                );
            }
            Err(e) => {
                let mut event = self.action_event("kill_failed", action);
                event.message = Some(format!("could not start the kill: {e}"));
                self.record(&event);
            }
        }
    }

    fn action_event(&self, name: &'static str, action: &Action) -> Event {
        let mut event = Event::new(name);
        event.rule = Some(action.rule.rule.clone());
        event.source = Some(action.rule.source.clone());
        event.pid = Some(action.facts.pid);
        event.start = Some(action.key.start);
        event.exe.clone_from(&action.facts.exe);
        event.argv = action
            .facts
            .argv_unredacted
            .as_deref()
            .map(|argv| self.redactor.argv(argv));
        event.reason = Some(self.redactor.text(&action.reason));
        event
    }

    fn record_kill_report(&mut self, report: &KillReport) {
        let flight = self.in_flight.remove(&report.root);
        let pids = |keys: &[ProcKey]| keys.iter().map(|k| k.pid).collect::<Vec<_>>();
        let mut event = Event::new("kill_report");
        event.pid = Some(report.root.pid);
        event.start = Some(report.root.start);
        if let Some(flight) = flight {
            event.rule = Some(flight.rule.rule);
            event.source = Some(flight.rule.source);
        }
        event.report = Some(KillReportFields {
            signalled: pids(&report.signalled),
            escalated: pids(&report.escalated),
            skipped: report
                .skipped
                .iter()
                .map(|(k, why)| Skipped {
                    pid: k.pid,
                    guard: why.to_string(),
                })
                .collect(),
            survivors_after: pids(&report.survivors_after),
            failed: report
                .failed
                .iter()
                .map(|(k, error)| Failed {
                    pid: k.pid,
                    error: error.clone(),
                })
                .collect(),
            aborted: report.aborted(),
        });
        self.record(&event);
    }

    /// Logs and notifies each failing evaluation once, until it stops failing.
    fn track_eval_errors(&mut self, errors: &[crate::engine::SourceEvalError]) {
        let mut current = BTreeMap::new();
        for e in errors {
            let message = self.redactor.text(&e.error.message);
            let id = (e.source.clone(), e.error.rule.clone(), message);
            if current.contains_key(&id) {
                continue;
            }
            let since = match self.eval_errors.get(&id) {
                Some(since) => *since,
                None => {
                    let mut event = Event::new("eval_error");
                    event.source = Some(id.0.clone());
                    event.rule = Some(id.1.clone());
                    event.pid = Some(e.key.pid);
                    event.message = Some(id.2.clone());
                    self.record(&event);
                    self.notifier.send(
                        "leukocyte: rule error",
                        &format!("\"{}\" ({}): {}", id.1, id.0, id.2),
                    );
                    SystemTime::now()
                }
            };
            current.insert(id, since);
        }
        self.eval_errors = current;
    }

    /// Answers a socket request.
    pub fn handle(&mut self, request: Request) -> Response {
        match request {
            Request::Status => Response::Status(Box::new(self.status_reply())),
            Request::Check { repo_path, rules } => self.check(repo_path.as_deref(), rules),
            Request::Keep { pid } => self.keep(pid),
            Request::Mode { mode } => self.set_mode(mode),
        }
    }

    fn keep(&mut self, pid: i32) -> Response {
        let key = self
            .table
            .as_ref()
            .and_then(|t| t.by_pid(pid))
            .map(|p| p.key())
            .filter(|k| platform::alive(*k))
            .or_else(|| platform::base_info(pid).map(|i| i.key));
        let Some(key) = key else {
            return Response::error(format!("no running process with pid {pid}"));
        };
        self.keep.insert(key);
        let mut event = Event::new("keep");
        event.pid = Some(key.pid);
        event.start = Some(key.start);
        self.record(&event);
        Response::Kept {
            pid: key.pid,
            start: key.start,
        }
    }

    fn set_mode(&mut self, mode: ConfigMode) -> Response {
        let mut config = self.config.clone();
        config.mode = mode;
        if let Err(e) = config.write(&self.paths.config_file()) {
            return Response::error(format!("cannot write the config: {e}"));
        }
        self.reload();
        Response::Mode {
            mode: self.config.mode,
        }
    }

    /// Explains the last scan through the registered rules, or through `rules` (a rules file's
    /// text) scoped to `repo_path`.
    fn check(&self, repo_path: Option<&str>, rules: Option<String>) -> Response {
        let Some(table) = &self.table else {
            return Response::error(
                "no scan to explain: none has completed yet, or the last one failed (see status)",
            );
        };
        let repo = match repo_path.map(|p| self.registered_repo(Path::new(p))) {
            None => None,
            Some(Ok(id)) => Some(id),
            Some(Err(message)) => return Response::error(message),
        };
        let adhoc = match rules {
            None => None,
            Some(text) => match RuleSet::load("check", text.as_bytes()) {
                Ok(set) => Some(set),
                Err(e) => return Response::error(format!("the rules do not load: {e}")),
            },
        };
        let adhoc_scope = repo.clone().map_or(Scope::Personal, Scope::Repo);
        let sources: Vec<Source<'_>> = match &adhoc {
            Some(set) => vec![Source {
                scope: &adhoc_scope,
                rules: set,
            }],
            None => self
                .sources()
                .into_iter()
                .filter(|s| repo.is_none() || s.scope == &adhoc_scope)
                .collect(),
        };
        let in_flight = self.in_flight_keys();
        let input = ScanInput {
            view: self.store.view(table),
            sources: &sources,
            mode: Mode::from(self.config.mode),
            keep: &self.keep,
            in_flight: &in_flight,
        };
        let (explanations, errors) = self.engine.explain(&input);
        Response::Check(CheckReply {
            explanations: explanations
                .into_iter()
                .map(|e| self.explanation_reply(table, e))
                .collect(),
            eval_errors: errors
                .into_iter()
                .map(|e| CheckEvalError {
                    source: e.source,
                    rule: e.error.rule,
                    pid: e.key.pid,
                    message: self.redactor.text(&e.error.message),
                })
                .collect(),
        })
    }

    /// The registered repo `path` belongs to (its root or any worktree).
    fn registered_repo(&self, path: &Path) -> Result<RepoId, String> {
        let mut probe = self.registry.clone();
        let id = probe
            .register(path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let registered = self
            .repos
            .iter()
            .any(|r| matches!(&r.registered, Ok((Scope::Repo(known), _)) if *known == id));
        if registered {
            Ok(id)
        } else {
            Err(format!(
                "{} is not a registered repo: add it to {}",
                path.display(),
                self.paths.config_file().display()
            ))
        }
    }

    fn explanation_reply(&self, table: &ProcessTable, e: Explanation) -> ExplanationReply {
        let cmdline = table.get(e.key).and_then(|p| p.cmdline());
        let (state, detail) = match e.state {
            CandidateState::KillReady => ("kill_ready", None),
            CandidateState::WouldKill => ("would_kill", None),
            CandidateState::Quarantined { remaining } => {
                ("quarantined", Some(format!("{} left", Human(remaining))))
            }
            CandidateState::Protected { by } => ("protected", Some(by.to_string())),
            CandidateState::ReportOnly => ("report_only", None),
            CandidateState::NoVerdict { why } => ("no_verdict", Some(why_text(&why))),
        };
        ExplanationReply {
            pid: e.key.pid,
            start: e.key.start,
            exe: cmdline.map(|c| c.exe.clone()),
            argv: cmdline.map(|c| self.redactor.argv(&c.argv).as_slice().to_vec()),
            state: state.to_owned(),
            detail: detail.map(|d| self.redactor.text(&d)),
            rule: e.rule.rule,
            source: e.rule.source,
            reason: e.reason.map(|r| self.redactor.text(&r)),
            matched: e.matched.iter().map(ToString::to_string).collect(),
        }
    }

    fn status_reply(&self) -> StatusReply {
        StatusReply {
            pid: platform::current_pid(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            mode: self.config.mode,
            config_error: self.config_error.clone(),
            repos: self
                .repos
                .iter()
                .map(|r| match &r.registered {
                    Ok((_, file)) => RepoStatus {
                        path: r.path.display().to_string(),
                        register_error: None,
                        rules: source_status(file),
                    },
                    Err(e) => RepoStatus {
                        path: r.path.display().to_string(),
                        register_error: Some(e.clone()),
                        rules: SourceStatus::default(),
                    },
                })
                .collect(),
            personal: source_status(&self.personal),
            last_scan: self.last_scan.clone(),
            in_flight: self
                .in_flight
                .iter()
                .map(|(root, f)| InFlightStatus {
                    pid: root.pid,
                    rule: f.rule.rule.clone(),
                    source: f.rule.source.clone(),
                    subtree: f.members.len(),
                })
                .collect(),
            fuse: self.last_fuse.clone(),
            eval_errors: self
                .eval_errors
                .iter()
                .map(|((source, rule, message), since)| EvalErrorStatus {
                    source: source.clone(),
                    rule: rule.clone(),
                    message: message.clone(),
                    since: rfc3339(*since),
                })
                .collect(),
        }
    }

    fn publish_status(&self) {
        let reply = self.status_reply();
        *self.status.lock().unwrap_or_else(PoisonError::into_inner) = reply;
    }

    /// Appends to the action log; a failed write goes to stderr and never stops the loop.
    fn record(&mut self, event: &Event) {
        if let Err(e) = self.log.write(event) {
            eprintln!("leukocyte: action log write failed: {e}");
        }
    }
}

/// The loaded rules files, personal first.
fn sources<'a>(
    personal_scope: &'a Scope,
    personal: &'a RulesFile,
    repos: &'a [RepoSource],
) -> Vec<Source<'a>> {
    let personal = personal.rules().map(|rules| Source {
        scope: personal_scope,
        rules,
    });
    let repos = repos.iter().filter_map(|r| {
        let (scope, file) = r.registered.as_ref().ok()?;
        Some(Source {
            scope,
            rules: file.rules()?,
        })
    });
    personal.into_iter().chain(repos).collect()
}

fn source_status(file: &RulesFile) -> SourceStatus {
    SourceStatus {
        file: file.path().display().to_string(),
        loaded: file.rules().is_some(),
        rule_count: file.rules().map_or(0, |r| r.rules().len()),
        error: file.error().map(|e| e.message.clone()),
    }
}

fn why_text(why: &NoVerdictWhy) -> String {
    match why {
        NoVerdictWhy::WhenNotMet(when) => format!("when = {when:?} does not hold"),
        NoVerdictWhy::IdleBelow { idle, need } => {
            format!("idle {} of the {} needed", Human(*idle), Human(*need))
        }
        NoVerdictWhy::EvalError(message) => format!("evaluation failed: {message}"),
        NoVerdictWhy::FactsUnknown => "facts unknown".to_owned(),
    }
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests;
