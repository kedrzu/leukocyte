//! The fact store: what the daemon remembers about each process across scans, and the facts it
//! derives from that for the rules.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::facts::ProcKey;
use crate::facts::idle::{self, Activity};
use crate::facts::origin::{self, OriginKind, OriginRecord};
use crate::facts::repo::{RepoId, Repos, Resolver};
use crate::facts::table::{Process, ProcessTable};
use crate::platform::Usage;

/// Remembers every live process from scan to scan. Memory only: a restart starts empty, and
/// every process then present is first seen again.
#[derive(Debug)]
pub struct FactStore {
    repos: Repos,
    tracked: HashMap<ProcKey, Tracked>,
    last_scan: Option<SystemTime>,
}

/// What is remembered about one process.
#[derive(Debug)]
struct Tracked {
    usage: Option<Usage>,
    cpu: Option<f64>,
    /// When its subtree last did work.
    last_active: SystemTime,
    origin: Option<OriginRecord>,
    /// Resolved once, at first sight: a deleted worktree does not lose it.
    repo: Option<RepoId>,
}

impl FactStore {
    pub fn new(repos: Repos) -> Self {
        Self {
            repos,
            tracked: HashMap::new(),
            last_scan: None,
        }
    }

    /// Takes in a new snapshot: forgets processes that are gone, records origin and repo of
    /// the new ones, and updates idle and CPU of all.
    pub fn update(&mut self, table: &ProcessTable) {
        let now = table.taken_at();
        let interval = self.last_scan.and_then(|t| now.duration_since(t).ok());
        self.tracked.retain(|key, _| table.get(*key).is_some());

        let mut new: Vec<&Process> = table
            .iter()
            .filter(|p| !self.tracked.contains_key(&p.key()))
            .collect();
        // Parents before children, so a child inherits from a parent already recorded.
        new.sort_unstable_by_key(|p| (p.key().start, p.key().pid));
        let mut resolver = Resolver::default();
        for process in &new {
            let tracked = self.first_sight(table, process, &mut resolver, now);
            self.tracked.insert(process.key(), tracked);
        }
        let new: HashSet<ProcKey> = new.iter().map(|p| p.key()).collect();

        let own: HashMap<ProcKey, Activity> = table
            .iter()
            .filter_map(|p| {
                let usage = p.info.usage;
                let activity = if new.contains(&p.key()) {
                    Activity::full(usage)
                } else {
                    Activity::delta(self.tracked.get(&p.key())?.usage, usage)
                };
                Some((p.key(), activity))
            })
            .collect();
        let subtree = idle::subtree_activity(table, &own);

        for process in table.iter() {
            let Some(tracked) = self.tracked.get_mut(&process.key()) else {
                continue;
            };
            let usage = process.info.usage;
            if !new.contains(&process.key()) {
                let active = subtree
                    .get(&process.key())
                    .is_some_and(|a| a.is_active(interval));
                if active {
                    tracked.last_active = now;
                }
                tracked.cpu = idle::cpu_percent(tracked.usage, usage, interval);
            }
            tracked.usage = usage;
        }
        self.last_scan = Some(now);
    }

    fn first_sight(
        &self,
        table: &ProcessTable,
        process: &Process,
        resolver: &mut Resolver,
        now: SystemTime,
    ) -> Tracked {
        let origin = origin::first_sight(table, process, |key| {
            self.tracked.get(&key).and_then(|t| t.origin)
        });
        let inherited = || {
            let parent = process.parent().and_then(|key| self.tracked.get(&key));
            let from_origin = origin.and_then(|o| self.tracked.get(&o.origin));
            parent
                .and_then(|t| t.repo.clone())
                .or_else(|| from_origin.and_then(|t| t.repo.clone()))
        };
        let repo = process
            .cwd()
            .and_then(|cwd| resolver.resolve(&self.repos, cwd))
            .or_else(inherited);
        Tracked {
            usage: None,
            cpu: None,
            last_active: now,
            origin,
            repo,
        }
    }

    /// The facts of the processes in `table`, which must be the table last passed to
    /// [`update`](Self::update).
    pub fn view<'a>(&'a self, table: &'a ProcessTable) -> FactView<'a> {
        FactView { store: self, table }
    }
}

/// Read-only facts of one scan.
#[derive(Debug, Clone, Copy)]
pub struct FactView<'a> {
    store: &'a FactStore,
    table: &'a ProcessTable,
}

/// The facts of one process. Every fact the daemon cannot establish is `None`, never a default
/// that could enable a kill.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcFacts {
    /// Since the process's whole subtree last did work; zero when first seen.
    pub idle: Duration,
    /// The process's own CPU over the last scan, in percent of one core.
    pub cpu: Option<f64>,
    /// Reparented to launchd.
    pub orphan: bool,
    /// Whether the leader of its session is still running.
    pub session_alive: Option<bool>,
    pub origin: OriginFacts,
    pub repo: Option<RepoId>,
    pub age: Duration,
}

/// Who started the process. Both fields are `None` when no origin was recorded: the process
/// was first seen already orphaned without usable identity environment, or before a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OriginFacts {
    pub kind: Option<OriginKind>,
    /// Whether the origin process is still running.
    pub alive: Option<bool>,
}

impl FactView<'_> {
    pub fn facts(&self, key: ProcKey) -> Option<ProcFacts> {
        let process = self.table.get(key)?;
        let tracked = self.store.tracked.get(&key)?;
        let now = self.table.taken_at();
        let started = UNIX_EPOCH + Duration::from_micros(key.start);
        Some(ProcFacts {
            idle: now.duration_since(tracked.last_active).unwrap_or_default(),
            cpu: tracked.cpu,
            orphan: process.info.ppid == 1,
            session_alive: self.session_alive(process),
            origin: OriginFacts {
                kind: tracked.origin.map(|o| o.kind),
                alive: tracked.origin.map(|o| self.table.get(o.origin).is_some()),
            },
            repo: tracked.repo.clone(),
            // A process that started while the snapshot was being taken is zero seconds old.
            age: now.duration_since(started).unwrap_or_default(),
        })
    }

    /// How many live processes with the same executable and argv, in the same repo, started
    /// after this one. `None` when its argv or repo is unknown. Reads argv of the candidates,
    /// so it is computed only when asked.
    pub fn newer_twins(&self, key: ProcKey) -> Option<usize> {
        let process = self.table.get(key)?;
        let repo = self.store.tracked.get(&key)?.repo.as_ref()?;
        let cmdline = process.cmdline()?;
        let twins = self
            .store
            .tracked
            .iter()
            .filter(|(other, t)| other.start > key.start && t.repo.as_ref() == Some(repo))
            .filter_map(|(other, _)| self.table.get(*other)?.cmdline())
            .filter(|other| other.exe == cmdline.exe && other.argv == cmdline.argv)
            .count();
        Some(twins)
    }

    /// The session leader is the process whose pid is the session id. A pid reused by a
    /// process that started later, or that leads another session, is not it.
    fn session_alive(&self, process: &Process) -> Option<bool> {
        let sid = process.info.session?;
        let alive = self.table.by_pid(sid).is_some_and(|leader| {
            leader.key().start <= process.key().start && leader.info.session == Some(sid)
        });
        Some(alive)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::facts::table::SyntheticProcess;
    use crate::platform::{BaseInfo, Cmdline};

    const UID: u32 = 501;
    const SECRET_AGENT_ID: &str = "paseo-agent-secret-7f3a";
    const SECRET_SESSION: &str = "claude-session-secret-91bc";

    /// A made-up process; `start` is in seconds since the epoch.
    fn proc(pid: i32, start: u64, ppid: i32, argv0: &str) -> SyntheticProcess {
        SyntheticProcess {
            info: BaseInfo {
                key: key(pid, start),
                ppid,
                uid: UID,
                tty: None,
                session: None,
                rss: Some(0),
                usage: Some(usage(0, 0)),
            },
            cmdline: Some(Cmdline {
                exe: format!("/usr/bin/{argv0}"),
                argv: vec![argv0.to_owned()],
                env: Some(BTreeMap::new()),
            }),
            cwd: None,
        }
    }

    fn key(pid: i32, start: u64) -> ProcKey {
        ProcKey {
            pid,
            start: start * 1_000_000,
        }
    }

    fn usage(cpu_ms: u64, disk: u64) -> Usage {
        Usage {
            cpu: Duration::from_millis(cpu_ms),
            children_cpu: Duration::ZERO,
            disk_read: disk,
            disk_written: 0,
        }
    }

    fn launchd() -> SyntheticProcess {
        let mut p = proc(1, 1, 0, "launchd");
        p.info.uid = 0;
        p.info.usage = None;
        p.cmdline = None;
        p
    }

    trait With {
        fn tty(self, tty: u32) -> Self;
        fn env(self, name: &str, value: &str) -> Self;
        fn no_env(self) -> Self;
        fn cwd(self, dir: &Path) -> Self;
        fn cpu(self, cpu_ms: u64) -> Self;
        fn session(self, sid: i32) -> Self;
        fn argv(self, argv: &[&str]) -> Self;
    }

    impl With for SyntheticProcess {
        fn tty(mut self, tty: u32) -> Self {
            self.info.tty = Some(tty);
            self
        }
        fn env(mut self, name: &str, value: &str) -> Self {
            let env = self.cmdline.as_mut().unwrap().env.as_mut().unwrap();
            env.insert(name.to_owned(), value.to_owned());
            self
        }
        fn no_env(mut self) -> Self {
            self.cmdline.as_mut().unwrap().env = None;
            self
        }
        fn cwd(mut self, dir: &Path) -> Self {
            self.cwd = Some(dir.to_path_buf());
            self
        }
        fn cpu(mut self, cpu_ms: u64) -> Self {
            self.info.usage = Some(usage(cpu_ms, 0));
            self
        }
        fn session(mut self, sid: i32) -> Self {
            self.info.session = Some(sid);
            self
        }
        fn argv(mut self, argv: &[&str]) -> Self {
            let cmdline = self.cmdline.as_mut().unwrap();
            cmdline.argv = argv.iter().map(|a| (*a).to_owned()).collect();
            self
        }
    }

    /// A table taken `at` seconds after the epoch.
    fn table(at: u64, procs: Vec<SyntheticProcess>) -> ProcessTable {
        ProcessTable::synthetic(UNIX_EPOCH + Duration::from_secs(at), procs)
    }

    fn scan(store: &mut FactStore, at: u64, procs: Vec<SyntheticProcess>) -> ProcessTable {
        let table = table(at, procs);
        store.update(&table);
        table
    }

    fn facts(store: &FactStore, table: &ProcessTable, pid: i32) -> ProcFacts {
        let key = table.by_pid(pid).unwrap().key();
        store.view(table).facts(key).unwrap()
    }

    fn agent_origin(alive: bool) -> OriginFacts {
        OriginFacts {
            kind: Some(OriginKind::Agent),
            alive: Some(alive),
        }
    }

    const NO_ORIGIN: OriginFacts = OriginFacts {
        kind: None,
        alive: None,
    };

    /// A temp dir holding a git checkout (a bare `.git` directory is enough for attribution).
    fn repo_dir() -> (tempfile::TempDir, PathBuf, Repos, RepoId) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap().join("repo");
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        let mut repos = Repos::default();
        let id = repos.register(&root).unwrap();
        (tmp, root, repos, id)
    }

    #[test]
    fn origin_recorded_with_the_chain_intact_survives_reparenting() {
        let (_tmp, root, repos, id) = repo_dir();
        let mut store = FactStore::new(repos);
        let agent = || proc(10, 10, 1, "claude");
        let t = scan(
            &mut store,
            100,
            vec![
                launchd(),
                agent(),
                proc(11, 11, 10, "npx"),
                proc(12, 12, 11, "agent-browser").cwd(&root.join("src")),
            ],
        );
        assert_eq!(facts(&store, &t, 12).origin, agent_origin(true));

        // npx exits; the daemon is reparented to launchd.
        let reparented = || proc(12, 12, 1, "agent-browser").cwd(Path::new("/"));
        let t = scan(&mut store, 105, vec![launchd(), agent(), reparented()]);
        let f = facts(&store, &t, 12);
        assert!(f.orphan);
        assert_eq!(f.origin, agent_origin(true));
        assert_eq!(f.repo, Some(id.clone()));

        let t = scan(&mut store, 110, vec![launchd(), reparented()]);
        let f = facts(&store, &t, 12);
        assert_eq!(f.origin, agent_origin(false));
        assert_eq!(f.repo, Some(id));
    }

    #[test]
    fn a_child_of_a_reparented_process_inherits_its_origin() {
        let mut store = FactStore::new(Repos::default());
        let agent = || proc(10, 10, 1, "claude");
        scan(
            &mut store,
            100,
            vec![
                launchd(),
                agent(),
                proc(11, 11, 10, "sh"),
                proc(12, 12, 11, "nx"),
            ],
        );
        let t = scan(
            &mut store,
            105,
            vec![
                launchd(),
                agent(),
                proc(12, 12, 1, "nx"),
                proc(13, 104, 12, "node"),
            ],
        );
        assert_eq!(facts(&store, &t, 13).origin, agent_origin(true));
    }

    #[test]
    fn origin_is_unknown_without_a_record_never_dead() {
        let mut store = FactStore::new(Repos::default());
        let t = scan(
            &mut store,
            100,
            vec![
                launchd(),
                // First seen already orphaned, without identity env, with a withheld env.
                proc(20, 20, 1, "agent-browser"),
                proc(21, 21, 1, "sleep").no_env(),
                proc(22, 22, 1, "node").env(CLAUDE_PID_VAR, "not-a-pid"),
            ],
        );
        for pid in [20, 21, 22] {
            assert_eq!(facts(&store, &t, pid).origin, NO_ORIGIN, "pid {pid}");
        }
    }

    const CLAUDE_PID_VAR: &str = "CLAUDE_PID";
    const PASEO_VAR: &str = "PASEO_AGENT_ID";

    #[test]
    fn claude_pid_is_accepted_only_for_an_older_process() {
        let mut store = FactStore::new(Repos::default());
        let t = scan(
            &mut store,
            100,
            vec![
                launchd(),
                proc(30, 30, 1, "claude"),
                proc(31, 50, 1, "agent-browser").env(CLAUDE_PID_VAR, "30"),
                // pid 32 was reused by a process that started after the one naming it.
                proc(32, 60, 1, "claude"),
                proc(33, 40, 1, "agent-browser").env(CLAUDE_PID_VAR, "32"),
            ],
        );
        assert_eq!(facts(&store, &t, 31).origin, agent_origin(true));
        assert_eq!(facts(&store, &t, 33).origin, NO_ORIGIN);
    }

    #[test]
    fn paseo_agent_id_names_the_older_agent_carrying_it() {
        let mut store = FactStore::new(Repos::default());
        let t = scan(
            &mut store,
            100,
            vec![
                launchd(),
                proc(40, 40, 1, "/Users/u/.local/bin/claude").env(PASEO_VAR, SECRET_AGENT_ID),
                // Not an agent, though it carries the same id.
                proc(41, 41, 1, "node").env(PASEO_VAR, SECRET_AGENT_ID),
                proc(42, 50, 1, "agent-browser").env(PASEO_VAR, SECRET_AGENT_ID),
                proc(43, 50, 1, "agent-browser").env(PASEO_VAR, "another-agent"),
                // An agent carrying the id that started after the process is not its origin.
                proc(44, 60, 1, "codex").env(PASEO_VAR, "late"),
                proc(45, 55, 1, "agent-browser").env(PASEO_VAR, "late"),
            ],
        );
        let f = facts(&store, &t, 42);
        assert_eq!(f.origin, agent_origin(true));
        let record = store.tracked[&t.by_pid(42).unwrap().key()].origin.unwrap();
        assert_eq!(record.origin, key(40, 40));
        assert_eq!(facts(&store, &t, 43).origin, NO_ORIGIN);
        assert_eq!(facts(&store, &t, 45).origin, NO_ORIGIN);
    }

    /// Privacy: identity values are used to find the origin and then dropped; neither the store
    /// nor the facts handed to the rules carry them.
    #[test]
    fn identity_values_never_leave_the_store() {
        let mut store = FactStore::new(Repos::default());
        let t = scan(
            &mut store,
            100,
            vec![
                launchd(),
                proc(40, 40, 1, "claude")
                    .env(PASEO_VAR, SECRET_AGENT_ID)
                    .env("CLAUDE_CODE_SESSION_ID", SECRET_SESSION),
                proc(42, 50, 1, "agent-browser")
                    .env(PASEO_VAR, SECRET_AGENT_ID)
                    .env("CLAUDE_CODE_SESSION_ID", SECRET_SESSION),
            ],
        );
        let f = facts(&store, &t, 42);
        assert_eq!(f.origin, agent_origin(true));
        let view = store.view(&t);
        for dump in [
            format!("{store:?}"),
            format!("{f:?}"),
            format!("{:?}", view.facts(key(40, 40))),
        ] {
            assert!(!dump.contains(SECRET_AGENT_ID), "{dump}");
            assert!(!dump.contains(SECRET_SESSION), "{dump}");
        }
    }

    #[test]
    fn the_terminal_origin_is_the_topmost_tty_holder_not_the_nearest() {
        let mut store = FactStore::new(Repos::default());
        let t = scan(
            &mut store,
            100,
            vec![
                launchd(),
                proc(50, 50, 1, "Terminal"),
                proc(51, 51, 50, "zsh").tty(3),
                proc(52, 52, 51, "nx").tty(3),
                // nx gives each task its own pty.
                proc(53, 53, 52, "node").tty(5),
                proc(54, 54, 53, "vitest").tty(5),
            ],
        );
        let record = store.tracked[&key(54, 54)].origin.unwrap();
        assert_eq!(record.kind, OriginKind::Terminal);
        assert_eq!(record.origin, key(51, 51));
        assert_eq!(
            store.tracked[&key(51, 51)].origin,
            record_of(51, 51, OriginKind::Terminal)
        );
        // The app above the terminal has no origin.
        assert_eq!(facts(&store, &t, 50).origin, NO_ORIGIN);
    }

    fn record_of(pid: i32, start: u64, kind: OriginKind) -> Option<OriginRecord> {
        Some(OriginRecord {
            origin: key(pid, start),
            kind,
        })
    }

    #[test]
    fn an_agent_anywhere_in_the_chain_beats_a_terminal() {
        let mut store = FactStore::new(Repos::default());
        scan(
            &mut store,
            100,
            vec![
                launchd(),
                proc(60, 60, 1, "zsh").tty(3),
                proc(61, 61, 60, "claude").tty(3),
                proc(62, 62, 61, "bash").tty(3),
                proc(63, 63, 62, "bun").tty(3),
                proc(64, 64, 63, "codex").tty(3),
                proc(65, 65, 64, "node").tty(3),
            ],
        );
        let tracked = |pid, start| store.tracked[&key(pid, start)].origin;
        assert_eq!(tracked(61, 61), record_of(60, 60, OriginKind::Terminal));
        assert_eq!(tracked(63, 63), record_of(61, 61, OriginKind::Agent));
        // The nearest agent.
        assert_eq!(tracked(65, 65), record_of(64, 64, OriginKind::Agent));
    }

    #[test]
    fn idle_is_the_subtree_idle_and_resets_on_any_member_work() {
        let mut store = FactStore::new(Repos::default());
        let tree = |parent_ms, child_ms| {
            vec![
                launchd(),
                proc(70, 70, 1, "nx").cpu(parent_ms),
                proc(71, 71, 70, "node").cpu(child_ms),
                proc(72, 72, 1, "other").cpu(0),
            ]
        };
        let t = scan(&mut store, 100, tree(1000, 1000));
        // First sight: idle 0, no CPU reading yet.
        assert_eq!(facts(&store, &t, 70).idle, Duration::ZERO);
        assert_eq!(facts(&store, &t, 70).cpu, None);

        let t = scan(&mut store, 105, tree(1001, 1001));
        assert_eq!(facts(&store, &t, 70).idle, Duration::from_secs(5));
        assert_eq!(facts(&store, &t, 71).idle, Duration::from_secs(5));

        // Only the child works: the parent's subtree is active too, an unrelated tree is not.
        let t = scan(&mut store, 110, tree(1001, 3501));
        let parent = facts(&store, &t, 70);
        assert_eq!(parent.idle, Duration::ZERO);
        assert_eq!(parent.cpu, Some(0.0));
        let child = facts(&store, &t, 71);
        assert_eq!(child.idle, Duration::ZERO);
        assert!((child.cpu.unwrap() - 50.0).abs() < 1e-9);
        assert_eq!(facts(&store, &t, 72).idle, Duration::from_secs(10));

        // A child that appears between scans brings its whole CPU into the parent's subtree.
        let t = scan(&mut store, 115, tree(1001, 3501));
        assert_eq!(facts(&store, &t, 70).idle, Duration::from_secs(5));
        let mut procs = tree(1001, 3501);
        procs.push(proc(73, 118, 70, "esbuild").cpu(400));
        let t = scan(&mut store, 120, procs);
        assert_eq!(facts(&store, &t, 70).idle, Duration::ZERO);
        assert_eq!(facts(&store, &t, 73).idle, Duration::ZERO);
        assert_eq!(facts(&store, &t, 71).idle, Duration::from_secs(10));
    }

    #[test]
    fn a_reused_pid_is_seen_anew_and_records_of_gone_processes_are_dropped() {
        let mut store = FactStore::new(Repos::default());
        scan(&mut store, 100, vec![launchd(), proc(80, 80, 1, "x")]);
        let t = scan(&mut store, 105, vec![launchd(), proc(80, 80, 1, "x")]);
        assert_eq!(facts(&store, &t, 80).idle, Duration::from_secs(5));

        let t = scan(&mut store, 110, vec![launchd(), proc(80, 108, 1, "y")]);
        assert_eq!(store.tracked.len(), 2);
        assert!(!store.tracked.contains_key(&key(80, 80)));
        assert_eq!(facts(&store, &t, 80).idle, Duration::ZERO);
        assert_eq!(facts(&store, &t, 80).age, Duration::from_secs(2));
    }

    #[test]
    fn a_child_inherits_the_repo_when_its_own_cwd_does_not_resolve() {
        let (tmp, root, repos, id) = repo_dir();
        let outside = tmp.path().join("elsewhere");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::create_dir_all(outside.join("other/.git")).unwrap();
        let mut store = FactStore::new(repos);
        let t = scan(
            &mut store,
            100,
            vec![
                launchd(),
                proc(90, 90, 1, "claude").cwd(&root),
                proc(91, 91, 90, "node").cwd(&outside),
                proc(92, 92, 91, "chrome"),
                // An unregistered checkout is no attribution: it inherits.
                proc(93, 93, 90, "git").cwd(&outside.join("other")),
            ],
        );
        for pid in [90, 91, 92, 93] {
            assert_eq!(facts(&store, &t, pid).repo, Some(id.clone()), "pid {pid}");
        }
    }

    #[test]
    fn newer_twins_counts_later_identical_processes_in_the_same_repo() {
        let (tmp, root, repos, _) = repo_dir();
        let other = tmp.path().canonicalize().unwrap().join("other");
        std::fs::create_dir_all(other.join(".git")).unwrap();
        let mut repos = repos;
        repos.register(&other).unwrap();
        let mut store = FactStore::new(repos);
        let dev = |pid, start, dir: &Path| {
            proc(pid, start, 1, "node")
                .argv(&["node", "nuxt", "dev"])
                .cwd(dir)
        };
        let t = scan(
            &mut store,
            100,
            vec![
                launchd(),
                dev(201, 10, &root),
                dev(202, 20, &root),
                dev(203, 30, &root),
                dev(204, 40, &other),
                dev(205, 50, &root).argv(&["node", "nuxt", "build"]),
                dev(206, 60, Path::new("/")),
            ],
        );
        let view = store.view(&t);
        assert_eq!(view.newer_twins(key(201, 10)), Some(2));
        assert_eq!(view.newer_twins(key(202, 20)), Some(1));
        assert_eq!(view.newer_twins(key(203, 30)), Some(0));
        assert_eq!(view.newer_twins(key(204, 40)), Some(0));
        // No repo: unknown.
        assert_eq!(view.newer_twins(key(206, 60)), None);
    }

    #[test]
    fn session_alive_follows_the_session_leader() {
        let mut store = FactStore::new(Repos::default());
        let t = scan(
            &mut store,
            100,
            vec![
                launchd(),
                proc(100, 10, 1, "zsh").session(100),
                proc(101, 20, 1, "node").session(100),
                proc(102, 20, 1, "node").session(103),
                // pid 103 is a newer process that reused the old leader's pid.
                proc(103, 30, 1, "node").session(103),
                proc(104, 20, 1, "node").session(105),
                proc(106, 20, 1, "node"),
            ],
        );
        assert_eq!(facts(&store, &t, 101).session_alive, Some(true));
        assert_eq!(facts(&store, &t, 102).session_alive, Some(false));
        assert_eq!(facts(&store, &t, 104).session_alive, Some(false));
        assert_eq!(facts(&store, &t, 106).session_alive, None);
    }
}
