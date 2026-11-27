use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use super::*;
use crate::facts::table::{ProcessTable, SyntheticProcess};
use crate::facts::{FactStore, Repos};
use crate::platform::{BaseInfo, Cmdline, Usage};

const UID: u32 = 501;
/// The daemon's pid: absent from the tables unless a test adds it.
const DAEMON: i32 = 9999;
const OWN: Own = Own {
    pid: DAEMON,
    uid: UID,
};

fn key(pid: i32, start: u64) -> ProcKey {
    ProcKey {
        pid,
        start: start * 1_000_000,
    }
}

/// A made-up process started at second `pid` (so parents, with lower pids, are older); `cmd`
/// is the exe and argv.
fn proc(pid: i32, ppid: i32, cmd: &str) -> SyntheticProcess {
    let mut words = cmd.split(' ');
    let exe = words.next().unwrap_or_default().to_owned();
    SyntheticProcess {
        info: BaseInfo {
            key: key(pid, u64::try_from(pid).unwrap()),
            ppid,
            uid: UID,
            tty: None,
            session: None,
            rss: Some(4096),
            usage: Some(Usage {
                cpu: Duration::ZERO,
                children_cpu: Duration::ZERO,
                disk_read: 0,
                disk_written: 0,
            }),
        },
        cmdline: Some(Cmdline {
            exe,
            argv: words.map(str::to_owned).collect(),
            env: Some(BTreeMap::new()),
        }),
        cwd: None,
    }
}

fn launchd() -> SyntheticProcess {
    let mut p = proc(1, 0, "/sbin/launchd");
    p.info.uid = 0;
    p.info.usage = None;
    p.cmdline = None;
    p
}

fn in_dir(mut p: SyntheticProcess, dir: &Path) -> SyntheticProcess {
    p.cwd = Some(dir.to_path_buf());
    p
}

fn tty(mut p: SyntheticProcess, tty: u32) -> SyntheticProcess {
    p.info.tty = Some(tty);
    p
}

fn uid(mut p: SyntheticProcess, uid: u32) -> SyntheticProcess {
    p.info.uid = uid;
    p
}

/// Two registered repos, `a` and `b`, and the fact store over them.
struct World {
    _tmp: tempfile::TempDir,
    a: PathBuf,
    b: PathBuf,
    scope_a: Scope,
    scope_b: Scope,
    store: FactStore,
}

fn world() -> World {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().canonicalize().unwrap();
    let mut repos = Repos::default();
    let mut repo = |name: &str| {
        let root = base.join(name);
        std::fs::create_dir_all(root.join(".git")).unwrap();
        let id = repos.register(&root).unwrap();
        (root, Scope::Repo(id))
    };
    let (a, scope_a) = repo("a");
    let (b, scope_b) = repo("b");
    World {
        _tmp: tmp,
        a,
        b,
        scope_a,
        scope_b,
        store: FactStore::new(repos),
    }
}

impl World {
    /// Takes in a snapshot taken `at` seconds after the epoch.
    fn table(&mut self, at: u64, procs: Vec<SyntheticProcess>) -> ProcessTable {
        let table = ProcessTable::synthetic(UNIX_EPOCH + Duration::from_secs(at), procs);
        self.store.update(&table);
        table
    }
}

fn rules(name: &str, body: &str) -> RuleSet {
    let source = format!("return {{ api = 1, rules = {{ {body} }} }}");
    RuleSet::load(name, source.as_bytes()).unwrap_or_else(|e| panic!("{e}"))
}

/// An enforced kill rule without quarantine for every process whose command line holds
/// `needle`.
fn kill(name: &str, needle: &str) -> String {
    format!(
        r#"{{ name = "{name}", match = "{needle}", when = "always", quarantine = "0s", enforce = true }},"#
    )
}

fn protect(name: &str, needle: &str) -> String {
    format!(
        r#"{{ name = "{name}", match = "{needle}", when = "always",
              judge = function(p) return "protect", "busy" end }},"#
    )
}

/// Inputs of one scan, owning the sets the [`ScanInput`] borrows.
struct Inputs {
    mode: Mode,
    keep: HashSet<ProcKey>,
    in_flight: HashSet<ProcKey>,
}

impl Inputs {
    fn new() -> Self {
        Self {
            mode: Mode::Enforce,
            keep: HashSet::new(),
            in_flight: HashSet::new(),
        }
    }

    fn input<'a>(
        &'a self,
        store: &'a FactStore,
        table: &'a ProcessTable,
        sources: &'a [Source<'a>],
    ) -> ScanInput<'a> {
        ScanInput {
            view: store.view(table),
            sources,
            mode: self.mode,
            keep: &self.keep,
            in_flight: &self.in_flight,
        }
    }
}

fn kills(out: &ScanOutput) -> Vec<(i32, Vec<i32>)> {
    out.actions
        .iter()
        .filter(|a| matches!(a.kind, ActionKind::Kill { .. }))
        .map(|a| (a.key.pid, a.subtree.iter().map(|k| k.pid).collect()))
        .collect()
}

fn of_pid(out: &ScanOutput, pid: i32) -> Vec<&ActionKind> {
    out.actions
        .iter()
        .filter(|a| a.key.pid == pid)
        .map(|a| &a.kind)
        .collect()
}

fn state(explained: &[Explanation], pid: i32) -> CandidateState {
    explained
        .iter()
        .find(|e| e.key.pid == pid)
        .unwrap_or_else(|| panic!("pid {pid} is no candidate"))
        .state
        .clone()
}

fn rule_ref(source: &str, rule: &str) -> RuleRef {
    RuleRef {
        source: source.to_owned(),
        rule: rule.to_owned(),
    }
}

#[test]
fn a_protect_on_any_member_of_a_tree_vetoes_the_tree_kill() {
    let mut w = world();
    let t = w.table(
        100,
        vec![
            launchd(),
            in_dir(proc(20, 1, "/bin/nx-root run"), &w.a),
            proc(21, 20, "/bin/node worker"),
            proc(22, 21, "/bin/node keepme"),
        ],
    );
    let repo = rules("repo.lua", &kill("reap", "nx-root"));
    let personal = rules("personal.lua", &protect("busy", "keepme"));
    let sources = [
        Source {
            scope: &w.scope_a,
            rules: &repo,
        },
        Source {
            scope: &Scope::Personal,
            rules: &personal,
        },
    ];
    let inputs = Inputs::new();
    let out = Engine::new(OWN).scan(&inputs.input(&w.store, &t, &sources));
    assert_eq!(kills(&out), vec![]);
    let by = Blocker::Rule {
        by: rule_ref("personal.lua", "busy"),
        pid: 22,
    };
    assert_eq!(
        of_pid(&out, 20),
        vec![&ActionKind::Blocked { by: by.clone() }]
    );
    let action = out.actions.iter().find(|a| a.key.pid == 20).unwrap();
    assert!(
        action
            .reason
            .ends_with("blocked by protect \"busy\" (personal.lua) on pid 22"),
        "{}",
        action.reason
    );
    assert!(action.subtree.is_empty());
}

#[test]
fn a_protect_outranks_a_kill_from_another_rule_and_another_source() {
    let mut w = world();
    let t = w.table(
        100,
        vec![
            launchd(),
            in_dir(proc(20, 1, "/bin/nx-root one"), &w.a),
            in_dir(proc(30, 1, "/bin/nx-root two"), &w.a),
        ],
    );
    // Same source: a kill and a protect rule on pid 20.
    let repo = rules(
        "repo.lua",
        &format!("{}{}", kill("reap", "nx-root"), protect("hold", "root one")),
    );
    // Another source protects pid 30.
    let personal = rules("personal.lua", &protect("mine", "root two"));
    let sources = [
        Source {
            scope: &w.scope_a,
            rules: &repo,
        },
        Source {
            scope: &Scope::Personal,
            rules: &personal,
        },
    ];
    let inputs = Inputs::new();
    let mut engine = Engine::new(OWN);
    let out = engine.scan(&inputs.input(&w.store, &t, &sources));
    assert_eq!(kills(&out), vec![]);
    assert_eq!(
        of_pid(&out, 20),
        vec![&ActionKind::Blocked {
            by: Blocker::Rule {
                by: rule_ref("repo.lua", "hold"),
                pid: 20
            }
        }]
    );
    assert_eq!(
        of_pid(&out, 30),
        vec![&ActionKind::Blocked {
            by: Blocker::Rule {
                by: rule_ref("personal.lua", "mine"),
                pid: 30
            }
        }]
    );
}

#[test]
fn a_kept_process_is_never_killed_nor_its_tree() {
    let mut w = world();
    let t = w.table(
        100,
        vec![
            launchd(),
            proc(20, 1, "/bin/nx-root one"),
            proc(30, 1, "/bin/nx-root two"),
            proc(31, 30, "/bin/node worker"),
        ],
    );
    let personal = rules("personal.lua", &kill("reap", "nx-root"));
    let sources = [Source {
        scope: &Scope::Personal,
        rules: &personal,
    }];
    let mut inputs = Inputs::new();
    inputs.keep = HashSet::from([key(20, 20), key(31, 31)]);
    let mut engine = Engine::new(OWN);
    let out = engine.scan(&inputs.input(&w.store, &t, &sources));
    assert_eq!(kills(&out), vec![]);
    assert_eq!(
        of_pid(&out, 20),
        vec![&ActionKind::Blocked {
            by: Blocker::Keep { pid: 20 }
        }]
    );
    // The kept worker is not matched by any rule, and still vetoes its parent's tree.
    assert_eq!(
        of_pid(&out, 30),
        vec![&ActionKind::Blocked {
            by: Blocker::Keep { pid: 31 }
        }]
    );
}

#[test]
fn repo_rules_judge_only_their_repo_and_personal_rules_judge_all() {
    let mut w = world();
    let t = w.table(
        100,
        vec![
            launchd(),
            in_dir(proc(20, 1, "/bin/nx-root a"), &w.a),
            in_dir(proc(30, 1, "/bin/nx-root b"), &w.b),
            proc(40, 1, "/bin/nx-root nowhere"),
        ],
    );
    let repo = rules("a.lua", &kill("reap", "nx-root"));
    let sources = [Source {
        scope: &w.scope_a,
        rules: &repo,
    }];
    let inputs = Inputs::new();
    let out = Engine::new(OWN).scan(&inputs.input(&w.store, &t, &sources));
    assert_eq!(kills(&out), vec![(20, vec![20])]);

    let personal = rules("personal.lua", &kill("reap", "nx-root"));
    let sources = [Source {
        scope: &Scope::Personal,
        rules: &personal,
    }];
    let out = Engine::new(OWN).scan(&inputs.input(&w.store, &t, &sources));
    assert_eq!(
        kills(&out),
        vec![(20, vec![20]), (30, vec![30]), (40, vec![40])]
    );
    // The scope of repo b is honoured too.
    let sources = [Source {
        scope: &w.scope_b,
        rules: &repo,
    }];
    let out = Engine::new(OWN).scan(&inputs.input(&w.store, &t, &sources));
    assert_eq!(kills(&out), vec![(30, vec![30])]);
}

/// A process that is orphaned at `orphaned`, and the child of a live shell otherwise.
fn orphan_or_not(orphaned: bool) -> Vec<SyntheticProcess> {
    vec![
        launchd(),
        proc(10, 1, "/bin/sh holder"),
        proc(20, if orphaned { 1 } else { 10 }, "/bin/nx-root run"),
    ]
}

#[test]
fn nothing_is_killed_before_its_quarantine_elapses_and_a_lapse_resets_it() {
    let mut w = world();
    let personal = rules(
        "personal.lua",
        r#"{ name = "reap", match = "nx-root", when = "orphaned", quarantine = "10m", enforce = true },"#,
    );
    let sources = [Source {
        scope: &Scope::Personal,
        rules: &personal,
    }];
    let inputs = Inputs::new();
    let mut engine = Engine::new(OWN);
    let mut scan = |w: &mut World, at: u64, orphaned: bool| {
        let t = w.table(at, orphan_or_not(orphaned));
        let out = engine.scan(&inputs.input(&w.store, &t, &sources));
        let (explained, _) = engine.explain(&inputs.input(&w.store, &t, &sources));
        (kills(&out), state(&explained, 20))
    };
    let quarantined = |secs| CandidateState::Quarantined {
        remaining: Duration::from_secs(secs),
    };

    assert_eq!(scan(&mut w, 1000, true), (vec![], quarantined(600)));
    assert_eq!(scan(&mut w, 1300, true), (vec![], quarantined(300)));
    // The verdict lapses: the clock restarts from the next kill verdict.
    let (k, s) = scan(&mut w, 1500, false);
    assert_eq!(k, vec![]);
    assert!(matches!(s, CandidateState::NoVerdict { .. }), "{s:?}");
    assert_eq!(scan(&mut w, 1600, true), (vec![], quarantined(600)));
    assert_eq!(scan(&mut w, 2199, true), (vec![], quarantined(1)));
    assert_eq!(
        scan(&mut w, 2200, true),
        (vec![(20, vec![20])], CandidateState::KillReady)
    );
}

#[test]
fn quarantine_clocks_of_vanished_processes_are_dropped() {
    let mut w = world();
    let personal = rules(
        "personal.lua",
        r#"{ name = "reap", match = "nx-root", when = "always", quarantine = "10m", enforce = true },"#,
    );
    let sources = [Source {
        scope: &Scope::Personal,
        rules: &personal,
    }];
    let inputs = Inputs::new();
    let mut engine = Engine::new(OWN);
    let t = w.table(100, orphan_or_not(true));
    engine.scan(&inputs.input(&w.store, &t, &sources));
    assert_eq!(engine.kill_since.len(), 1);
    let t = w.table(105, vec![launchd()]);
    engine.scan(&inputs.input(&w.store, &t, &sources));
    assert!(engine.kill_since.is_empty());
}

#[test]
fn observe_mode_and_enforce_false_never_kill() {
    let mut w = world();
    let t = w.table(
        100,
        vec![
            launchd(),
            proc(20, 1, "/bin/nx-root run"),
            proc(21, 20, "/bin/node worker"),
            proc(30, 1, "/bin/vitest run"),
        ],
    );
    let personal = rules(
        "personal.lua",
        &format!(
            "{}{}",
            kill("reap", "nx-root"),
            r#"{ name = "soft", match = "vitest", when = "always", quarantine = "0s" },"#
        ),
    );
    let sources = [Source {
        scope: &Scope::Personal,
        rules: &personal,
    }];
    let mut inputs = Inputs::new();
    let out = Engine::new(OWN).scan(&inputs.input(&w.store, &t, &sources));
    // enforce = false: would kill, even in enforce mode.
    assert_eq!(kills(&out), vec![(20, vec![20, 21])]);
    assert_eq!(of_pid(&out, 30), vec![&ActionKind::WouldKill]);

    inputs.mode = Mode::Observe;
    let out = Engine::new(OWN).scan(&inputs.input(&w.store, &t, &sources));
    assert_eq!(kills(&out), vec![]);
    assert_eq!(of_pid(&out, 20), vec![&ActionKind::WouldKill]);
    assert_eq!(of_pid(&out, 30), vec![&ActionKind::WouldKill]);
    let would = out.actions.iter().find(|a| a.key.pid == 20).unwrap();
    assert_eq!(would.subtree, vec![key(20, 20), key(21, 21)]);
}

/// `n` unrelated orphaned nx roots, pids 100 and up.
fn roots(n: i32) -> Vec<SyntheticProcess> {
    std::iter::once(launchd())
        .chain((0..n).map(|i| proc(100 + i, 1, "/bin/nx-root run")))
        .collect()
}

#[test]
fn a_scan_exceeding_the_fuse_kills_nothing() {
    let mut w = world();
    let personal = rules("personal.lua", &kill("reap", "nx-root"));
    let sources = [Source {
        scope: &Scope::Personal,
        rules: &personal,
    }];
    let inputs = Inputs::new();
    let mut engine = Engine::new(OWN);
    let limit = i32::try_from(FUSE_LIMIT).unwrap();

    let t = w.table(100, roots(limit + 1));
    let out = engine.scan(&inputs.input(&w.store, &t, &sources));
    assert_eq!(kills(&out), vec![]);
    assert_eq!(
        out.fuse,
        Some(FuseEvent {
            kills: FUSE_LIMIT + 1,
            new_episode: true
        })
    );
    assert!(
        out.actions
            .iter()
            .all(|a| a.kind == ActionKind::Blocked { by: Blocker::Fuse } && a.subtree.is_empty())
    );

    // Still tripped: the same episode.
    let out = engine.scan(&inputs.input(&w.store, &t, &sources));
    assert_eq!(kills(&out), vec![]);
    assert_eq!(out.fuse.map(|f| f.new_episode), Some(false));

    // At the limit the kills go out, and the episode ends.
    let t = w.table(105, roots(limit));
    let out = engine.scan(&inputs.input(&w.store, &t, &sources));
    assert_eq!(kills(&out).len(), FUSE_LIMIT);
    assert_eq!(out.fuse, None);

    let t = w.table(110, roots(limit + 1));
    let out = engine.scan(&inputs.input(&w.store, &t, &sources));
    assert_eq!(out.fuse.map(|f| f.new_episode), Some(true));
}

#[test]
fn a_kill_in_flight_is_skipped_and_not_counted_by_the_fuse() {
    let mut w = world();
    let personal = rules("personal.lua", &kill("reap", "nx-root"));
    let sources = [Source {
        scope: &Scope::Personal,
        rules: &personal,
    }];
    let limit = i32::try_from(FUSE_LIMIT).unwrap();
    let mut procs = roots(limit + 1);
    // A worker of the first root, already being killed.
    procs.push(proc(500, 100, "/bin/node worker"));
    let t = w.table(100, procs);
    let mut inputs = Inputs::new();
    inputs.in_flight = HashSet::from([key(110, 110), key(500, 500)]);
    let out = Engine::new(OWN).scan(&inputs.input(&w.store, &t, &sources));
    assert_eq!(out.fuse, None);
    let k = kills(&out);
    assert_eq!(k.len(), FUSE_LIMIT);
    assert!(of_pid(&out, 110).is_empty());
    // The in-flight worker is not part of its parent's subtree.
    assert!(k.contains(&(100, vec![100])), "{k:?}");
}

#[test]
fn a_kill_folds_into_the_topmost_killed_ancestor() {
    let mut w = world();
    let t = w.table(
        100,
        vec![
            launchd(),
            proc(20, 1, "/bin/nx-root run"),
            proc(21, 20, "/bin/nx-root child"),
            proc(22, 21, "/bin/node worker"),
            proc(23, 22, "/bin/nx-root grandchild"),
        ],
    );
    let personal = rules("personal.lua", &kill("reap", "nx-root"));
    let sources = [Source {
        scope: &Scope::Personal,
        rules: &personal,
    }];
    let inputs = Inputs::new();
    let out = Engine::new(OWN).scan(&inputs.input(&w.store, &t, &sources));
    assert_eq!(kills(&out), vec![(20, vec![20, 21, 22, 23])]);
    assert_eq!(out.actions.len(), 1);
}

#[test]
fn a_real_kill_does_not_fold_into_a_would_kill() {
    let mut w = world();
    let t = w.table(
        100,
        vec![
            launchd(),
            proc(20, 1, "/bin/soft-root run"),
            proc(21, 20, "/bin/nx-root child"),
        ],
    );
    let personal = rules(
        "personal.lua",
        &format!(
            "{}{}",
            kill("reap", "nx-root"),
            r#"{ name = "soft", match = "soft-root", when = "always", quarantine = "0s" },"#
        ),
    );
    let sources = [Source {
        scope: &Scope::Personal,
        rules: &personal,
    }];
    let inputs = Inputs::new();
    let out = Engine::new(OWN).scan(&inputs.input(&w.store, &t, &sources));
    assert_eq!(kills(&out), vec![(21, vec![21])]);
    assert_eq!(of_pid(&out, 20), vec![&ActionKind::WouldKill]);
}

#[test]
fn an_origin_anchor_stops_the_subtree_and_is_never_killed() {
    let mut w = world();
    let t = w.table(
        100,
        vec![
            launchd(),
            proc(20, 1, "/bin/nx-root run"),
            proc(21, 20, "/usr/local/bin/claude claude"),
            proc(22, 21, "/bin/node agent-child"),
            proc(23, 20, "/bin/node worker"),
            // A terminal session below the root: its tty holder is a terminal anchor.
            tty(proc(24, 20, "/bin/zsh -zsh"), 3),
            tty(proc(25, 24, "/bin/node nuxt dev"), 3),
        ],
    );
    let personal = rules(
        "personal.lua",
        &format!("{}{}", kill("reap", "nx-root"), kill("agents", "claude")),
    );
    let sources = [Source {
        scope: &Scope::Personal,
        rules: &personal,
    }];
    let inputs = Inputs::new();
    let out = Engine::new(OWN).scan(&inputs.input(&w.store, &t, &sources));
    assert_eq!(kills(&out), vec![(20, vec![20, 23])]);
    assert_eq!(
        of_pid(&out, 21),
        vec![&ActionKind::Blocked {
            by: Blocker::Anchor { pid: 21 }
        }]
    );
}

#[test]
fn hard_guards_keep_the_daemon_its_ancestors_and_other_users_out() {
    let mut w = world();
    let t = w.table(
        100,
        vec![
            launchd(),
            proc(20, 1, "/bin/nx-root run"),
            proc(21, 20, "/bin/node worker"),
            uid(proc(22, 20, "/bin/sudo-thing"), 0),
            proc(30, 1, "/bin/nx-root host"),
            proc(DAEMON, 30, "/usr/local/bin/leukocyte daemon"),
            uid(proc(40, 1, "/bin/nx-root root-owned"), 0),
        ],
    );
    let personal = rules("personal.lua", &kill("reap", "nx-root"));
    let sources = [Source {
        scope: &Scope::Personal,
        rules: &personal,
    }];
    let inputs = Inputs::new();
    let out = Engine::new(OWN).scan(&inputs.input(&w.store, &t, &sources));
    assert_eq!(kills(&out), vec![(20, vec![20, 21])]);
    assert_eq!(
        of_pid(&out, 30),
        vec![&ActionKind::Blocked {
            by: Blocker::Guard {
                pid: 30,
                guard: Guard::Daemon
            }
        }]
    );
    // Another user's process is never judged.
    assert!(of_pid(&out, 40).is_empty());
}

#[test]
fn explain_does_not_touch_the_quarantine_or_the_fuse() {
    let mut w = world();
    let personal = rules(
        "personal.lua",
        &format!(
            "{}{}",
            kill("reap", "nx-root"),
            r#"{ name = "slow", match = "vitest", when = "always", quarantine = "10m", enforce = true },"#
        ),
    );
    let sources = [Source {
        scope: &Scope::Personal,
        rules: &personal,
    }];
    let inputs = Inputs::new();
    let engine = Engine::new(OWN);
    let limit = i32::try_from(FUSE_LIMIT).unwrap();
    let procs = || {
        let mut procs = roots(limit + 1);
        procs.push(proc(600, 1, "/bin/vitest run"));
        procs
    };
    let t = w.table(100, procs());
    let (explained, _) = engine.explain(&inputs.input(&w.store, &t, &sources));
    assert_eq!(state(&explained, 100), CandidateState::KillReady);
    assert_eq!(
        state(&explained, 600),
        CandidateState::Quarantined {
            remaining: Duration::from_secs(600)
        }
    );
    assert!(engine.kill_since.is_empty());
    assert!(!engine.fuse_tripped);

    // Ten minutes later, with no scan in between, the clock has not started.
    let t = w.table(700, procs());
    let (explained, _) = engine.explain(&inputs.input(&w.store, &t, &sources));
    assert_eq!(
        state(&explained, 600),
        CandidateState::Quarantined {
            remaining: Duration::from_secs(600)
        }
    );
}

#[test]
fn explain_tells_why_with_an_unregistered_rules_file_scoped_to_a_repo() {
    let mut w = world();
    let t = w.table(
        100,
        vec![
            launchd(),
            proc(10, 1, "/bin/sh holder"),
            in_dir(proc(20, 10, "/bin/nx-root parented"), &w.a),
            in_dir(proc(21, 1, "/bin/nx-root idle"), &w.a),
            in_dir(proc(22, 1, "/bin/nx-root report"), &w.a),
            in_dir(proc(23, 1, "/bin/nx-root broken"), &w.a),
            in_dir(proc(24, 1, "/bin/nx-root kept"), &w.a),
            in_dir(proc(30, 1, "/bin/nx-root other-repo"), &w.b),
        ],
    );
    let adhoc = rules(
        "/tmp/new/rules.lua",
        r#"
        { name = "parented", match = "parented", when = "orphaned" },
        { name = "idle", match = "nx-root idle", when = "orphaned", idle = "20m" },
        { name = "report", match = "report", when = "always",
          judge = function(p) return "report", "just looking" end },
        { name = "broken", match = "broken", when = "always",
          judge = function(p) error("boom") end },
        { name = "kept", match = "kept", when = "always", quarantine = "0s", enforce = true },
        { name = "other", match = "other-repo", when = "always" },
        "#,
    );
    let sources = [Source {
        scope: &w.scope_a,
        rules: &adhoc,
    }];
    let mut inputs = Inputs::new();
    inputs.keep = HashSet::from([key(24, 24)]);
    let engine = Engine::new(OWN);
    let (explained, errors) = engine.explain(&inputs.input(&w.store, &t, &sources));

    assert_eq!(
        state(&explained, 20),
        CandidateState::NoVerdict {
            why: NoVerdictWhy::WhenNotMet(When::Orphaned)
        }
    );
    assert_eq!(
        state(&explained, 21),
        CandidateState::NoVerdict {
            why: NoVerdictWhy::IdleBelow {
                idle: Duration::ZERO,
                need: Duration::from_secs(1200)
            }
        }
    );
    assert_eq!(state(&explained, 22), CandidateState::ReportOnly);
    let report = explained.iter().find(|e| e.key.pid == 22).unwrap();
    assert_eq!(report.rule, rule_ref("/tmp/new/rules.lua", "report"));
    assert!(
        report.reason.as_deref().unwrap().ends_with("just looking"),
        "{:?}",
        report.reason
    );
    let CandidateState::NoVerdict {
        why: NoVerdictWhy::EvalError(message),
    } = state(&explained, 23)
    else {
        panic!("pid 23: {:?}", state(&explained, 23));
    };
    assert!(message.contains("boom"), "{message}");
    assert_eq!(
        state(&explained, 24),
        CandidateState::Protected {
            by: Blocker::Keep { pid: 24 }
        }
    );
    // The file is scoped to repo a.
    assert!(explained.iter().all(|e| e.key.pid != 30));

    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].source, "/tmp/new/rules.lua");
    assert_eq!(errors[0].key, key(23, 23));
    assert_eq!(errors[0].error.rule, "broken");
}

#[test]
fn scan_returns_eval_errors_per_source() {
    let mut w = world();
    let t = w.table(100, vec![launchd(), proc(20, 1, "/bin/nx-root run")]);
    let personal = rules(
        "personal.lua",
        r#"{ name = "broken", match = "nx-root", when = "always",
             judge = function(p) return p.idel > 60 end },"#,
    );
    let sources = [Source {
        scope: &Scope::Personal,
        rules: &personal,
    }];
    let inputs = Inputs::new();
    let out = Engine::new(OWN).scan(&inputs.input(&w.store, &t, &sources));
    assert!(out.actions.is_empty());
    assert_eq!(out.eval_errors.len(), 1);
    assert_eq!(out.eval_errors[0].source, "personal.lua");
}

#[test]
fn action_facts_carry_the_argv_but_never_print_it() {
    let mut w = world();
    let t = w.table(
        100,
        vec![launchd(), proc(20, 1, "/bin/nx-root --token=hunter2")],
    );
    let personal = rules("personal.lua", &kill("reap", "nx-root"));
    let sources = [Source {
        scope: &Scope::Personal,
        rules: &personal,
    }];
    let inputs = Inputs::new();
    let out = Engine::new(OWN).scan(&inputs.input(&w.store, &t, &sources));
    let facts = &out.actions[0].facts;
    assert_eq!(facts.exe.as_deref(), Some("/bin/nx-root"));
    assert_eq!(
        facts.argv_unredacted,
        Some(vec!["--token=hunter2".to_owned()])
    );
    let dump = format!("{out:?}");
    assert!(!dump.contains("hunter2"), "{dump}");
}
