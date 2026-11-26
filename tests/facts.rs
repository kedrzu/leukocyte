//! Drives the fact store over real process trees spawned by the tests.

use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use leukocyte::facts::table::ProcessTable;
use leukocyte::facts::{FactStore, OriginFacts, OriginKind, ProcFacts, ProcKey, Repos};
use leukocyte::platform;

const SLEEPER_ARG: &str = "leukocyte-test-sleeper";

/// Not a test: the body of a child process that, unlike `/bin/sleep`, is not a platform binary,
/// so the kernel shows its environment. Sleeps only when started with `SLEEPER_ARG`.
#[test]
#[ignore = "helper: runs as a child process of the store tests"]
fn sleeper() {
    if std::env::args().any(|arg| arg == SLEEPER_ARG) {
        std::thread::sleep(Duration::from_secs(30));
    }
}

/// Test helpers. `#[cfg(test)]` marks them as test code for clippy's `allow-unwrap-in-tests`.
#[cfg(test)]
mod support {
    use super::*;

    /// A spawned child, killed and reaped when dropped.
    pub struct Spawned(pub Child);

    impl Spawned {
        pub fn new(command: &mut Command) -> Self {
            Self(command.spawn().unwrap())
        }

        pub fn pid(&self) -> i32 {
            i32::try_from(self.0.id()).unwrap()
        }
    }

    impl Drop for Spawned {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// A process the test started indirectly (a grandchild), killed when dropped.
    pub struct Descendant(pub ProcKey);

    impl Drop for Descendant {
        fn drop(&mut self) {
            let _ = platform::signal(self.0, libc::SIGKILL);
        }
    }

    pub fn sleeper_cmd() -> String {
        format!(
            "'{}' --exact sleeper --ignored --quiet {SLEEPER_ARG}",
            std::env::current_exe().unwrap().display()
        )
    }

    /// Polls `check` until it returns `Some`, for up to 5 s.
    pub fn wait_for<T>(mut check: impl FnMut() -> Option<T>) -> T {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(value) = check() {
                return value;
            }
            assert!(Instant::now() < deadline, "timed out waiting");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn snapshot() -> ProcessTable {
        ProcessTable::snapshot(Vec::<String>::new()).unwrap()
    }

    pub fn scan(store: &mut FactStore) -> ProcessTable {
        let table = snapshot();
        store.update(&table);
        table
    }

    pub fn facts(store: &FactStore, table: &ProcessTable, key: ProcKey) -> ProcFacts {
        store.view(table).facts(key).unwrap()
    }

    pub fn git(dir: &Path, args: &[&str]) {
        let status = Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
            .args(args)
            .current_dir(dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    }

    pub fn agent_origin(alive: bool) -> OriginFacts {
        OriginFacts {
            kind: Some(OriginKind::Agent),
            alive: Some(alive),
        }
    }
}

use support::*;

/// An agent starts a launcher that starts a daemon and exits, as `npx agent-browser` does: the
/// daemon is reparented to launchd and keeps the origin and repo recorded while the chain was
/// intact.
#[test]
fn a_reparented_daemon_keeps_its_origin_and_repo() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    std::fs::create_dir_all(root.join("src")).unwrap();
    git(&root, &["init", "-q"]);
    let mut repos = Repos::default();
    let id = repos.register(&root).unwrap();

    // The "agent" is a shell named `claude`; its launcher waits on stdin before exiting.
    let script = "/bin/sh -c '/bin/sleep 30 & read x'; /bin/sleep 30; true";
    let mut agent = Spawned::new(
        Command::new("/bin/sh")
            .arg0("claude")
            .args(["-c", script])
            .env_clear()
            .stdin(Stdio::piped())
            .current_dir(root.join("src")),
    );
    let table = wait_for(|| {
        let table = snapshot();
        let agent = table.by_pid(agent.pid())?;
        let launcher = table.children_of(agent).next()?;
        let daemon = table.children_of(launcher).next()?.key();
        Some((table, daemon))
    });
    let (table, daemon) = table;
    let _daemon = Descendant(daemon);
    let agent_key = table.by_pid(agent.pid()).unwrap().key();

    let mut store = FactStore::new(repos);
    store.update(&table);
    let first = facts(&store, &table, daemon);
    assert_eq!(first.origin, agent_origin(true));
    assert_eq!(first.repo, Some(id.clone()));
    assert!(!first.orphan);

    agent.0.stdin.take().unwrap().write_all(b"\n").unwrap();
    wait_for(|| (platform::base_info(daemon.pid)?.ppid == 1).then_some(()));
    let table = scan(&mut store);
    let reparented = facts(&store, &table, daemon);
    assert!(reparented.orphan);
    assert_eq!(reparented.origin, agent_origin(true));
    assert_eq!(reparented.repo, Some(id.clone()));

    // The agent's own `sleep` is ours too: stop it along with the agent.
    let agent_sleep = table
        .children_of(table.get(agent_key).unwrap())
        .map(|p| Descendant(p.key()))
        .collect::<Vec<_>>();
    drop(agent);
    drop(agent_sleep);
    let table = scan(&mut store);
    let orphaned = facts(&store, &table, daemon);
    assert_eq!(orphaned.origin, agent_origin(false));
    assert_eq!(orphaned.repo, Some(id));

    // A restarted daemon has no record: unknown, never dead.
    let mut restarted = FactStore::new(Repos::default());
    let table = scan(&mut restarted);
    let unknown = facts(&restarted, &table, daemon).origin;
    assert_eq!(unknown.kind, None);
    assert_eq!(unknown.alive, None);
}

#[test]
fn a_process_keeps_its_repo_after_its_worktree_is_deleted() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    std::fs::create_dir_all(&root).unwrap();
    git(&root, &["init", "-q"]);
    git(&root, &["commit", "-q", "--allow-empty", "-m", "init"]);
    git(&root, &["worktree", "add", "-q", "../wt"]);
    let wt = tmp.path().join("wt");
    let mut repos = Repos::default();
    let id = repos.register(&root).unwrap();

    let child = Spawned::new(
        Command::new("/bin/sleep")
            .arg("30")
            .env_clear()
            .current_dir(&wt),
    );
    let key = platform::base_info(child.pid()).unwrap().key;
    let mut store = FactStore::new(repos.clone());
    let table = scan(&mut store);
    assert_eq!(facts(&store, &table, key).repo, Some(id.clone()));

    std::fs::remove_dir_all(&wt).unwrap();
    let table = scan(&mut store);
    assert_eq!(facts(&store, &table, key).repo, Some(id));

    // The deleted directory no longer resolves: the repo above came from memory.
    let mut fresh = FactStore::new(repos);
    let table = scan(&mut fresh);
    assert_eq!(facts(&fresh, &table, key).repo, None);
}

/// A daemon first seen already orphaned takes its origin from `CLAUDE_PID`.
#[test]
fn an_orphan_takes_its_origin_from_claude_pid() {
    let mut agent = Spawned::new(Command::new("/bin/sleep").arg("30").env_clear());
    let output = Command::new("/bin/sh")
        .args([
            "-c",
            &format!("{} >/dev/null 2>&1 & echo $!", sleeper_cmd()),
        ])
        .env_clear()
        .env("CLAUDE_PID", agent.pid().to_string())
        .output()
        .unwrap();
    let pid: i32 = String::from_utf8(output.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let orphan = wait_for(|| {
        let info = platform::base_info(pid)?;
        (info.ppid == 1).then_some(info.key)
    });
    let _orphan = Descendant(orphan);

    let mut store = FactStore::new(Repos::default());
    let table = scan(&mut store);
    assert_eq!(facts(&store, &table, orphan).origin, agent_origin(true));

    agent.0.kill().unwrap();
    agent.0.wait().unwrap();
    let table = scan(&mut store);
    assert_eq!(facts(&store, &table, orphan).origin, agent_origin(false));
}

#[test]
fn a_sleeping_process_grows_idle_and_a_busy_one_does_not() {
    let idle = Spawned::new(
        Command::new("/bin/sh")
            .args(["-c", &format!("exec {}", sleeper_cmd())])
            .env_clear(),
    );
    let busy = Spawned::new(
        Command::new("/bin/sh")
            .args(["-c", "while :; do :; done"])
            .env_clear(),
    );
    std::thread::sleep(Duration::from_millis(300));

    let mut store = FactStore::new(Repos::default());
    let table = scan(&mut store);
    let idle_key = table.by_pid(idle.pid()).unwrap().key();
    let busy_key = table.by_pid(busy.pid()).unwrap().key();
    assert_eq!(facts(&store, &table, idle_key).idle, Duration::ZERO);

    std::thread::sleep(Duration::from_millis(1500));
    let table = scan(&mut store);
    let sleeping = facts(&store, &table, idle_key);
    assert!(sleeping.idle >= Duration::from_millis(1400), "{sleeping:?}");
    assert!(sleeping.cpu.unwrap() < 1.0, "{sleeping:?}");
    let working = facts(&store, &table, busy_key);
    assert_eq!(working.idle, Duration::ZERO);
    assert!(working.cpu.unwrap() > 50.0, "{working:?}");
}
