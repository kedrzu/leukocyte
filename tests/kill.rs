//! Drives the kill executor over real process trees spawned by the tests. Nothing here signals a
//! process the test did not start: every tree runs in its own process group, killed whole when
//! its guard drops, even on failure.

use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use leukocyte::engine::Own;
use leukocyte::facts::ProcKey;
use leukocyte::facts::table::ProcessTable;
use leukocyte::kill::{Executor, GuardReason, KillJob, KillReport, kill};
use leukocyte::platform;
use leukocyte::rules::Signal;

const AGENT_ARG: &str = "leukocyte-test-agent";
const SPAWNER_ARG: &str = "leukocyte-test-spawner";

/// Not a test: the body of a fake agent (started with argv0 `claude`) that runs a child and
/// sleeps. Acts only when started with `AGENT_ARG`.
#[test]
#[ignore = "helper: runs as a child process of the kill tests"]
fn agent() {
    if std::env::args().any(|arg| arg == AGENT_ARG) {
        let _child = Command::new("/bin/sleep").arg("300").spawn();
        std::thread::sleep(Duration::from_secs(300));
    }
}

/// Not a test: a plain process that starts the fake agent and sleeps. Acts only when started
/// with `SPAWNER_ARG`.
#[test]
#[ignore = "helper: runs as a child process of the kill tests"]
fn spawner() {
    if std::env::args().any(|arg| arg == SPAWNER_ARG) {
        let _agent = support::helper("agent", AGENT_ARG).arg0("claude").spawn();
        std::thread::sleep(Duration::from_secs(300));
    }
}

/// Test helpers. `#[cfg(test)]` marks them as test code for clippy's `allow-unwrap-in-tests`.
#[cfg(test)]
mod support {
    use super::*;

    /// A spawned tree in its own process group: the whole group is killed and the root reaped
    /// when dropped.
    pub struct Tree(pub Child);

    impl Tree {
        pub fn new(command: &mut Command) -> Self {
            Self(command.process_group(0).spawn().unwrap())
        }

        pub fn sh(script: &str) -> Self {
            Self::new(Command::new("/bin/sh").args(["-c", script]))
        }

        pub fn pid(&self) -> i32 {
            i32::try_from(self.0.id()).unwrap()
        }

        pub fn key(&self) -> ProcKey {
            platform::base_info(self.pid()).unwrap().key
        }

        /// Waits until the tree has `count` processes and returns them root first, parents
        /// before children.
        pub fn members(&self, count: usize) -> Vec<ProcKey> {
            wait_for(|| {
                let members = subtree(&snapshot(), self.key());
                (members.len() == count).then_some(members)
            })
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = Command::new("/bin/kill")
                .args(["-KILL", "--", &format!("-{}", self.pid())])
                // A group left with only its zombie leader answers EPERM: nothing to kill.
                .stderr(Stdio::null())
                .status();
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    pub fn helper(name: &str, arg: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", name, "--ignored", "--quiet", arg]);
        command
    }

    pub fn snapshot() -> ProcessTable {
        ProcessTable::snapshot(Vec::<String>::new()).unwrap()
    }

    /// `root` and its descendants in `table`, in pre-order.
    pub fn subtree(table: &ProcessTable, root: ProcKey) -> Vec<ProcKey> {
        let mut out = Vec::new();
        let mut stack = vec![root];
        while let Some(key) = stack.pop() {
            let Some(process) = table.get(key) else {
                continue;
            };
            out.push(key);
            stack.extend(process.children().iter().rev());
        }
        out
    }

    pub fn job(subtree: Vec<ProcKey>, grace: Duration) -> KillJob {
        KillJob {
            root: subtree[0],
            subtree,
            signal: Signal::Term,
            grace,
        }
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

    pub fn sorted(mut keys: Vec<ProcKey>) -> Vec<ProcKey> {
        keys.sort_unstable();
        keys
    }

    pub fn skipped(report: &KillReport, key: ProcKey) -> Option<GuardReason> {
        report
            .skipped
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, r)| *r)
    }
}

use support::*;

#[test]
fn a_tree_that_obeys_term_dies_without_escalation() {
    let tree = Tree::sh("/bin/sleep 300 & /bin/sleep 300 & wait");
    let members = tree.members(3);

    let started = Instant::now();
    let report = kill(
        &job(members.clone(), Duration::from_secs(10)),
        Own::current(),
    );

    assert!(
        started.elapsed() < Duration::from_secs(5),
        "waited out the grace"
    );
    assert_eq!(sorted(report.signalled.clone()), sorted(members.clone()));
    assert!(report.escalated.is_empty(), "{report:?}");
    assert!(report.skipped.is_empty(), "{report:?}");
    assert!(report.survivors_after.is_empty(), "{report:?}");
    assert!(report.failed.is_empty(), "{report:?}");
    // The children were signalled before their parent.
    assert_eq!(report.signalled.last(), Some(&members[0]));
    assert!(members.iter().all(|k| !platform::alive(*k)));
}

#[test]
fn a_member_ignoring_term_is_escalated_after_grace() {
    // The shell ignores TERM, and `sleep` inherits the ignored disposition across fork and exec.
    let tree = Tree::sh("trap '' TERM; /bin/sleep 300");
    let members = tree.members(2);
    let grace = Duration::from_millis(800);

    let started = Instant::now();
    let report = kill(&job(members.clone(), grace), Own::current());

    assert!(started.elapsed() >= grace);
    assert_eq!(sorted(report.signalled.clone()), sorted(members.clone()));
    // Both ignored TERM for the whole grace, so both had to be escalated.
    assert_eq!(sorted(report.escalated.clone()), sorted(members.clone()));
    assert!(report.survivors_after.is_empty(), "{report:?}");
    assert!(members.iter().all(|k| !platform::alive(*k)));
}

#[test]
fn a_member_reparented_during_grace_is_still_killed() {
    // The outer shell dies on TERM; the inner one ignores it and becomes `sleep`, which launchd
    // adopts once the outer shell is gone.
    let tree = Tree::sh("/bin/sh -c \"trap '' TERM; exec /bin/sleep 300\" & wait");
    let members = tree.members(2);
    let (root, child) = (members[0], members[1]);

    let executor = Executor::new(Own::current());
    executor
        .submit(job(members.clone(), Duration::from_secs(3)))
        .unwrap();

    // Observed during grace: the child now belongs to launchd, out of the root's reach.
    wait_for(|| (platform::base_info(child.pid)?.ppid == 1).then_some(()));
    assert!(!platform::alive(root));
    assert!(platform::alive(child));

    let report = executor.wait(Duration::from_secs(10)).unwrap();
    assert_eq!(report.root, root);
    assert_eq!(report.escalated, vec![child]);
    assert!(report.survivors_after.is_empty(), "{report:?}");
    assert!(!platform::alive(child));
    assert_eq!(executor.completed().count(), 0);
}

#[test]
fn a_child_started_during_grace_is_found_and_killed() {
    // The shell ignores TERM and starts a new `sleep` after the kill began.
    let tree = Tree::sh("trap '' TERM; /bin/sleep 0.4; /bin/sleep 300");
    let root = tree.key();
    let first = tree.members(2)[1];

    let report = kill(
        &job(vec![root, first], Duration::from_secs(2)),
        Own::current(),
    );

    assert_eq!(report.escalated.len(), 2, "{report:?}");
    assert!(report.escalated.contains(&root));
    assert!(
        !report.escalated.contains(&first),
        "the first sleep exited on its own"
    );
    assert!(report.survivors_after.is_empty(), "{report:?}");
    assert!(report.escalated.iter().all(|k| !platform::alive(*k)));
}

/// Must protect: a key whose start time does not match the live process is never signalled.
#[test]
fn a_reused_pid_is_never_signalled() {
    let victim = Tree::new(Command::new("/bin/sleep").arg("300"));
    let real = victim.key();
    let fake = ProcKey {
        pid: real.pid,
        start: real.start + 1,
    };

    // As the root: the whole kill is aborted.
    let report = kill(&job(vec![fake], Duration::ZERO), Own::current());
    assert!(report.aborted());
    assert_eq!(skipped(&report, fake), Some(GuardReason::Gone));
    assert!(report.signalled.is_empty() && report.escalated.is_empty());

    // As a member of another tree: skipped, while the rest dies.
    let other = Tree::new(Command::new("/bin/sleep").arg("300"));
    let report = kill(
        &job(vec![other.key(), fake], Duration::ZERO),
        Own::current(),
    );
    assert_eq!(report.signalled, vec![other.key()]);
    assert_eq!(skipped(&report, fake), Some(GuardReason::Gone));
    assert!(!report.escalated.contains(&fake));

    std::thread::sleep(Duration::from_millis(200));
    assert!(
        platform::alive(real),
        "the live process behind the reused pid was signalled"
    );
}

/// Must protect: the daemon (here the test process) and its ancestors are never signalled,
/// whatever the job holds.
#[test]
fn the_daemon_and_its_ancestors_are_never_signalled() {
    let table = snapshot();
    let me = table.by_pid(Own::current().pid).unwrap();
    let parent = table.parent_of(me).unwrap().key();
    let me = me.key();

    let report = kill(&job(vec![me], Duration::ZERO), Own::current());
    assert!(report.aborted());
    assert_eq!(skipped(&report, me), Some(GuardReason::Daemon));
    assert!(report.signalled.is_empty());

    let tree = Tree::new(Command::new("/bin/sleep").arg("300"));
    let report = kill(
        &job(vec![tree.key(), me, parent], Duration::ZERO),
        Own::current(),
    );
    assert_eq!(report.signalled, vec![tree.key()]);
    assert_eq!(skipped(&report, me), Some(GuardReason::Daemon));
    assert_eq!(skipped(&report, parent), Some(GuardReason::Daemon));
    assert!(platform::alive(parent));
}

/// Must protect: an agent process and everything below it are never signalled, decided on the
/// live process (argv0), not on any origin record.
#[test]
fn an_agent_and_its_subtree_are_never_signalled() {
    let tree = Tree::new(&mut helper("spawner", SPAWNER_ARG));
    let members = tree.members(3);
    let (spawner, agent, child) = (members[0], members[1], members[2]);

    // The agent as the root: nothing is signalled.
    let report = kill(&job(vec![agent, child], Duration::ZERO), Own::current());
    assert!(report.aborted());
    assert_eq!(skipped(&report, agent), Some(GuardReason::Agent));
    assert!(report.signalled.is_empty());

    // The agent inside the tree: the tree stops at it.
    let report = kill(
        &job(members.clone(), Duration::from_secs(5)),
        Own::current(),
    );
    assert_eq!(report.signalled, vec![spawner]);
    assert_eq!(skipped(&report, agent), Some(GuardReason::Agent));
    assert_eq!(
        skipped(&report, child),
        Some(GuardReason::Below { pid: agent.pid })
    );
    assert!(report.escalated.is_empty(), "{report:?}");

    std::thread::sleep(Duration::from_millis(200));
    assert!(!platform::alive(spawner));
    assert!(platform::alive(agent));
    assert!(platform::alive(child));
}
