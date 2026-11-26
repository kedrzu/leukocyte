//! Reads real process trees spawned by the tests back through the platform layer and the table.

use std::os::unix::fs::MetadataExt;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use leukocyte::facts::ProcKey;
use leukocyte::facts::table::ProcessTable;
use leukocyte::platform;

const SECRET: &str = "leukocyte-test-secret-value";

const SLEEPER_ARG: &str = "leukocyte-test-sleeper";

/// Not a test: the body of a child process that, unlike `/bin/sleep`, is not a platform binary,
/// so the kernel shows its environment. Sleeps only when started by `sleeper_cmd`.
#[test]
#[ignore = "helper: runs as a child process of the env tests"]
fn sleeper() {
    if std::env::args().any(|arg| arg == SLEEPER_ARG) {
        std::thread::sleep(Duration::from_secs(30));
    }
}

/// Test helpers. `#[cfg(test)]` marks them as test code for clippy's `allow-unwrap-in-tests`,
/// which does not count a test crate's free functions as tests.
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

        pub fn key(&self) -> ProcKey {
            platform::base_info(self.pid()).unwrap().key
        }
    }

    impl Drop for Spawned {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    pub fn sleep_cmd() -> Command {
        let mut command = Command::new("/bin/sleep");
        command.arg("30").env_clear();
        command
    }

    pub fn sleeper_cmd() -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "sleeper", "--ignored", "--quiet", SLEEPER_ARG])
            .env_clear();
        command
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

    pub fn own_pid() -> i32 {
        i32::try_from(std::process::id()).unwrap()
    }
}

use support::*;

#[test]
fn snapshot_reads_a_spawned_tree() {
    let dir = tempfile::tempdir().unwrap();
    let script = "/bin/sleep 30; true";
    let sh = Spawned::new(
        Command::new("/bin/sh")
            .args(["-c", script])
            .env_clear()
            .env("LEUKO_TEST_ALLOWED", "visible")
            .env("LEUKO_TEST_SECRET", SECRET)
            .env("PASEO_AGENT_ID", "agent-test")
            .current_dir(dir.path()),
    );

    let table = wait_for(|| {
        let table = ProcessTable::snapshot(["LEUKO_TEST_ALLOWED"]).unwrap();
        let has_child = !table.by_pid(sh.pid())?.children().is_empty();
        has_child.then_some(table)
    });

    let me = table.by_pid(own_pid()).unwrap();
    let shell = table.by_pid(sh.pid()).unwrap();
    assert_eq!(shell.info.ppid, own_pid());
    assert_eq!(shell.parent(), Some(me.key()));
    assert!(me.children().contains(&shell.key()));
    assert_eq!(table.parent_of(shell).unwrap().key(), me.key());

    let own_uid = dir.path().metadata().unwrap().uid();
    assert_eq!(shell.info.uid, own_uid);
    assert!(shell.info.rss.is_some());
    assert!(shell.info.usage.is_some());
    assert!(shell.info.session.is_some());
    assert_eq!(shell.info.session, me.info.session);

    let shell_cmd = shell.cmdline().unwrap();
    assert_eq!(shell_cmd.argv, ["/bin/sh", "-c", script]);
    // `/bin/sh` is a platform binary: the kernel withholds its environment, so its identity
    // variables are unknown rather than absent.
    assert_eq!(shell_cmd.env, None);

    let children: Vec<_> = table.children_of(shell).collect();
    assert_eq!(children.len(), 1);
    let sleep = children[0];
    assert_eq!(sleep.parent(), Some(shell.key()));
    let cmd = sleep.cmdline().unwrap();
    assert_eq!(cmd.exe, "/bin/sleep");
    assert_eq!(cmd.argv, ["/bin/sleep", "30"]);
    assert_eq!(
        sleep.cwd().unwrap(),
        dir.path().canonicalize().unwrap().as_path()
    );

    // Signal the grandchild ourselves: dropping `sh` kills only the shell.
    assert!(platform::signal(sleep.key(), libc::SIGKILL).unwrap());
}

/// Privacy: a variable outside the allowlist never leaves the platform layer; the built-in
/// identity variables are read without the rules asking for them.
#[test]
fn env_outside_the_allowlist_is_never_read() {
    let child = Spawned::new(
        sleeper_cmd()
            .env("LEUKO_TEST_ALLOWED", "visible")
            .env("LEUKO_TEST_SECRET", SECRET)
            .env("CLAUDE_CODE_SESSION_ID", "session-test"),
    );
    let table = ProcessTable::snapshot(["LEUKO_TEST_ALLOWED"]).unwrap();
    let cmd = table.by_pid(child.pid()).unwrap().cmdline().unwrap();
    let env = cmd.env.as_ref().unwrap();

    assert_eq!(env.get("LEUKO_TEST_ALLOWED").unwrap(), "visible");
    assert_eq!(env.get("CLAUDE_CODE_SESSION_ID").unwrap(), "session-test");
    assert!(!env.contains_key("LEUKO_TEST_SECRET"));
    assert_eq!(env.len(), 2);
    assert!(!format!("{cmd:?}").contains(SECRET));

    let direct = platform::cmdline(child.key(), &Default::default()).unwrap();
    assert_eq!(direct.env, Some(Default::default()));
}

#[test]
fn a_withheld_env_is_unknown() {
    let child = Spawned::new(sleep_cmd().env("CLAUDE_PID", "1"));
    let table = ProcessTable::snapshot(Vec::<String>::new()).unwrap();
    let cmd = table.by_pid(child.pid()).unwrap().cmdline().unwrap();
    assert_eq!(cmd.argv, ["/bin/sleep", "30"]);
    assert_eq!(cmd.env, None);
}

#[test]
fn vanished_process_reads_as_none() {
    let mut child = Spawned::new(&mut sleep_cmd());
    let key = child.key();
    let table = ProcessTable::snapshot(Vec::<String>::new()).unwrap();
    assert!(table.get(key).is_some());

    assert!(platform::signal(key, libc::SIGKILL).unwrap());
    child.0.wait().unwrap();

    assert!(platform::base_info(key.pid).is_none());
    assert_eq!(platform::cmdline(key, &Default::default()), None);
    assert_eq!(platform::cwd(key), None);
    assert_eq!(platform::sockets(key), None);
    assert!(!platform::signal(key, libc::SIGTERM).unwrap());

    // Lazy facts first read after the process died are unknown, not empty.
    let process = table.get(key).unwrap();
    assert_eq!(process.cmdline(), None);
    assert_eq!(process.cwd(), None);
    assert_eq!(process.sockets(), None);
}

#[test]
fn a_reused_pid_is_a_different_process() {
    let mut child = Spawned::new(&mut sleep_cmd());
    let key = child.key();
    let stale = ProcKey {
        start: key.start + 1,
        ..key
    };

    assert_eq!(platform::cmdline(stale, &Default::default()), None);
    assert_eq!(platform::cwd(stale), None);
    assert_eq!(platform::sockets(stale), None);
    assert!(!platform::signal(stale, libc::SIGTERM).unwrap());
    assert!(child.0.try_wait().unwrap().is_none());
}

#[test]
fn signal_reaches_the_process() {
    let mut child = Spawned::new(&mut sleep_cmd());
    assert!(platform::signal(child.key(), libc::SIGTERM).unwrap());
    assert_eq!(child.0.wait().unwrap().signal(), Some(libc::SIGTERM));
}

/// launchd runs as root: the table shows its identity and parentage, and nothing the kernel
/// refuses to a user.
#[test]
fn another_uids_process_has_only_readable_facts() {
    let table = ProcessTable::snapshot(Vec::<String>::new()).unwrap();
    let launchd = table.by_pid(1).unwrap();
    assert_eq!(launchd.info.uid, 0);
    assert!(launchd.info.key.start > 0);
    assert_eq!(launchd.info.rss, None);
    assert_eq!(launchd.info.usage, None);
    assert_eq!(launchd.cmdline(), None);
    assert_eq!(launchd.cwd(), None);
    assert_eq!(launchd.sockets(), None);
}

#[test]
fn cpu_time_is_in_real_time_units() {
    let spin = Instant::now();
    let mut x = 0u64;
    while spin.elapsed() < Duration::from_millis(300) {
        x = x.wrapping_add(std::hint::black_box(1));
    }
    std::hint::black_box(x);

    let info = platform::base_info(own_pid()).unwrap();
    let cpu = info.usage.unwrap().cpu;
    let started = UNIX_EPOCH + Duration::from_micros(info.key.start);
    let alive = SystemTime::now().duration_since(started).unwrap();
    let cores = std::thread::available_parallelism().unwrap().get();
    let cores = u32::try_from(cores).unwrap();
    assert!(cpu >= Duration::from_millis(250), "cpu {cpu:?}");
    assert!(cpu <= alive * cores, "cpu {cpu:?} over {alive:?} alive");
}

#[test]
fn reaped_children_cpu_is_counted() {
    // No `exec` at the end: exec resets the reaped-children counters (observed 2026-11-26).
    let script = "(i=0; while [ $i -lt 100000 ]; do i=$((i+1)); done); /bin/sleep 30; true";
    let sh = Spawned::new(Command::new("/bin/sh").args(["-c", script]).env_clear());
    let pid = sh.pid();
    wait_for(|| {
        let usage = platform::base_info(pid)?.usage?;
        (usage.children_cpu >= Duration::from_millis(10)).then_some(())
    });
    // The busy subshell is gone; kill the `sleep` the shell started after it.
    let table = ProcessTable::snapshot(Vec::<String>::new()).unwrap();
    let shell = table.by_pid(pid).unwrap();
    for child in table.children_of(shell) {
        platform::signal(child.key(), libc::SIGKILL).unwrap();
    }
}
