//! Runs the `leukocyte` binary under a temp `LEUKOCYTE_HOME`, with real daemons and processes
//! the tests spawn themselves. Only those are ever signalled, and each is killed and reaped
//! when its guard drops, even when a test fails. `install` and `uninstall` are never run
//! except to see them refuse.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

mod common;

#[cfg(test)]
mod support {
    use super::*;

    const BIN: &str = env!("CARGO_BIN_EXE_leukocyte");

    /// A `LEUKOCYTE_HOME`, and a git repo next to it.
    pub struct Home {
        pub tmp: TempDir,
    }

    pub struct Ran {
        pub ok: bool,
        pub out: String,
        pub err: String,
    }

    impl Home {
        pub fn new() -> Self {
            Self {
                tmp: tempfile::tempdir().unwrap(),
            }
        }

        pub fn root(&self) -> PathBuf {
            self.tmp.path().canonicalize().unwrap()
        }

        pub fn command(&self, args: &[&str]) -> Command {
            let mut cmd = Command::new(BIN);
            cmd.args(args)
                .env("LEUKOCYTE_HOME", self.tmp.path().join("home"))
                .env("LEUKOCYTE_SCAN_INTERVAL_MS", "150")
                .stdin(Stdio::null());
            cmd
        }

        pub fn run(&self, args: &[&str]) -> Ran {
            let Output {
                status,
                stdout,
                stderr,
            } = common::output(&mut self.command(args)).unwrap();
            Ran {
                ok: status.success(),
                out: String::from_utf8_lossy(&stdout).into_owned(),
                err: String::from_utf8_lossy(&stderr).into_owned(),
            }
        }

        /// A directory with a `.git` directory, named `name`.
        pub fn repo(&self, name: &str) -> PathBuf {
            let repo = self.root().join(name);
            fs::create_dir_all(repo.join(".git")).unwrap();
            repo
        }

        pub fn action_log(&self) -> String {
            fs::read_to_string(self.tmp.path().join("home/logs/actions.jsonl")).unwrap_or_default()
        }

        pub fn start_daemon(&self) -> DaemonGuard {
            let child = common::spawn(
                self.command(&["daemon"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null()),
            )
            .unwrap();
            let guard = DaemonGuard(child);
            wait_for("the daemon's first scan", || {
                let status = self.run(&["status"]);
                status.ok && !status.out.contains("scan:     none yet")
            });
            guard
        }
    }

    pub struct DaemonGuard(Child);

    impl Drop for DaemonGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// `sh` waiting on a `sleep`, with `marker` in its argv, run in `cwd`.
    pub struct Spawned(Child);

    impl Spawned {
        pub fn new(marker: &str, cwd: &Path) -> Self {
            Self(
                common::spawn(
                    Command::new("/bin/sh")
                        // `; :` keeps the shell alive instead of exec'ing `sleep`.
                        .args(["-c", "sleep 60; :", marker])
                        .current_dir(cwd)
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null()),
                )
                .unwrap(),
            )
        }

        pub fn pid(&self) -> String {
            self.0.id().to_string()
        }

        pub fn alive(&mut self) -> bool {
            self.0.try_wait().unwrap().is_none()
        }
    }

    impl Drop for Spawned {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    pub fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    pub fn rules(name: &str, marker: &str, extra: &str) -> String {
        format!(
            r#"return {{ api = 1, rules = {{
                {{ name = "{name}", match = "{marker}", when = "always", quarantine = "0s",
                   grace = "1s", {extra} }},
            }} }}"#
        )
    }

    pub fn marker(test: &str) -> String {
        format!("lk-cli-{test}-{}", std::process::id())
    }
}

use support::*;

#[test]
fn version_and_help() {
    let home = Home::new();
    let v = home.run(&["--version"]);
    assert!(v.ok);
    assert_eq!(
        v.out.trim(),
        format!("leukocyte {}", env!("CARGO_PKG_VERSION"))
    );
    assert!(home.run(&["--help"]).out.contains("check"));
    assert!(!home.run(&["nonsense"]).ok);
}

#[test]
fn add_registers_a_repo_and_status_shows_it() {
    let home = Home::new();
    let repo = home.repo("repo");
    fs::create_dir_all(repo.join(".leukocyte")).unwrap();
    fs::write(
        repo.join(".leukocyte/rules.lua"),
        rules("r", "never-matches-anything", "enforce = false"),
    )
    .unwrap();
    let _daemon = home.start_daemon();

    let added = home.run(&["add", repo.to_str().unwrap()]);
    assert!(added.ok, "{}", added.err);
    assert!(added.out.contains("1 rules load"), "{}", added.out);
    let again = home.run(&["add", repo.to_str().unwrap()]);
    assert!(again.ok && again.out.contains("already registered"));

    wait_for("the daemon to load the repo's rules", || {
        home.run(&["status"]).out.contains("1 rule loaded")
    });
    let status = home.run(&["status"]);
    assert!(status.out.contains("mode: observe"), "{}", status.out);
    assert!(status.out.contains(&repo.display().to_string()));
    assert!(status.out.contains("personal: no rules file"));

    let removed = home.run(&["remove", repo.to_str().unwrap()]);
    assert!(removed.ok, "{}", removed.err);
    assert!(!home.run(&["remove", repo.to_str().unwrap()]).ok);
    wait_for("the daemon to drop the repo", || {
        home.run(&["status"]).out.contains("repos:    none")
    });
}

#[test]
fn add_refuses_a_non_repo_and_warns_about_broken_rules() {
    let home = Home::new();
    let plain = home.root().join("plain");
    fs::create_dir_all(&plain).unwrap();
    let refused = home.run(&["add", plain.to_str().unwrap()]);
    assert!(!refused.ok);
    assert!(refused.err.contains("has no .git"));
    assert!(!home.run(&["add", "/no/such/dir"]).ok);

    let repo = home.repo("broken");
    fs::create_dir_all(repo.join(".leukocyte")).unwrap();
    fs::write(repo.join(".leukocyte/rules.lua"), "return {").unwrap();
    let added = home.run(&["add", repo.to_str().unwrap()]);
    assert!(added.ok, "a broken rules file still registers");
    assert!(added.err.contains("WARNING"), "{}", added.err);
    assert!(added.out.contains("registered"));
}

#[test]
fn status_without_a_daemon_says_how_to_start_one() {
    let home = Home::new();
    let status = home.run(&["status"]);
    assert!(!status.ok);
    assert!(status.err.contains("not running"));
    assert!(status.err.contains("leukocyte install"));
}

#[test]
fn check_with_an_adhoc_file_explains_without_registering_it() {
    let home = Home::new();
    let repo = home.repo("repo");
    let needle = marker("adhoc");
    let process = Spawned::new(&needle, &repo);
    assert!(home.run(&["add", repo.to_str().unwrap()]).ok);
    let _daemon = home.start_daemon();

    let adhoc = repo.join("try.lua");
    fs::write(&adhoc, rules("try-it", &needle, "")).unwrap();
    wait_for("the process to be judged", || {
        home.run(&["check", adhoc.to_str().unwrap()])
            .out
            .contains("try-it")
    });
    let checked = home.run(&["check", adhoc.to_str().unwrap()]);
    assert!(checked.ok, "{}", checked.err);
    assert!(checked.out.contains("pid     "), "{}", checked.out);
    assert!(checked.out.contains(&process.pid()));
    assert!(checked.out.contains(&needle));

    // The registered rules (none) match nothing.
    assert!(
        home.run(&["check"])
            .out
            .contains("no process matches a rule")
    );

    // A file in a repo that is not registered is refused, with the way to register it.
    let other = home.repo("other");
    let stray = other.join("try.lua");
    fs::write(&stray, rules("x", &needle, "")).unwrap();
    let refused = home.run(&["check", stray.to_str().unwrap()]);
    assert!(!refused.ok);
    assert!(refused.err.contains("leukocyte add"), "{}", refused.err);

    // A file outside any repo, and a broken one.
    let outside = std::env::temp_dir().join(format!("lk-cli-outside-{}.lua", std::process::id()));
    fs::write(&outside, "return {}").unwrap();
    let not_in_repo = home.run(&["check", outside.to_str().unwrap()]);
    let _ = fs::remove_file(&outside);
    assert!(!not_in_repo.ok && not_in_repo.err.contains("not inside a git repo"));
    fs::write(&adhoc, "return {").unwrap();
    let broken = home.run(&["check", adhoc.to_str().unwrap()]);
    assert!(
        !broken.ok && broken.err.contains("do not load"),
        "{}",
        broken.err
    );
}

/// `check` goes through `Engine::explain`, which never acts: even in enforce mode, with a rule
/// whose quarantine is over, it signals nothing. The registered rule is `enforce = false` so
/// the daemon's own scans do not kill the process either; the ad-hoc file asks for a kill.
#[test]
fn check_never_kills_even_in_enforce_mode() {
    let home = Home::new();
    let repo = home.repo("repo");
    let needle = marker("protect");
    fs::create_dir_all(repo.join(".leukocyte")).unwrap();
    fs::write(
        repo.join(".leukocyte/rules.lua"),
        rules("registered", &needle, "enforce = false"),
    )
    .unwrap();
    let mut process = Spawned::new(&needle, &repo);
    assert!(home.run(&["add", repo.to_str().unwrap()]).ok);
    assert!(home.run(&["mode", "enforce"]).ok);
    let _daemon = home.start_daemon();
    assert!(
        home.run(&["status"]).out.contains("mode: enforce"),
        "the daemon runs in enforce mode"
    );

    let adhoc = repo.join("kill.lua");
    fs::write(&adhoc, rules("kill-it", &needle, "enforce = true")).unwrap();
    wait_for("the adhoc rule to be kill-ready", || {
        home.run(&["check", adhoc.to_str().unwrap()])
            .out
            .starts_with("kill-ready")
    });
    for _ in 0..5 {
        let checked = home.run(&["check", adhoc.to_str().unwrap()]);
        assert!(checked.out.starts_with("kill-ready"), "{}", checked.out);
        std::thread::sleep(Duration::from_millis(150));
    }
    assert!(process.alive(), "check must not signal the process");

    // The daemon itself kept judging it all along, as the registered rule says: would kill.
    wait_for("the registered rule's would-kill", || {
        home.action_log().contains(r#""kind":"would_kill""#)
    });
    for line in home.action_log().lines() {
        let event: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_ne!(event["kind"], "kill", "{line}");
        assert_ne!(event["event"], "kill_report", "{line}");
    }
    assert!(process.alive());
}

#[test]
fn mode_goes_through_the_daemon_or_the_config() {
    let home = Home::new();
    let config = home.tmp.path().join("home/config/config.toml");

    let offline = home.run(&["mode", "enforce"]);
    assert!(offline.ok, "{}", offline.err);
    assert!(offline.out.contains("not running"), "{}", offline.out);
    assert!(fs::read_to_string(&config).unwrap().contains("enforce"));
    assert!(!home.run(&["mode", "kill"]).ok);

    let _daemon = home.start_daemon();
    assert!(home.run(&["status"]).out.contains("mode: enforce"));
    let online = home.run(&["mode", "observe"]);
    assert!(
        online.ok && online.out.contains("mode: observe"),
        "{}",
        online.out
    );
    assert!(fs::read_to_string(&config).unwrap().contains("observe"));
    assert!(home.run(&["status"]).out.contains("mode: observe"));
}

#[test]
fn keep_names_the_process() {
    let home = Home::new();
    let process = Spawned::new(&marker("keep"), &home.root());
    assert!(!home.run(&["keep", &process.pid()]).ok, "no daemon yet");
    let _daemon = home.start_daemon();
    let kept = home.run(&["keep", &process.pid()]);
    assert!(kept.ok, "{}", kept.err);
    assert!(kept.out.contains(&process.pid()));
    assert!(!home.run(&["keep", "2147483000"]).ok);
}

#[test]
fn log_prints_events_one_per_line() {
    let home = Home::new();
    let empty = home.run(&["log"]);
    assert!(empty.ok && empty.out.contains("no actions logged yet"));

    let repo = home.repo("repo");
    assert!(home.run(&["add", repo.to_str().unwrap()]).ok);
    let _daemon = home.start_daemon();
    wait_for("the log to hold an event", || !home.action_log().is_empty());
    let log = home.run(&["log"]);
    assert!(log.ok, "{}", log.err);
    assert!(!log.out.contains('{'), "events are rendered: {}", log.out);
    assert_eq!(log.out.lines().count(), home.action_log().lines().count());
}

#[test]
fn install_and_uninstall_refuse_under_leukocyte_home() {
    let home = Home::new();
    for command in ["install", "uninstall"] {
        let ran = home.run(&[command]);
        assert!(!ran.ok);
        assert!(
            ran.err.contains("LEUKOCYTE_HOME is set: refusing"),
            "{}",
            ran.err
        );
    }
}
