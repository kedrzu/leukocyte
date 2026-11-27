//! End to end: the real binary as a daemon under a temp `LEUKOCYTE_HOME`, in enforce mode, with
//! a registered repo whose enforcing rule matches a marker unique to this run. Only processes
//! this test spawns carry the marker, so the daemon can match nothing else; each spawned tree
//! runs in its own process group, killed whole when its guard drops, even on failure.
//!
//! Also loads the shipped example rules, so they cannot drift from the loader.

use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use leukocyte::facts::ProcKey;
use leukocyte::platform;
use leukocyte::rules::RuleSet;
use tempfile::TempDir;

mod common;

#[cfg(test)]
mod support {
    use super::*;

    const BIN: &str = env!("CARGO_BIN_EXE_leukocyte");
    pub const SCAN_MS: u64 = 150;

    /// A temporary directory holding the `LEUKOCYTE_HOME` and the test repo.
    pub struct Home {
        pub tmp: TempDir,
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
                .env("LEUKOCYTE_SCAN_INTERVAL_MS", SCAN_MS.to_string())
                .stdin(Stdio::null());
            cmd
        }

        /// Runs a command to completion; panics with its stderr when it fails.
        pub fn run(&self, args: &[&str]) -> String {
            let out = common::output(&mut self.command(args)).unwrap();
            assert!(
                out.status.success(),
                "leukocyte {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).into_owned()
        }

        pub fn events(&self) -> Vec<serde_json::Value> {
            fs::read_to_string(self.tmp.path().join("home/logs/actions.jsonl"))
                .unwrap_or_default()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        }

        pub fn start_daemon(&self) -> Group {
            let guard = Group(
                common::spawn(
                    self.command(&["daemon"])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .process_group(0),
                )
                .unwrap(),
            );
            wait_for("the daemon's first scan", Duration::from_secs(15), || {
                common::output(&mut self.command(&["status"])).is_ok_and(|out| {
                    out.status.success()
                        && !String::from_utf8_lossy(&out.stdout).contains("scan:     none yet")
                })
            });
            guard
        }
    }

    /// A child in its own process group: the whole group is killed and the child reaped when
    /// dropped.
    pub struct Group(pub Child);

    impl Group {
        pub fn pid(&self) -> i32 {
            i32::try_from(self.0.id()).unwrap()
        }

        /// Kills and reaps the leader only, leaving the rest of its group running.
        pub fn kill_leader(&mut self) {
            self.0.kill().unwrap();
            self.0.wait().unwrap();
        }
    }

    impl Drop for Group {
        fn drop(&mut self) {
            let _ = common::status(
                Command::new("/bin/kill")
                    .args(["-KILL", "--", &format!("-{}", self.pid())])
                    // A group already gone, or left with only its zombie leader, answers an error.
                    .stderr(Stdio::null()),
            );
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// A fake agent: `/bin/sh` started with argv0 `claude`, in `cwd`, that stays alive. It
    /// starts an intermediate shell, which starts the tree (a shell carrying `marker` in its
    /// argv, with two `sleep` children) and exits once the file `go` exists, orphaning the
    /// tree. The tree writes its pids to `pids`, its shell first.
    ///
    /// The scripts reach the shells through the environment, so only the tree's shell has the
    /// marker in its argv.
    pub fn spawn_agent(cwd: &Path, marker: &str, pids: &Path, go: &Path) -> Group {
        let tree = format!(
            r#": {marker}; echo $$ >> "$LK_PIDS"; sleep 300 & echo $! >> "$LK_PIDS"; sleep 300 & echo $! >> "$LK_PIDS"; wait"#
        );
        let middle = r#"sh -c "$LK_TREE" & while [ ! -e "$LK_GO" ]; do sleep 0.05; done"#;
        Group(
            common::spawn(
                Command::new("/bin/sh")
                    .arg0("claude")
                    .args(["-c", r#"sh -c "$LK_MIDDLE" & sleep 300; :"#])
                    .env("LK_TREE", tree)
                    .env("LK_MIDDLE", middle)
                    .env("LK_PIDS", pids)
                    .env("LK_GO", go)
                    .current_dir(cwd)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .process_group(0),
            )
            .unwrap(),
        )
    }

    /// The keys of the pids in `file` once it holds `count` of them.
    pub fn read_keys(file: &Path, count: usize) -> Vec<ProcKey> {
        let mut keys = Vec::new();
        wait_for("the tree's pids", Duration::from_secs(10), || {
            let text = fs::read_to_string(file).unwrap_or_default();
            let pids: Vec<i32> = text.lines().filter_map(|l| l.trim().parse().ok()).collect();
            if pids.len() < count {
                return false;
            }
            keys = pids
                .iter()
                .map(|pid| platform::base_info(*pid).unwrap().key)
                .collect();
            true
        });
        keys
    }

    pub fn wait_for(what: &str, timeout: Duration, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + timeout;
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// A marker no other process on the machine carries.
    pub fn marker() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        format!("lk-e2e-marker-{}-{nanos}", std::process::id())
    }
}

use support::*;

#[test]
fn the_example_rules_load() {
    for (file, rules) in [
        ("examples/repo-rules.lua", 3),
        ("examples/personal-rules.lua", 2),
    ] {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(file);
        let set = RuleSet::load_file(&path).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(set.rules().len(), rules, "{file}");
    }
}

/// The path that matters: an enforcing rule of a registered repo leaves an orphaned matching
/// tree alone while the agent that started it lives, and kills the whole tree once the agent
/// is dead and the quarantine is over.
#[test]
fn an_abandoned_tree_is_killed_only_after_its_agent_dies() {
    const QUARANTINE: Duration = Duration::from_secs(1);
    const GRACE: Duration = Duration::from_secs(1);
    const RULE: &str = "e2e abandoned tree";

    let home = Home::new();
    let repo = home.root().join("repo");
    fs::create_dir_all(repo.join(".git")).unwrap();
    fs::create_dir_all(repo.join(".leukocyte")).unwrap();
    let marker = marker();
    fs::write(
        repo.join(".leukocyte/rules.lua"),
        format!(
            r#"return {{ api = 1, rules = {{
                {{ name = "{RULE}", match = "{marker}", when = "abandoned",
                   quarantine = "1s", grace = "1s", enforce = true }},
            }} }}"#
        ),
    )
    .unwrap();
    home.run(&["add", repo.to_str().unwrap()]);
    home.run(&["mode", "enforce"]);
    let _daemon = home.start_daemon();
    let status = home.run(&["status"]);
    assert!(status.contains("mode: enforce"), "{status}");
    assert!(status.contains("1 rule loaded"), "{status}");

    let pids = home.root().join("tree.pids");
    let go = home.root().join("go");
    let mut agent = spawn_agent(&repo, &marker, &pids, &go);
    let tree = read_keys(&pids, 3);
    let shell = tree[0];
    let middle = platform::base_info(shell.pid).unwrap().ppid;
    assert_eq!(
        platform::base_info(middle).unwrap().ppid,
        agent.pid(),
        "agent -> middle -> tree"
    );

    // The daemon sees the tree while its chain to the agent is intact, and records the agent
    // as its origin.
    wait_for(
        "the daemon to judge the tree",
        Duration::from_secs(10),
        || {
            home.run(&["check"])
                .contains(&format!("pid     {}", shell.pid))
        },
    );
    // The middle shell exits: the tree is orphaned while its agent lives, and stays alone
    // well past the quarantine.
    fs::write(&go, "").unwrap();
    wait_for("the tree to be orphaned", Duration::from_secs(5), || {
        platform::base_info(shell.pid).is_some_and(|info| info.ppid == 1)
    });
    std::thread::sleep(QUARANTINE + Duration::from_millis(SCAN_MS * 6));
    let check = home.run(&["check"]);
    assert!(
        check.contains(&format!("pid     {}", shell.pid))
            && check.contains("when = Abandoned does not hold"),
        "{check}"
    );
    assert!(tree.iter().all(|k| platform::alive(*k)), "{check}");
    let kills = |events: &[serde_json::Value]| {
        events
            .iter()
            .filter(|e| e["kind"] == "kill" || e["event"] == "kill_report")
            .count()
    };
    assert_eq!(kills(&home.events()), 0, "{:#?}", home.events());

    // The agent dies; its tree is orphaned and abandoned, and is killed whole.
    agent.kill_leader();
    let killed_within = QUARANTINE + GRACE + Duration::from_secs(5);
    wait_for("the tree to be killed", killed_within, || {
        tree.iter().all(|k| !platform::alive(*k))
    });

    let events = home.events();
    let kill = events
        .iter()
        .find(|e| e["event"] == "action" && e["kind"] == "kill")
        .unwrap_or_else(|| panic!("no kill action: {events:#?}"));
    assert_eq!(kill["rule"], RULE);
    assert_eq!(kill["pid"], shell.pid);
    let reason = kill["reason"].as_str().unwrap();
    assert!(reason.contains("origin agent dead"), "{reason}");
    let mut subtree: Vec<i64> = kill["subtree"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_i64().unwrap())
        .collect();
    subtree.sort_unstable();
    let mut expected: Vec<i64> = tree.iter().map(|k| i64::from(k.pid)).collect();
    expected.sort_unstable();
    assert_eq!(subtree, expected);

    wait_for("the kill report", Duration::from_secs(5), || {
        home.events().iter().any(|e| e["event"] == "kill_report")
    });
    let events = home.events();
    let report = events.iter().find(|e| e["event"] == "kill_report").unwrap();
    assert_eq!(report["rule"], RULE);
    assert_eq!(report["report"]["aborted"], false, "{report:#}");
    assert_eq!(report["report"]["survivors_after"], serde_json::json!([]));
    assert_eq!(kills(&events), 2, "one kill and its report: {events:#?}");
}
