//! The daemon driven in-process, on a temp `LEUKOCYTE_HOME`-style root, against processes the
//! tests spawn themselves. Only a test's own children are ever signalled.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use super::*;

/// A process the test spawned: `sh` waiting on a `sleep`, with `args` after the script so they
/// show in its argv. Killed and reaped on drop.
struct Spawned(Child);

impl Spawned {
    fn new(args: &[&str], cwd: Option<&Path>) -> Self {
        let mut cmd = Command::new("/bin/sh");
        // `; :` keeps the shell alive instead of exec'ing `sleep`.
        cmd.args(["-c", "sleep 60; :"])
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(cwd) = cwd {
            cmd.current_dir(cwd);
        }
        Self(crate::test_support::spawn(&mut cmd).unwrap())
    }

    fn pid(&self) -> i32 {
        i32::try_from(self.0.id()).unwrap()
    }
}

impl Drop for Spawned {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A marker unique to one test in this test run.
fn marker(test: &str) -> String {
    format!("lk-test-{test}-{}", std::process::id())
}

fn daemon(home: &Path) -> Daemon {
    Daemon::new(
        Paths::under(home),
        Notifier::Record(Vec::new()),
        Watches::none(),
    )
    .unwrap()
}

fn notifications(daemon: &Daemon) -> &[(String, String)] {
    match &daemon.notifier {
        Notifier::Record(sent) => sent,
        _ => panic!("not recording"),
    }
}

fn events(home: &Path) -> Vec<serde_json::Value> {
    fs::read_to_string(Paths::under(home).action_log())
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// Rules that report every process matching `needle`, as rule `name`.
fn report_rules(name: &str, needle: &str) -> String {
    format!(
        r#"return {{ api = 1, rules = {{
            {{ name = "{name}", match = "{needle}", judge = function(p) return "report", "seen" end }},
        }} }}"#
    )
}

/// The rules that reported on `pid`, in log order.
fn reports_on(home: &Path, pid: i32) -> Vec<String> {
    events(home)
        .iter()
        .filter(|e| e["event"] == "action" && e["kind"] == "report" && e["pid"] == pid)
        .map(|e| e["rule"].as_str().unwrap().to_owned())
        .collect()
}

fn mode_bits(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn a_fresh_home_starts_in_observe_mode() {
    let tmp = tempfile::tempdir().unwrap();
    let d = daemon(tmp.path());
    let text = fs::read_to_string(Paths::under(tmp.path()).config_file()).unwrap();
    assert!(text.contains("mode = \"observe\""), "{text}");
    assert_eq!(d.config.mode, ConfigMode::Observe);
    assert_eq!(d.status_reply().mode, ConfigMode::Observe);
    assert!(d.config.repos.is_empty());
}

#[test]
fn a_rules_edit_takes_effect_next_scan_and_a_broken_one_keeps_the_last_valid_rules() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths::under(tmp.path());
    let needle = marker("reload");
    let child = Spawned::new(&[&needle], None);
    let mut d = daemon(tmp.path());

    fs::write(paths.personal_rules(), report_rules("first", &needle)).unwrap();
    d.tick();
    assert_eq!(reports_on(tmp.path(), child.pid()), ["first"]);

    fs::write(
        paths.personal_rules(),
        "return { api = 1, rules = { { name = 1 } } }",
    )
    .unwrap();
    d.tick();
    let status = d.status_reply();
    assert!(status.personal.loaded);
    assert!(status.personal.error.is_some(), "{status:?}");
    assert_eq!(reports_on(tmp.path(), child.pid()), ["first", "first"]);
    let broken = events(tmp.path())
        .iter()
        .filter(|e| e["event"] == "rules_error")
        .count();
    assert_eq!(broken, 1);
    assert_eq!(notifications(&d).len(), 1, "{:?}", notifications(&d));

    // Still broken: neither logged nor notified again.
    d.tick();
    assert_eq!(notifications(&d).len(), 1);

    fs::write(paths.personal_rules(), report_rules("second", &needle)).unwrap();
    d.tick();
    assert_eq!(
        reports_on(tmp.path(), child.pid()),
        ["first", "first", "first", "second"]
    );
    assert!(d.status_reply().personal.error.is_none());
}

#[test]
fn repo_rules_judge_only_the_repos_processes_and_a_broken_repo_file_shows_in_status() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths::under(tmp.path());
    let repo = tmp.path().canonicalize().unwrap().join("repo");
    fs::create_dir_all(repo.join(".git")).unwrap();
    fs::create_dir_all(repo.join(".leukocyte")).unwrap();
    let needle = marker("repo");
    let rules = repo.join(".leukocyte/rules.lua");
    fs::write(&rules, report_rules("repo-rule", &needle)).unwrap();
    let missing = tmp.path().join("not-a-repo");
    let mut d = daemon(tmp.path());
    let config = Config {
        mode: ConfigMode::Observe,
        repos: vec![repo.clone(), missing],
    };
    config.write(&paths.config_file()).unwrap();

    let inside = Spawned::new(&[&needle], Some(&repo));
    let outside = Spawned::new(&[&needle], Some(tmp.path()));
    d.tick();
    assert_eq!(reports_on(tmp.path(), inside.pid()), ["repo-rule"]);
    assert!(reports_on(tmp.path(), outside.pid()).is_empty());

    let status = d.status_reply();
    assert_eq!(status.repos.len(), 2);
    assert!(status.repos[0].rules.loaded);
    assert!(status.repos[1].register_error.is_some());

    fs::write(&rules, "return {").unwrap();
    d.tick();
    let status = d.status_reply();
    assert!(status.repos[0].rules.loaded);
    assert!(status.repos[0].rules.error.is_some());
    assert_eq!(
        reports_on(tmp.path(), inside.pid()),
        ["repo-rule", "repo-rule"]
    );
}

#[test]
fn a_broken_config_keeps_the_previous_one() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths::under(tmp.path());
    let mut d = daemon(tmp.path());
    assert!(matches!(
        d.handle(Request::Mode {
            mode: ConfigMode::Enforce
        }),
        Response::Mode {
            mode: ConfigMode::Enforce
        }
    ));
    fs::write(paths.config_file(), "mode = \"loud\"").unwrap();
    d.reload();
    assert_eq!(d.config.mode, ConfigMode::Enforce);
    assert!(d.status_reply().config_error.is_some());
    assert_eq!(notifications(&d).len(), 1);
}

const SECRETS: [&str; 4] = [
    "sk-test-0123456789abcdef",
    "hunter2-plain-password",
    "ghp_abcdefghijklmnopqrstuvwxyz0123",
    "s3cr3t-in-url",
];

#[test]
fn argv_secrets_never_reach_the_log_status_or_check_and_the_files_are_private() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths::under(tmp.path());
    let needle = marker("privacy");
    let child = Spawned::new(
        &[
            &needle,
            &format!("--api-key={}", SECRETS[0]),
            "--password",
            SECRETS[1],
            SECRETS[2],
            &format!("https://user:{}@example.com/", SECRETS[3]),
        ],
        None,
    );
    let mut d = daemon(tmp.path());
    fs::write(paths.personal_rules(), report_rules("privacy", &needle)).unwrap();
    d.tick();

    let log = fs::read_to_string(paths.action_log()).unwrap();
    assert_eq!(reports_on(tmp.path(), child.pid()), ["privacy"], "{log}");
    assert!(
        log.contains(&needle),
        "the argv was not logged at all: {log}"
    );
    let Response::Check(check) = d.handle(Request::Check {
        repo_path: None,
        rules: None,
    }) else {
        panic!("check failed");
    };
    let explained = check
        .explanations
        .iter()
        .find(|e| e.pid == child.pid())
        .unwrap();
    assert!(explained.argv.as_ref().unwrap().contains(&needle));
    let Response::Check(adhoc) = d.handle(Request::Check {
        repo_path: None,
        rules: Some(report_rules("adhoc", &needle)),
    }) else {
        panic!("ad-hoc check failed");
    };
    assert!(adhoc.explanations.iter().any(|e| e.pid == child.pid()));
    let replies = [
        serde_json::to_string(&Response::Check(check)).unwrap(),
        serde_json::to_string(&Response::Check(adhoc)).unwrap(),
        serde_json::to_string(&d.handle(Request::Status)).unwrap(),
    ];
    for secret in SECRETS {
        assert!(!log.contains(secret), "{secret} in the action log: {log}");
        for reply in &replies {
            assert!(!reply.contains(secret), "{secret} in a reply: {reply}");
        }
    }

    assert_eq!(mode_bits(&paths.action_log()), 0o600);
    assert_eq!(mode_bits(&paths.data), 0o700);
    assert_eq!(mode_bits(&paths.logs), 0o700);
}

const SLEEPER_ARG: &str = "leukocyte-test-sleeper";

/// Not a test: the body of a long-lived process that is not an Apple binary, so macOS lets the
/// daemon read its environment. Acts only when started with `SLEEPER_ARG`.
#[test]
#[ignore = "helper: runs as a child process of the daemon tests"]
fn sleeper() {
    if std::env::args().any(|arg| arg == SLEEPER_ARG) {
        std::thread::sleep(Duration::from_secs(300));
    }
}

#[test]
fn identity_values_never_reach_the_log_status_or_check() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths::under(tmp.path());
    let repo = tmp.path().canonicalize().unwrap().join("repo");
    fs::create_dir_all(repo.join(".git")).unwrap();
    fs::create_dir_all(repo.join(".leukocyte")).unwrap();
    let needle = marker("identity");
    fs::write(
        repo.join(".leukocyte/rules.lua"),
        report_rules("identity", &needle),
    )
    .unwrap();
    let mut d = daemon(tmp.path());
    Config {
        mode: ConfigMode::Observe,
        repos: vec![repo.clone()],
    }
    .write(&paths.config_file())
    .unwrap();
    let agent_id = format!("sentinel-agent-{}", std::process::id());
    let session_id = format!("sentinel-session-{}", std::process::id());
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", "daemon::tests::sleeper", "--ignored", "--quiet"])
        .args([SLEEPER_ARG, &needle])
        .env("PASEO_AGENT_ID", &agent_id)
        .env("CLAUDE_CODE_SESSION_ID", &session_id)
        .current_dir(&repo)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = Spawned(crate::test_support::spawn(&mut cmd).unwrap());

    d.tick();
    d.tick();

    let log = fs::read_to_string(paths.action_log()).unwrap();
    assert_eq!(
        reports_on(tmp.path(), child.pid()),
        ["identity", "identity"],
        "{log}"
    );
    let check = |d: &mut Daemon, repo_path: Option<String>, rules: Option<String>| {
        let Response::Check(check) = d.handle(Request::Check { repo_path, rules }) else {
            panic!("check failed");
        };
        assert!(check.explanations.iter().any(|e| e.pid == child.pid()));
        serde_json::to_string(&Response::Check(check)).unwrap()
    };
    let outputs = [
        ("action log", log),
        ("check", check(&mut d, None, None)),
        (
            "check of the repo",
            check(&mut d, Some(repo.display().to_string()), None),
        ),
        (
            "ad-hoc check",
            check(&mut d, None, Some(report_rules("adhoc", &needle))),
        ),
        (
            "status",
            serde_json::to_string(&d.handle(Request::Status)).unwrap(),
        ),
        ("notifications", format!("{:?}", notifications(&d))),
    ];
    for value in [&agent_id, &session_id] {
        for (what, text) in &outputs {
            assert!(
                !text.contains(value.as_str()),
                "{value} in the {what}: {text}"
            );
        }
    }
}

#[test]
fn a_failing_rule_is_logged_and_notified_once_until_it_clears() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths::under(tmp.path());
    let needle = marker("evalerr");
    let _child = Spawned::new(&[&needle], None);
    let mut d = daemon(tmp.path());
    let failing = format!(
        r#"return {{ api = 1, rules = {{
            {{ name = "boom", match = "{needle}", judge = function(p) error("broken judge") end }},
        }} }}"#
    );
    fs::write(paths.personal_rules(), failing).unwrap();
    d.tick();
    d.tick();
    let logged = |home: &Path| {
        events(home)
            .iter()
            .filter(|e| e["event"] == "eval_error")
            .count()
    };
    assert_eq!(logged(tmp.path()), 1);
    assert_eq!(notifications(&d).len(), 1);
    assert_eq!(d.status_reply().eval_errors.len(), 1);

    fs::write(paths.personal_rules(), report_rules("boom", &needle)).unwrap();
    d.tick();
    assert!(d.status_reply().eval_errors.is_empty());
}

#[test]
fn keep_protects_a_running_process() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths::under(tmp.path());
    let needle = marker("keep");
    let child = Spawned::new(&[&needle], None);
    let mut d = daemon(tmp.path());
    fs::write(
        paths.personal_rules(),
        format!(
            r#"return {{ api = 1, rules = {{
                {{ name = "k", match = "{needle}", when = "always", quarantine = "1h" }},
            }} }}"#
        ),
    )
    .unwrap();
    d.tick();
    let state = |d: &mut Daemon| {
        let Response::Check(check) = d.handle(Request::Check {
            repo_path: None,
            rules: None,
        }) else {
            panic!("check failed");
        };
        let e = check
            .explanations
            .into_iter()
            .find(|e| e.pid == child.pid())
            .unwrap();
        e.state
    };
    assert_eq!(state(&mut d), "quarantined");
    let Response::Kept { pid, .. } = d.handle(Request::Keep { pid: child.pid() }) else {
        panic!("keep failed");
    };
    assert_eq!(pid, child.pid());
    assert_eq!(state(&mut d), "protected");
}

#[test]
fn check_refuses_an_unregistered_repo() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir_all(repo.join(".git")).unwrap();
    let mut d = daemon(tmp.path());
    d.tick();
    let reply = d.handle(Request::Check {
        repo_path: Some(repo.display().to_string()),
        rules: None,
    });
    assert!(matches!(reply, Response::Error { .. }), "{reply:?}");
}

#[test]
fn an_enforced_kill_is_tracked_in_flight_and_its_report_logged() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths::under(tmp.path());
    let needle = marker("kill");
    let mut child = Spawned::new(&[&needle], None);
    let mut d = daemon(tmp.path());
    fs::write(
        paths.personal_rules(),
        format!(
            r#"return {{ api = 1, rules = {{
                {{ name = "kill-it", match = "{needle}", when = "always", quarantine = "0s",
                   grace = "1s", enforce = true }},
            }} }}"#
        ),
    )
    .unwrap();
    d.handle(Request::Mode {
        mode: ConfigMode::Enforce,
    });
    d.tick();
    let kills: Vec<_> = events(tmp.path())
        .into_iter()
        .filter(|e| e["event"] == "action" && e["kind"] == "kill")
        .collect();
    assert_eq!(kills.len(), 1, "{kills:?}");
    assert_eq!(kills[0]["pid"], child.pid());
    assert!(d.in_flight.contains_key(&ProcKey {
        pid: child.pid(),
        start: kills[0]["start"].as_u64().unwrap(),
    }));
    assert_eq!(d.status_reply().in_flight.len(), 1);

    let deadline = Instant::now() + Duration::from_secs(10);
    while !d.in_flight.is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        d.tick();
    }
    assert!(d.in_flight.is_empty());
    let report = events(tmp.path())
        .into_iter()
        .find(|e| e["event"] == "kill_report")
        .unwrap();
    assert_eq!(report["rule"], "kill-it");
    assert!(
        report["report"]["signalled"]
            .as_array()
            .unwrap()
            .contains(&child.pid().into())
    );
    assert!(child.0.wait().is_ok());
}
