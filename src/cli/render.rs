//! Human-readable text for what the daemon answers: `status`, `check` and the action log.

use std::fmt::Write as _;

use serde_json::Value;

use crate::daemon::ConfigMode;
use crate::daemon::ipc::{CheckReply, ExplanationReply, SourceStatus, StatusReply};
use crate::platform::NotifyState;
use crate::platform::notify;

pub fn mode_name(mode: ConfigMode) -> &'static str {
    match mode {
        ConfigMode::Observe => "observe",
        ConfigMode::Enforce => "enforce",
    }
}

fn source_state(s: &SourceStatus) -> String {
    let rules = |n: usize| format!("{n} rule{}", if n == 1 { "" } else { "s" });
    match (&s.error, s.loaded) {
        (None, true) => format!("{} loaded", rules(s.rule_count)),
        (None, false) => "no rules file".to_owned(),
        (Some(e), true) => format!(
            "{} in force, but the file now fails to load: {e}",
            rules(s.rule_count)
        ),
        (Some(e), false) => format!("not loaded: {e}"),
    }
}

pub fn status(s: &StatusReply) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "leukocyte {} (pid {}), mode: {}",
        s.version,
        s.pid,
        mode_name(s.mode)
    );
    if let Some(e) = &s.config_error {
        let _ = writeln!(
            out,
            "config:   REJECTED, the previous one stays in force: {e}"
        );
    }
    match &s.last_scan {
        None => out.push_str("scan:     none yet\n"),
        Some(scan) => {
            let _ = write!(
                out,
                "scan:     {}, {} ms, {} processes",
                scan.at, scan.duration_ms, scan.processes
            );
            if let Some(e) = &scan.error {
                let _ = write!(out, ", FAILED: {e}");
            }
            out.push('\n');
        }
    }
    if s.repos.is_empty() {
        out.push_str("repos:    none (leukocyte add <repo>)\n");
    } else {
        out.push_str("repos:\n");
        for repo in &s.repos {
            let state = match &repo.register_error {
                Some(e) => format!("cannot be registered: {e}"),
                None => source_state(&repo.rules),
            };
            let _ = writeln!(out, "  {}: {state}", repo.path);
        }
    }
    let _ = writeln!(
        out,
        "personal: {} ({})",
        source_state(&s.personal),
        s.personal.file
    );
    if s.in_flight.is_empty() {
        out.push_str("kills in flight: none\n");
    } else {
        out.push_str("kills in flight:\n");
        for k in &s.in_flight {
            let _ = writeln!(
                out,
                "  pid {} ({} processes), rule {} from {}",
                k.pid, k.subtree, k.rule, k.source
            );
        }
    }
    if let Some(f) = &s.fuse {
        let _ = writeln!(
            out,
            "fuse:     last tripped {}, holding back {} kills",
            f.at, f.kills
        );
    }
    match &s.notifications {
        None => {}
        Some(state @ (NotifyState::Denied | NotifyState::NotAsked)) => {
            let _ = writeln!(out, "notify:   {state}: {}", notify::SETTINGS_HINT);
        }
        Some(state) => {
            let _ = writeln!(out, "notify:   {state}");
        }
    }
    if !s.eval_errors.is_empty() {
        out.push_str("rule errors:\n");
        for e in &s.eval_errors {
            let _ = writeln!(
                out,
                "  {} / {} since {}: {}",
                e.source, e.rule, e.since, e.message
            );
        }
    }
    out
}

/// The state of a candidate as one phrase.
fn state_label(e: &ExplanationReply) -> String {
    let detail = e.detail.as_deref().unwrap_or("");
    match e.state.as_str() {
        "kill_ready" => "kill-ready".to_owned(),
        "would_kill" => "would kill (observe mode / enforce=false)".to_owned(),
        "quarantined" => format!("quarantined ({detail})"),
        "protected" => format!("protected ({detail})"),
        "report_only" => "report only".to_owned(),
        "no_verdict" => format!("no verdict: {detail}"),
        other => other.to_owned(),
    }
}

pub fn check(reply: &CheckReply) -> String {
    let mut out = String::new();
    if reply.explanations.is_empty() && reply.eval_errors.is_empty() {
        out.push_str("no process matches a rule\n");
    }
    for e in &reply.explanations {
        let _ = writeln!(out, "{}", state_label(e));
        let _ = writeln!(out, "  rule    {} ({})", e.rule, e.source);
        let _ = writeln!(out, "  pid     {}", e.pid);
        if let Some(exe) = &e.exe {
            let _ = writeln!(out, "  exe     {exe}");
        }
        if let Some(argv) = &e.argv {
            let _ = writeln!(out, "  cmd     {}", argv.join(" "));
        }
        if let Some(reason) = &e.reason {
            let _ = writeln!(out, "  reason  {reason}");
        }
        out.push('\n');
    }
    for e in &reply.eval_errors {
        let _ = writeln!(
            out,
            "eval error: {} / {} on pid {}: {}",
            e.source, e.rule, e.pid, e.message
        );
    }
    out
}

/// One action-log line as one readable line; a line that is not an event is returned as is.
pub fn log_line(line: &str) -> String {
    let Ok(Value::Object(event)) = serde_json::from_str::<Value>(line) else {
        return line.to_owned();
    };
    let text = |key: &str| event.get(key).and_then(Value::as_str);
    let mut label = text("event").unwrap_or("?").to_owned();
    if let Some(kind) = text("kind") {
        label = format!("{label}/{kind}");
    }
    let mut out = format!("{}  {label:<18}", text("ts").unwrap_or("?"));
    if let Some(rule) = text("rule") {
        let _ = write!(out, " rule={rule}");
    }
    if let Some(pid) = event.get("pid").and_then(Value::as_i64) {
        let _ = write!(out, " pid={pid}");
    }
    if let Some(exe) = text("exe") {
        let _ = write!(out, " exe={exe}");
    }
    if let Some(Value::Array(argv)) = event.get("argv") {
        let argv: Vec<&str> = argv.iter().filter_map(Value::as_str).collect();
        let _ = write!(out, " cmd={}", argv.join(" "));
    }
    if let Some(n) = event.get("kills").and_then(Value::as_u64) {
        let _ = write!(out, " held_back={n}");
    }
    if let Some(Value::Array(subtree)) = event.get("subtree") {
        let _ = write!(out, " subtree={}", subtree.len());
    }
    if let Some(report) = event.get("report") {
        let count = |key: &str| {
            report
                .get(key)
                .and_then(Value::as_array)
                .map_or(0, Vec::len)
        };
        let _ = write!(
            out,
            " signalled={} escalated={} skipped={} survivors={} failed={}",
            count("signalled"),
            count("escalated"),
            count("skipped"),
            count("survivors_after"),
            count("failed")
        );
    }
    if let Some(source) = text("source") {
        let _ = write!(out, " source={source}");
    }
    if let Some(reason) = text("reason") {
        let _ = write!(out, " -- {reason}");
    }
    if let Some(message) = text("message") {
        let _ = write!(out, " -- {message}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::ipc::{CheckEvalError, RepoStatus};

    fn explanation(state: &str, detail: Option<&str>) -> ExplanationReply {
        ExplanationReply {
            pid: 42,
            start: 1,
            exe: Some("/usr/bin/node".to_owned()),
            argv: Some(vec!["node".to_owned(), "--token=***".to_owned()]),
            state: state.to_owned(),
            detail: detail.map(str::to_owned),
            rule: "nx".to_owned(),
            source: "/r/rules.lua".to_owned(),
            reason: Some("orphaned".to_owned()),
            matched: Vec::new(),
        }
    }

    #[test]
    fn every_state_has_a_label() {
        let label = |s, d| state_label(&explanation(s, d));
        assert_eq!(label("kill_ready", None), "kill-ready");
        assert!(label("would_kill", None).starts_with("would kill"));
        assert_eq!(
            label("quarantined", Some("3m12s left")),
            "quarantined (3m12s left)"
        );
        assert_eq!(
            label("protected", Some("kept by owner on pid 9")),
            "protected (kept by owner on pid 9)"
        );
        assert_eq!(label("report_only", None), "report only");
        assert_eq!(
            label("no_verdict", Some("idle 1m of the 20m needed")),
            "no verdict: idle 1m of the 20m needed"
        );
    }

    #[test]
    fn check_lists_candidates_and_errors() {
        let text = check(&CheckReply {
            explanations: vec![explanation("kill_ready", None)],
            eval_errors: vec![CheckEvalError {
                source: "s".to_owned(),
                rule: "r".to_owned(),
                pid: 7,
                message: "boom".to_owned(),
            }],
        });
        assert!(text.starts_with("kill-ready\n"));
        assert!(text.contains("  cmd     node --token=***\n"));
        assert!(text.contains("eval error: s / r on pid 7: boom"));
        assert_eq!(check(&CheckReply::default()), "no process matches a rule\n");
    }

    #[test]
    fn status_shows_the_notification_state_with_a_hint_when_it_is_off() {
        let line = |state: Option<NotifyState>| {
            status(&StatusReply {
                notifications: state,
                ..StatusReply::default()
            })
            .lines()
            .find(|l| l.starts_with("notify:"))
            .map(str::to_owned)
        };
        assert_eq!(line(None), None);
        assert_eq!(
            line(Some(NotifyState::Allowed)).unwrap(),
            "notify:   allowed"
        );
        let hint = "enable in System Settings → Notifications → leukocyte";
        assert_eq!(
            line(Some(NotifyState::Denied)).unwrap(),
            format!("notify:   denied: {hint}")
        );
        assert_eq!(
            line(Some(NotifyState::NotAsked)).unwrap(),
            format!("notify:   not asked: {hint}")
        );
        assert_eq!(
            line(Some(NotifyState::Unavailable("x".to_owned()))).unwrap(),
            "notify:   unavailable (x)"
        );
    }

    #[test]
    fn status_shows_every_source_state() {
        let broken = SourceStatus {
            file: "f".to_owned(),
            loaded: true,
            rule_count: 2,
            error: Some("bad".to_owned()),
        };
        let text = status(&StatusReply {
            repos: vec![
                RepoStatus {
                    path: "/a".to_owned(),
                    register_error: None,
                    rules: broken,
                },
                RepoStatus {
                    path: "/b".to_owned(),
                    register_error: Some("no .git".to_owned()),
                    rules: SourceStatus::default(),
                },
            ],
            ..StatusReply::default()
        });
        assert!(text.contains("mode: observe"));
        assert!(text.contains("/a: 2 rules in force, but the file now fails to load: bad"));
        assert!(text.contains("/b: cannot be registered: no .git"));
        assert!(text.contains("scan:     none yet"));
        assert!(text.contains("personal: no rules file"));
    }

    #[test]
    fn log_lines_are_one_readable_line() {
        let line = log_line(
            r#"{"ts":"T","event":"action","kind":"kill","rule":"r","pid":5,"argv":["a","b"],"reason":"why"}"#,
        );
        assert_eq!(line, "T  action/kill        rule=r pid=5 cmd=a b -- why");
        assert_eq!(log_line("not json"), "not json");
    }
}
