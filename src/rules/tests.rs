use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant, UNIX_EPOCH};

use super::*;
use crate::facts::table::{ProcessTable, SyntheticProcess};
use crate::facts::{FactStore, Repos};
use crate::platform::{BaseInfo, Cmdline, Usage};

const EXECUTOR: &str = "/usr/local/bin/node node node_modules/nx/dist/bin/run-executor.js";

fn key(pid: i32, start: u64) -> ProcKey {
    ProcKey {
        pid,
        start: start * 1_000_000,
    }
}

/// A made-up process; `start` is in seconds since the epoch, `cmd` is the exe and argv.
fn proc(pid: i32, start: u64, ppid: i32, cmd: &str) -> SyntheticProcess {
    let mut words = cmd.split(' ');
    let exe = words.next().unwrap_or_default().to_owned();
    SyntheticProcess {
        info: BaseInfo {
            key: key(pid, start),
            ppid,
            uid: 501,
            tty: None,
            session: None,
            rss: Some(4096),
            usage: Some(Usage {
                cpu: Duration::from_millis(100),
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

fn with_env(mut p: SyntheticProcess, name: &str, value: &str) -> SyntheticProcess {
    if let Some(env) = p.cmdline.as_mut().and_then(|c| c.env.as_mut()) {
        env.insert(name.to_owned(), value.to_owned());
    }
    p
}

fn launchd() -> SyntheticProcess {
    let mut p = proc(1, 1, 0, "/sbin/launchd");
    p.info.usage = None;
    p.cmdline = None;
    p
}

/// Two scans, 20 minutes apart, of:
/// - pid 20, an nx executor an agent (pid 10) started, abandoned: the agent is gone and it is
///   orphaned; pid 21 is its child;
/// - pid 30, an orphaned executor with no origin record;
/// - pid 41, an executor of a live agent (pid 40), not orphaned;
/// - pid 50, an orphaned executor of the live agent.
struct World {
    store: FactStore,
    table: ProcessTable,
    _tmp: tempfile::TempDir,
    repo: PathBuf,
}

fn world() -> World {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().canonicalize().unwrap().join("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    let mut repos = Repos::default();
    repos.register(&repo).unwrap();
    let mut store = FactStore::new(repos);

    let in_repo = |mut p: SyntheticProcess| {
        p.cwd = Some(repo.clone());
        p
    };
    let agent = || proc(10, 10, 1, "/usr/local/bin/claude claude");
    let live_agent = || proc(40, 40, 1, "/usr/local/bin/claude claude");
    let first = vec![
        launchd(),
        agent(),
        live_agent(),
        in_repo(with_env(
            proc(20, 20, 10, EXECUTOR),
            "NX_TASK_TARGET_PROJECT",
            "web",
        )),
        proc(21, 21, 20, "/usr/local/bin/node node worker.js"),
        proc(30, 30, 1, EXECUTOR),
        proc(41, 41, 40, EXECUTOR),
        proc(50, 50, 40, EXECUTOR),
    ];
    let t0 = ProcessTable::synthetic(UNIX_EPOCH + Duration::from_secs(100), first);
    store.update(&t0);

    let second = vec![
        launchd(),
        live_agent(),
        in_repo(with_env(
            with_env(proc(20, 20, 1, EXECUTOR), "NX_TASK_TARGET_PROJECT", "web"),
            "CLAUDE_PID",
            "10",
        )),
        proc(21, 21, 20, "/usr/local/bin/node node worker.js"),
        proc(30, 30, 1, EXECUTOR),
        proc(41, 41, 40, EXECUTOR),
        proc(50, 50, 1, EXECUTOR),
    ];
    let table = ProcessTable::synthetic(UNIX_EPOCH + Duration::from_secs(100 + 1200), second);
    store.update(&table);
    World {
        store,
        table,
        _tmp: tmp,
        repo,
    }
}

impl World {
    fn eval(&self, rules: &RuleSet, pid: i32) -> Result<Option<Verdict>, EvalError> {
        let key = self.table.by_pid(pid).unwrap().key();
        rules.evaluate(0, self.store.view(&self.table), key)
    }
}

fn load(source: &str) -> RuleSet {
    RuleSet::load("test.lua", source.as_bytes()).unwrap_or_else(|e| panic!("{e}"))
}

fn load_err(source: &str) -> String {
    RuleSet::load("test.lua", source.as_bytes())
        .err()
        .unwrap_or_else(|| panic!("loaded:\n{source}"))
        .to_string()
}

/// A file with one executor rule; `extra` is spliced into the rule.
fn rule(extra: &str) -> RuleSet {
    load(&format!(
        r#"return {{ api = 1, env = {{ "NX_TASK_TARGET_PROJECT" }}, rules = {{
            {{ name = "nx", match = "nx/dist/bin/run-executor.js", {extra} }},
        }} }}"#
    ))
}

/// A rule with a judge whose body is `body`.
fn judged(extra: &str, body: &str) -> RuleSet {
    rule(&format!("{extra} judge = function(p) {body} end,"))
}

fn kill(reason: &str) -> Option<Verdict> {
    Some(Verdict {
        verb: Verb::Kill,
        reason: reason.to_owned(),
        judge_reason: None,
    })
}

// Loading.

#[test]
fn a_rule_gets_the_documented_defaults() {
    let set = load(
        r#"return { api = 1, rules = {
            { name = "nx", match = "run-executor.js" },
            { name = "chrome", re = "Chrome.*--headless", when = "always", idle = "1h30m",
              quarantine = "10m", grace = "2s", signal = "INT", enforce = true,
              judge = function(p) return nil end },
        } }"#,
    );
    let [nx, chrome] = set.rules() else {
        panic!("{set:?}")
    };
    assert_eq!(nx.name, "nx");
    assert_eq!(nx.when, When::Abandoned);
    assert_eq!(nx.idle, None);
    assert_eq!(nx.quarantine, Duration::from_secs(300));
    assert_eq!(nx.grace, Duration::from_secs(5));
    assert_eq!(nx.signal, Signal::Term);
    assert!(!nx.enforce);
    assert!(nx.judge.is_none());
    assert!(nx.matcher.is_match("node run-executor.js"));

    assert_eq!(chrome.when, When::Always);
    assert_eq!(chrome.idle, Some(Duration::from_secs(5400)));
    assert_eq!(chrome.quarantine, Duration::from_secs(600));
    assert_eq!(chrome.grace, Duration::from_secs(2));
    assert_eq!(chrome.signal, Signal::Int);
    assert!(chrome.enforce);
    assert!(chrome.judge.is_some());
    assert!(
        chrome
            .matcher
            .is_match("/Applications/Chrome --headless=new")
    );
    assert!(!chrome.matcher.is_match("/Applications/Chrome"));
    assert!(set.env().is_empty());
}

#[test]
fn an_invalid_file_is_a_load_error_naming_the_rule_and_key() {
    let ok_rule = r#"{ name = "a", match = "abcd" }"#;
    let file = |rules: &str| format!("return {{ api = 1, rules = {{ {rules} }} }}");
    let rule = |body: &str| file(&format!("{{ name = \"r\", {body} }}"));
    let cases = [
        ("return {}".to_owned(), "missing required key \"api\""),
        (
            "return { api = 2, rules = {} }".to_owned(),
            "unsupported api 2",
        ),
        (
            "return { api = \"1\", rules = {} }".to_owned(),
            "unsupported api \"1\"",
        ),
        (
            "return { api = 1 }".to_owned(),
            "missing required key \"rules\"",
        ),
        (
            "return { api = 1, rules = {}, extra = 1 }".to_owned(),
            "unknown key \"extra\"",
        ),
        ("return 42".to_owned(), "must return a table"),
        (
            "return { api = 1, rules = { x = 1 } }".to_owned(),
            "expected a list",
        ),
        (file("42"), "rules[1]: expected a table"),
        (
            file("{ match = \"abcd\" }"),
            "rules[1]: missing required key \"name\"",
        ),
        (
            file(&format!("{ok_rule}, {ok_rule}")),
            "rule \"a\": duplicate name",
        ),
        (
            rule("match = \"abcd\", colour = 1"),
            "rules[1]: unknown key \"colour\"",
        ),
        (rule(""), "rule \"r\": missing required key \"match\""),
        (
            rule("match = \"abc\""),
            "rule \"r\": key \"match\": \"abc\" is shorter than 4",
        ),
        (rule("match = \"  ab  \""), "key \"match\""),
        (
            rule("match = 1234"),
            "rule \"r\": key \"match\": expected a string",
        ),
        (rule("match = \"abcd\", re = \"abcd\""), "exactly one of"),
        (
            rule("re = \"a.c\""),
            "rule \"r\": key \"re\": \"a.c\" is shorter than 4",
        ),
        (
            rule("re = \"(abcd)?\""),
            "rule \"r\": key \"re\": \"(abcd)?\" matches the empty string",
        ),
        (
            rule("re = \"abcd(\""),
            "rule \"r\": key \"re\": invalid regex",
        ),
        (
            rule("match = \"abcd\", when = \"never\""),
            "rule \"r\": key \"when\"",
        ),
        (
            rule("match = \"abcd\", idle = \"20x\""),
            "rule \"r\": key \"idle\": expected a duration",
        ),
        (
            rule("match = \"abcd\", idle = 1200"),
            "rule \"r\": key \"idle\"",
        ),
        (
            rule("match = \"abcd\", quarantine = \"5\""),
            "rule \"r\": key \"quarantine\"",
        ),
        (
            rule("match = \"abcd\", grace = \"\""),
            "rule \"r\": key \"grace\"",
        ),
        (
            rule("match = \"abcd\", signal = \"KILL\""),
            "rule \"r\": key \"signal\"",
        ),
        (
            rule("match = \"abcd\", enforce = \"yes\""),
            "rule \"r\": key \"enforce\"",
        ),
        (
            rule("match = \"abcd\", judge = \"kill\""),
            "rule \"r\": key \"judge\"",
        ),
        (
            "return { api = 1, env = \"HOME\", rules = {} }".to_owned(),
            "key \"env\"",
        ),
        (
            "return { api = 1, env = { \"A=B\" }, rules = {} }".to_owned(),
            "invalid variable name",
        ),
        ("return { api = 1,".to_owned(), "test.lua"),
        ("error(\"boom\")".to_owned(), "boom"),
    ];
    for (source, expected) in cases {
        let err = load_err(&source);
        assert!(
            err.contains(expected),
            "{source}\n=> {err}\nexpected: {expected}"
        );
        assert!(err.starts_with("test.lua: "), "{err}");
    }
}

/// Must protect: identity values never reach rules, even when a file asks for them.
#[test]
fn listing_an_identity_variable_in_env_is_a_load_error() {
    for name in crate::facts::table::IDENTITY_ENV {
        let err = load_err(&format!(
            "return {{ api = 1, env = {{ \"HOME\", \"{name}\" }}, rules = {{}} }}"
        ));
        assert!(err.contains(name) && err.contains("never visible"), "{err}");
    }
}

/// Must protect: a file that fails leaves the previous valid set in force, and no partial set
/// ever exists (the second rule's error rejects the first too).
#[test]
fn a_failed_reload_keeps_the_previous_rules() {
    let mut set = load(r#"return { api = 1, rules = { { name = "old", match = "abcd" } } }"#);
    let broken = br#"return { api = 1, rules = {
        { name = "new", match = "abcd" },
        { name = "bad", match = "ab" },
    } }"#;
    let err = set.reload(broken).unwrap_err();
    assert!(err.message.contains("rule \"bad\""), "{err}");
    assert!(RuleSet::load("x", broken).is_err());
    assert_eq!(set.rules().len(), 1);
    assert_eq!(set.rules()[0].name, "old");

    set.reload(br#"return { api = 1, rules = { { name = "new", match = "abcd" } } }"#)
        .unwrap();
    assert_eq!(set.rules()[0].name, "new");
    assert_eq!(set.name(), "test.lua");
}

#[test]
fn a_rules_file_that_loops_or_hogs_memory_fails_to_load() {
    let started = Instant::now();
    let err = load_err("while true do end");
    assert!(err.contains("time budget"), "{err}");
    assert!(started.elapsed() < Duration::from_secs(2));
    let err = load_err("local s = string.rep('x', 64 * 1024 * 1024) return {}");
    assert!(err.contains("memory"), "{err}");
}

// The sandbox (security obligation): every way out of the sandbox is absent.

const ESCAPES: [&str; 20] = [
    "io.open('/etc/passwd')",
    "io.write('x')",
    "os.execute('touch /tmp/leukocyte-pwned')",
    "os.getenv('HOME')",
    "os.remove('/tmp/x')",
    "os.exit(1)",
    "require('x')",
    "loadstring('return 1')()",
    "load('return 1')()",
    "dofile('/etc/passwd')",
    "loadfile('/etc/passwd')",
    "debug.getinfo(1)",
    "debug.traceback()",
    "collectgarbage('collect')",
    "collectgarbage('count')",
    "getfenv(1)",
    "setfenv(1, {})",
    "print('x')",
    "string.rep = function() return '' end",
    "rawset(string, 'rep', nil)",
];

/// The error of an absent global or a read-only library, not of something else going wrong.
fn refused(err: &str) -> bool {
    err.contains("attempt to call a nil value")
        || err.contains("attempt to index nil")
        || err.contains("attempt to modify a readonly table")
}

#[test]
fn the_sandbox_refuses_every_escape_at_load() {
    // The state itself works: pure libraries are there.
    load(
        "assert(string.format('%d', 1) == '1' and table.concat({'a'}) == 'a' and math.max(1, 2) == 2)
         return { api = 1, rules = {} }",
    );
    for escape in ESCAPES {
        let source = format!("{escape}\nreturn {{ api = 1, rules = {{}} }}");
        let err = load_err(&source);
        assert!(refused(&err), "{escape} => {err}");
    }
}

#[test]
fn the_sandbox_refuses_every_escape_in_a_judge() {
    let w = world();
    for escape in ESCAPES {
        let set = judged("when = \"always\",", &format!("{escape} return 'kill'"));
        let err = w.eval(&set, 20).unwrap_err();
        assert!(refused(&err.message), "{escape} => {err}");
    }
}

#[test]
fn the_sandbox_globals_are_absent() {
    load(
        "for _, name in ipairs({ 'io', 'os', 'require', 'loadstring', 'load', 'dofile',
             'loadfile', 'debug', 'collectgarbage', 'getfenv', 'setfenv', 'print' }) do
           assert(_G[name] == nil, name)
         end
         return { api = 1, rules = {} }",
    );
}

#[test]
fn bytecode_is_never_loaded() {
    let bytecode = mlua::chunk::Compiler::new()
        .compile("return { api = 1, rules = {} }")
        .unwrap();
    assert!(RuleSet::load("test.luau", &bytecode).is_err());
}

// The judge's budget and failures (must protect: no verdict).

#[test]
fn a_judge_that_runs_too_long_yields_no_verdict() {
    let w = world();
    for body in [
        "while true do end",
        // Catching the interrupt's error does not escape the budget.
        "while true do pcall(function() while true do end end) end",
        "local function f() return f() end return f()",
    ] {
        let set = judged("", body);
        let started = Instant::now();
        let err = w.eval(&set, 20).unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(2), "{body}: {err}");
    }
}

#[test]
fn a_judge_over_its_memory_budget_yields_no_verdict_and_the_state_recovers() {
    let w = world();
    let set = load(
        r#"return { api = 1, rules = {
            { name = "hog", match = "run-executor.js", when = "always",
              judge = function(p) local s = string.rep("x", 64 * 1024 * 1024) return "kill" end },
            { name = "fine", match = "run-executor.js", when = "always",
              judge = function(p) return "report", "ok" end },
        } }"#,
    );
    let key = w.table.by_pid(20).unwrap().key();
    let view = w.store.view(&w.table);
    let err = set.evaluate(0, view, key).unwrap_err();
    assert!(err.message.contains("memory"), "{err}");
    let verdict = set.evaluate(1, view, key).unwrap().unwrap();
    assert_eq!(verdict.verb, Verb::Report);
}

#[test]
fn a_judge_returning_garbage_yields_no_verdict() {
    let w = world();
    for body in [
        "return 1",
        "return 'destroy'",
        "return {}",
        "return p",
        "return 'kill', 'why', 'extra'",
        "return 'kill', {}",
        "error('boom')",
        // A misspelt field reads nil, and comparing nil fails.
        "return p.idel > 60 and 'kill' or nil",
    ] {
        let set = judged("", body);
        assert!(w.eval(&set, 20).is_err(), "{body}");
    }
}

#[test]
fn an_error_names_the_rule() {
    let w = world();
    let err = w.eval(&judged("", "error('boom')"), 20).unwrap_err();
    assert_eq!(err.rule, "nx");
    assert!(err.message.contains("boom"), "{err}");
    assert!(
        rule("")
            .evaluate(3, w.store.view(&w.table), key(20, 20))
            .is_err()
    );
}

// Declarative verdicts.

#[test]
fn abandoned_needs_an_orphan_with_a_dead_origin() {
    let w = world();
    let set = rule("");
    assert_eq!(
        w.eval(&set, 20).unwrap(),
        kill("orphaned · origin agent dead · idle 20m")
    );
    // No origin record: unknown protects.
    assert_eq!(w.eval(&set, 30).unwrap(), None);
    // Live origin, orphaned or not.
    assert_eq!(w.eval(&set, 50).unwrap(), None);
    assert_eq!(w.eval(&set, 41).unwrap(), None);
}

#[test]
fn orphaned_and_always_relax_the_structural_condition() {
    let w = world();
    let orphaned = rule("when = \"orphaned\",");
    assert_eq!(
        w.eval(&orphaned, 30).unwrap(),
        kill("orphaned · origin unknown · idle 20m")
    );
    assert!(w.eval(&orphaned, 50).unwrap().is_some());
    assert_eq!(w.eval(&orphaned, 41).unwrap(), None);
    let always = rule("when = \"always\",");
    assert_eq!(
        w.eval(&always, 41).unwrap(),
        kill("origin agent alive · idle 20m")
    );
}

#[test]
fn idle_must_be_reached() {
    let w = world();
    assert!(w.eval(&rule("idle = \"20m\","), 20).unwrap().is_some());
    assert_eq!(w.eval(&rule("idle = \"21m\","), 20).unwrap(), None);
}

#[test]
fn a_process_the_matcher_misses_gets_no_verdict_and_no_judge_call() {
    let w = world();
    let set = judged("when = \"always\",", "error('judge called')");
    assert_eq!(w.eval(&set, 21).unwrap(), None);
    assert_eq!(w.eval(&set, 1).unwrap(), None);
}

#[test]
fn a_judge_verb_overrides_and_nil_keeps_the_declarative_verdict() {
    let w = world();
    let keep = judged("", "return nil, 'looked'");
    assert_eq!(
        w.eval(&keep, 20).unwrap(),
        Some(Verdict {
            verb: Verb::Kill,
            reason: "orphaned · origin agent dead · idle 20m".to_owned(),
            judge_reason: Some("looked".to_owned()),
        })
    );
    assert_eq!(
        w.eval(&judged("", "return"), 20).unwrap(),
        kill("orphaned · origin agent dead · idle 20m")
    );
    let protect = judged("", "return 'protect', 'needed'");
    assert_eq!(w.eval(&protect, 20).unwrap().unwrap().verb, Verb::Protect);
    // A judge may kill what the declarative part spares.
    let killer = judged("", "return 'kill', 'twin'");
    let verdict = w.eval(&killer, 41).unwrap().unwrap();
    assert_eq!(verdict.verb, Verb::Kill);
    assert_eq!(verdict.judge_reason.as_deref(), Some("twin"));
    // Nothing either way.
    assert_eq!(w.eval(&judged("", "return nil"), 41).unwrap(), None);
}

#[test]
fn a_long_judge_reason_is_cut() {
    let w = world();
    let set = judged("", "return 'kill', string.rep('x', 1000)");
    let reason = w.eval(&set, 20).unwrap().unwrap().judge_reason.unwrap();
    assert_eq!(reason.chars().count(), MAX_JUDGE_REASON_CHARS);
}

// ProcView.

/// Evaluates `checks` (Lua `assert`s over `p`) in a judge for `pid`; the judge reports when
/// they all pass.
fn check(w: &World, pid: i32, checks: &str) {
    let set = judged("when = \"always\",", &format!("{checks}\nreturn 'report'"));
    let verdict = w.eval(&set, pid).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(verdict.map(|v| v.verb), Some(Verb::Report));
}

#[test]
fn procview_exposes_the_documented_fields() {
    let w = world();
    let repo = w.repo.to_str().unwrap();
    check(
        &w,
        20,
        &format!(
            r#"
        assert(p.pid == 20 and p.ppid == 1, "pid")
        assert(p.exe == "/usr/local/bin/node", p.exe)
        assert(#p.argv == 2 and p.argv[2] == "node_modules/nx/dist/bin/run-executor.js")
        assert(p.cmd == "{EXECUTOR}", p.cmd)
        assert(p.cwd == "{repo}", tostring(p.cwd))
        assert(p.repo == "{repo}", tostring(p.repo))
        assert(p.age == 1280, tostring(p.age))
        assert(p.idle == 1200, tostring(p.idle))
        assert(p.rss == 4096)
        assert(p.cpu == 0, tostring(p.cpu))
        assert(p.orphan == true)
        assert(p.session_alive == nil)
        assert(p.origin.kind == "agent" and p.origin.alive == false)
        assert(p.env.NX_TASK_TARGET_PROJECT == "web")
        assert(p.clients == nil and p.listening == nil, "synthetic sockets are unknown")
        assert(p.parent.pid == 1)
        assert(#p.children == 1 and p.children[1].pid == 21)
        assert(p.children[1].parent.pid == 20)
        assert(p.children[1].cmd == "/usr/local/bin/node node worker.js")
        assert(p.newer_twins == 0, tostring(p.newer_twins))
        assert(p.not_a_field == nil and p[1] == nil)
    "#
        ),
    );
    check(
        &w,
        30,
        r#"
        assert(p.origin.kind == nil and p.origin.alive == nil)
        assert(p.repo == nil and p.newer_twins == nil)
    "#,
    );
    check(
        &w,
        41,
        "assert(p.parent.pid == 40 and p.parent.origin.kind == nil)",
    );
}

/// Privacy: identity variables the process carries are never visible, only the file's list.
#[test]
fn procview_env_holds_only_the_allowlisted_names() {
    let w = world();
    check(
        &w,
        20,
        r#"
        assert(p.env.CLAUDE_PID == nil)
        local n = 0
        for name in pairs(p.env) do n += 1 end
        assert(n == 1, tostring(n))
    "#,
    );
}

#[test]
fn procview_is_read_only() {
    let w = world();
    for body in [
        "p.pid = 1",
        "p.argv[1] = 'x'",
        "p.origin.alive = true",
        "p.env.NX_TASK_TARGET_PROJECT = 'x'",
        "table.insert(p.children, 1)",
    ] {
        let set = judged("when = \"always\",", &format!("{body} return 'kill'"));
        assert!(w.eval(&set, 20).is_err(), "{body}");
    }
}

/// A view stashed by one evaluation and read in the next fails rather than reading anything,
/// even when the next evaluation is of another process.
#[test]
fn a_stashed_procview_is_dead_in_the_next_evaluation() {
    let w = world();
    let set = load(
        r#"local stash
        return { api = 1, rules = {
            { name = "nx", match = "run-executor.js", when = "always", judge = function(p)
                if stash then
                    local ok = pcall(function() return stash.pid end)
                    local ok_child = pcall(function() return stash.children end)
                    if ok or ok_child then return "kill", "stale read" end
                    return "protect", "stale view failed"
                end
                stash = p
                return nil
            end },
        } }"#,
    );
    assert_eq!(w.eval(&set, 20).unwrap().unwrap().verb, Verb::Kill);
    let verdict = w.eval(&set, 30).unwrap().unwrap();
    assert_eq!(verdict.verb, Verb::Protect, "{verdict:?}");
}

#[test]
fn the_guide_and_the_examples_load() {
    let mut blocks = Vec::new();
    let mut lines = GUIDE.lines();
    while let Some(line) = lines.next() {
        if line.trim() == "```lua" {
            let block: Vec<&str> = lines.by_ref().take_while(|l| l.trim() != "```").collect();
            blocks.push(block.join("\n"));
        }
    }
    assert!(
        blocks.len() >= 4,
        "the guide's lua blocks: {}",
        blocks.len()
    );
    for (i, block) in blocks.iter().enumerate() {
        if let Err(e) = RuleSet::load(&format!("guide block {i}"), block.as_bytes()) {
            panic!("{e}\n{block}");
        }
    }
    for (name, source) in [
        (
            "repo-rules.lua",
            include_str!("../../examples/repo-rules.lua"),
        ),
        (
            "personal-rules.lua",
            include_str!("../../examples/personal-rules.lua"),
        ),
    ] {
        if let Err(e) = RuleSet::load(name, source.as_bytes()) {
            panic!("{e}");
        }
    }
}
