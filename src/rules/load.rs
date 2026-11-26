//! Loading a rules file: the sandboxed Luau state, and validation of the returned table into
//! typed [`Rule`]s.

use std::cell::Cell;
use std::collections::{BTreeMap, HashSet};
use std::rc::Rc;
use std::time::Instant;

use mlua::chunk::ChunkMode;
use mlua::{Lua, LuaOptions, StdLib, Table, Value, VmState};
use regex::Regex;

use crate::facts::table::IDENTITY_ENV;
use crate::rules::schema::{MIN_MATCH_CHARS, Matcher, Rule, Signal, When, parse_duration};

/// Memory one rule source's Lua state may use, its rules and every `judge` call included.
pub const MEMORY_LIMIT: usize = 8 * 1024 * 1024;

/// Globals that are removed before the state is sandboxed: every way out to the file system,
/// the process, other code or the collector. Luau has no `io`, `os` is not loaded, and the
/// standard `debug` library is not loaded either; `dofile`, `loadfile` and `load` do not exist
/// in Luau and are listed so that a future version adding them stays closed.
const REMOVED_GLOBALS: [&str; 10] = [
    "require",
    "loadstring",
    "load",
    "dofile",
    "loadfile",
    "collectgarbage",
    "gcinfo",
    "getfenv",
    "setfenv",
    "print",
];

/// A fresh sandboxed state. `deadline` is checked by the interrupt: when it is set and has
/// passed, the running Lua code fails.
pub(super) fn new_state(deadline: &Rc<Cell<Option<Instant>>>) -> mlua::Result<Lua> {
    // Pure libraries only: no `os`, `debug`, `coroutine`, `buffer`.
    let libs = StdLib::STRING | StdLib::TABLE | StdLib::MATH | StdLib::UTF8 | StdLib::BIT;
    let lua = Lua::new_with(libs, LuaOptions::default())?;
    let globals = lua.globals();
    for name in REMOVED_GLOBALS {
        globals.raw_set(name, Value::Nil)?;
    }
    // Read-only globals and libraries; writes go to a per-script environment.
    lua.sandbox(true)?;
    let deadline = Rc::clone(deadline);
    lua.set_interrupt(move |_| match deadline.get() {
        Some(at) if Instant::now() >= at => Err(mlua::Error::runtime("time budget exceeded")),
        _ => Ok(VmState::Continue),
    });
    lua.set_memory_limit(MEMORY_LIMIT)?;
    Ok(lua)
}

/// Runs the rules file's chunk as text (bytecode is never loaded: Luau does not verify it).
pub(super) fn run_chunk(lua: &Lua, name: &str, source: &[u8]) -> mlua::Result<Value> {
    lua.load(source)
        .set_name(format!("={name}"))
        .set_mode(ChunkMode::Text)
        .call(())
}

/// The validated content of a rules file.
pub(super) struct Parsed {
    pub env: Vec<String>,
    pub rules: Vec<Rule>,
}

const FILE_KEYS: [&str; 3] = ["api", "env", "rules"];
const RULE_KEYS: [&str; 10] = [
    "name",
    "match",
    "re",
    "when",
    "idle",
    "quarantine",
    "grace",
    "signal",
    "enforce",
    "judge",
];

/// Validates what the rules file returned. The message of an error names the rule and key.
pub(super) fn parse(lua: &Lua, value: Value) -> Result<Parsed, String> {
    let Value::Table(file) = value else {
        return Err(format!(
            "the file must return a table, not {}",
            value.type_name()
        ));
    };
    let mut fields = keyed(&file, &FILE_KEYS, "the file")?;

    match fields.remove("api") {
        None => return Err("missing required key \"api\"".to_owned()),
        Some(api) if as_integer(&api) == Some(1) => {}
        Some(api) => {
            return Err(format!(
                "key \"api\": unsupported api {} (this daemon supports api = 1)",
                describe(&api)
            ));
        }
    }

    let env = match fields.remove("env") {
        None => Vec::new(),
        Some(env) => parse_env(env)?,
    };

    let rules = match fields.remove("rules") {
        None => return Err("missing required key \"rules\"".to_owned()),
        Some(Value::Table(rules)) => sequence(&rules, "key \"rules\"")?,
        Some(other) => {
            return Err(format!(
                "key \"rules\": expected a list of rules, not {}",
                other.type_name()
            ));
        }
    };
    let mut names = HashSet::new();
    let rules = rules
        .into_iter()
        .enumerate()
        .map(|(i, rule)| {
            let rule = parse_rule(lua, i + 1, rule)?;
            if !names.insert(rule.name.clone()) {
                return Err(format!("rule \"{}\": duplicate name", rule.name));
            }
            Ok(rule)
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(Parsed { env, rules })
}

fn parse_env(env: Value) -> Result<Vec<String>, String> {
    let Value::Table(env) = env else {
        return Err(format!(
            "key \"env\": expected a list of variable names, not {}",
            env.type_name()
        ));
    };
    let mut names = Vec::new();
    for name in sequence(&env, "key \"env\"")? {
        let Value::String(name) = &name else {
            return Err(format!(
                "key \"env\": expected variable names, found {}",
                name.type_name()
            ));
        };
        let name = name
            .to_str()
            .map_err(|_| "key \"env\": a name is not UTF-8")?;
        let valid = !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            return Err(format!("key \"env\": invalid variable name \"{name}\""));
        }
        // Identity values serve origin tracking only; they never reach a rule.
        if IDENTITY_ENV.contains(&&*name) {
            return Err(format!(
                "key \"env\": \"{name}\" identifies an agent and is never visible to rules"
            ));
        }
        if !names.iter().any(|n| n == &*name) {
            names.push(name.to_owned());
        }
    }
    Ok(names)
}

fn parse_rule(lua: &Lua, index: usize, value: Value) -> Result<Rule, String> {
    let Value::Table(table) = value else {
        return Err(format!(
            "rules[{index}]: expected a table, not {}",
            value.type_name()
        ));
    };
    let mut fields = keyed(&table, &RULE_KEYS, &format!("rules[{index}]"))?;
    let name = match fields.remove("name") {
        None => return Err(format!("rules[{index}]: missing required key \"name\"")),
        Some(name) => string(name)
            .filter(|n| !n.trim().is_empty())
            .ok_or_else(|| format!("rules[{index}]: key \"name\": expected a non-empty string"))?,
    };
    let err = |key: &str, msg: String| format!("rule \"{name}\": key \"{key}\": {msg}");
    let expected = |key: &str, what: &str, got: &Value| {
        err(key, format!("expected {what}, not {}", describe(got)))
    };

    let matcher = match (fields.remove("match"), fields.remove("re")) {
        (Some(_), Some(_)) => {
            return Err(format!(
                "rule \"{name}\": give exactly one of \"match\" and \"re\", not both"
            ));
        }
        (None, None) => {
            return Err(format!(
                "rule \"{name}\": missing required key \"match\" (or \"re\")"
            ));
        }
        (Some(m), None) => {
            let text = string(m.clone()).ok_or_else(|| expected("match", "a string", &m))?;
            if text.trim().chars().count() < MIN_MATCH_CHARS {
                return Err(err(
                    "match",
                    format!("\"{text}\" is shorter than {MIN_MATCH_CHARS} characters"),
                ));
            }
            Matcher::Substring(text)
        }
        (None, Some(r)) => {
            let text = string(r.clone()).ok_or_else(|| expected("re", "a string", &r))?;
            Matcher::Regex(regex(&text).map_err(|msg| err("re", msg))?)
        }
    };

    let when = match fields.remove("when") {
        None => When::Abandoned,
        Some(v) => match string(v.clone()).as_deref() {
            Some("abandoned") => When::Abandoned,
            Some("orphaned") => When::Orphaned,
            Some("always") => When::Always,
            _ => {
                return Err(expected(
                    "when",
                    "\"abandoned\", \"orphaned\" or \"always\"",
                    &v,
                ));
            }
        },
    };

    let duration = |key: &str, value: Value| {
        string(value.clone())
            .and_then(|text| parse_duration(&text))
            .ok_or_else(|| expected(key, "a duration such as \"20m\" or \"1h30m\"", &value))
    };
    let idle = fields
        .remove("idle")
        .map(|v| duration("idle", v))
        .transpose()?;
    let quarantine = match fields.remove("quarantine") {
        None => std::time::Duration::from_secs(5 * 60),
        Some(v) => duration("quarantine", v)?,
    };
    let grace = match fields.remove("grace") {
        None => std::time::Duration::from_secs(5),
        Some(v) => duration("grace", v)?,
    };

    let signal = match fields.remove("signal") {
        None => Signal::Term,
        Some(v) => string(v.clone())
            .as_deref()
            .and_then(Signal::parse)
            .ok_or_else(|| expected("signal", "\"TERM\", \"INT\", \"HUP\" or \"QUIT\"", &v))?,
    };

    let enforce = match fields.remove("enforce") {
        None => false,
        Some(Value::Boolean(b)) => b,
        Some(v) => return Err(expected("enforce", "true or false", &v)),
    };

    let judge = match fields.remove("judge") {
        None => None,
        Some(Value::Function(f)) => Some(
            lua.create_registry_value(f)
                .map_err(|e| err("judge", e.to_string()))?,
        ),
        Some(v) => return Err(expected("judge", "a function", &v)),
    };

    Ok(Rule {
        name,
        matcher,
        when,
        idle,
        quarantine,
        grace,
        signal,
        enforce,
        judge,
    })
}

/// A regex for `re`: it must compile, be at least [`MIN_MATCH_CHARS`] characters long and not
/// match the empty string. The length check is a best effort against patterns that select
/// everything (`.{4}` passes it).
fn regex(text: &str) -> Result<Regex, String> {
    if text.trim().chars().count() < MIN_MATCH_CHARS {
        return Err(format!(
            "\"{text}\" is shorter than {MIN_MATCH_CHARS} characters"
        ));
    }
    let re = Regex::new(text).map_err(|e| format!("invalid regex: {e}"))?;
    if re.is_match("") {
        return Err(format!("\"{text}\" matches the empty string"));
    }
    Ok(re)
}

/// The string-keyed fields of `table`, failing on a key outside `allowed` or a non-string key.
fn keyed(table: &Table, allowed: &[&str], what: &str) -> Result<BTreeMap<String, Value>, String> {
    let mut fields = BTreeMap::new();
    for pair in table.pairs::<Value, Value>() {
        let (key, value) = pair.map_err(|e| format!("{what}: {e}"))?;
        let name = string(key.clone())
            .ok_or_else(|| format!("{what}: unexpected key {}", describe(&key)))?;
        if !allowed.contains(&name.as_str()) {
            return Err(format!(
                "{what}: unknown key \"{name}\" (allowed: {})",
                allowed.join(", ")
            ));
        }
        fields.insert(name, value);
    }
    Ok(fields)
}

/// The values of a list, failing on anything but the keys `1..=n`.
fn sequence(table: &Table, what: &str) -> Result<Vec<Value>, String> {
    let mut items = BTreeMap::new();
    for pair in table.pairs::<Value, Value>() {
        let (key, value) = pair.map_err(|e| format!("{what}: {e}"))?;
        let index = as_integer(&key)
            .and_then(|i| usize::try_from(i).ok())
            .filter(|i| *i >= 1)
            .ok_or_else(|| format!("{what}: expected a list, found key {}", describe(&key)))?;
        items.insert(index, value);
    }
    if items.keys().copied().ne(1..=items.len()) {
        return Err(format!("{what}: expected a list without holes"));
    }
    Ok(items.into_values().collect())
}

fn string(value: Value) -> Option<String> {
    match value {
        Value::String(s) => s.to_str().ok().map(|s| s.to_owned()),
        _ => None,
    }
}

fn as_integer(value: &Value) -> Option<i64> {
    match *value {
        Value::Integer(i) => Some(i),
        // Luau numbers are doubles; only an exact integer counts.
        Value::Number(n) if n.fract() == 0.0 && n.abs() < 9.0e15 => Some(n as i64),
        _ => None,
    }
}

/// A value for an error message: short strings and numbers verbatim, the type otherwise.
fn describe(value: &Value) -> String {
    match value {
        Value::String(s) => match s.to_str() {
            Ok(s) if s.chars().count() <= 40 => format!("\"{s}\""),
            _ => "a string".to_owned(),
        },
        Value::Integer(i) => i.to_string(),
        Value::Number(n) => n.to_string(),
        Value::Boolean(b) => b.to_string(),
        other => other.type_name().to_owned(),
    }
}
