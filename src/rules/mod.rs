//! Rules: loading a Luau rules file into a typed [`RuleSet`], and evaluating its rules against
//! one process.
//!
//! Each rules file gets its own sandboxed Luau state ([`load`]). The file format is `api = 1`,
//! decided in `docs/decisions/rule-api-declarative-rules-with-a-judge-escape-hatch.md`.

#![deny(unsafe_code)]

mod load;
mod procview;
mod schema;

use std::cell::Cell;
use std::fmt;
use std::path::Path;
use std::rc::Rc;
use std::time::{Duration, Instant};

use mlua::{AnyUserData, Function, Lua, MultiValue, Value};

use crate::facts::{FactView, OriginKind, ProcFacts, ProcKey};
use procview::{ProcView, Resolver};

pub use load::MEMORY_LIMIT;
pub use schema::{
    Human, MIN_MATCH_CHARS, Matcher, Rule, Signal, Verb, Verdict, When, command_line,
    parse_duration,
};

/// How long one `judge` call may run.
pub const JUDGE_BUDGET: Duration = Duration::from_millis(10);
/// How long running a rules file's top level may take.
pub const LOAD_BUDGET: Duration = Duration::from_millis(100);
/// The longest judge reason kept; a longer one is cut.
pub const MAX_JUDGE_REASON_CHARS: usize = 200;

/// The rules of one rules file, with the Luau state their `judge`s live in.
///
/// A set is built whole or not at all: [`load`](Self::load) never returns a partial set, and
/// [`reload`](Self::reload) leaves the set in force when the new text fails.
pub struct RuleSet {
    name: String,
    env: Vec<String>,
    rules: Vec<Rule>,
    lua: Lua,
    /// Read by the state's interrupt; set while Lua code runs.
    deadline: Rc<Cell<Option<Instant>>>,
}

impl fmt::Debug for RuleSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleSet")
            .field("name", &self.name)
            .field("env", &self.env)
            .field("rules", &self.rules)
            .finish_non_exhaustive()
    }
}

/// Why a rules file was rejected. The message names the rule and key at fault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadError {
    /// The rules file, as named to [`RuleSet::load`].
    pub file: String,
    pub message: String,
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.file, self.message)
    }
}

impl std::error::Error for LoadError {}

/// Why an evaluation produced no verdict: the `judge` failed (an error, a read of a misspelt
/// field, the time or memory budget) or returned something other than a verb and a reason.
/// The engine treats it as no opinion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalError {
    pub rule: String,
    pub message: String,
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rule \"{}\": {}", self.rule, self.message)
    }
}

impl std::error::Error for EvalError {}

impl RuleSet {
    /// Loads a rules file from its text; `name` names it in errors and Lua tracebacks.
    pub fn load(name: &str, source: &[u8]) -> Result<Self, LoadError> {
        let error = |message: String| LoadError {
            file: name.to_owned(),
            message,
        };
        let deadline = Rc::new(Cell::new(None));
        let lua = load::new_state(&deadline).map_err(|e| error(e.to_string()))?;
        deadline.set(Some(Instant::now() + LOAD_BUDGET));
        let returned = load::run_chunk(&lua, name, source);
        deadline.set(None);
        let returned = returned.map_err(|e| error(e.to_string()))?;
        let parsed = load::parse(&lua, returned).map_err(error)?;
        Ok(Self {
            name: name.to_owned(),
            env: parsed.env,
            rules: parsed.rules,
            lua,
            deadline,
        })
    }

    /// Reads and loads a rules file.
    pub fn load_file(path: &Path) -> Result<Self, LoadError> {
        let name = path.display().to_string();
        let source = std::fs::read(path).map_err(|e| LoadError {
            file: name.clone(),
            message: e.to_string(),
        })?;
        Self::load(&name, &source)
    }

    /// Replaces this set with `source` loaded under the same name. On error the set is left
    /// as it was, so the previously valid rules stay in force.
    pub fn reload(&mut self, source: &[u8]) -> Result<(), LoadError> {
        *self = Self::load(&self.name, source)?;
        Ok(())
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// The environment variables the file's rules may read as `p.env.NAME`; the process
    /// table must read them (see [`ProcessTable::snapshot`](crate::facts::table::ProcessTable::snapshot)).
    pub fn env(&self) -> &[String] {
        &self.env
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// The opinion of rule number `rule` (an index into [`rules`](Self::rules)) on process
    /// `key`.
    ///
    /// `None` when the rule's matcher does not hit the process's command line, when the
    /// process or its facts are unknown, or when neither the declarative part nor the `judge`
    /// has an opinion. The declarative part: when `when` holds and the subtree has been idle
    /// at least `idle`, [`Verb::Kill`]. Then a `judge` is called for every process the matcher
    /// hits; a verb it returns replaces the declarative verdict, `nil` keeps it.
    ///
    /// The kill is raw: the engine downgrades it to a report when the rule does not enforce.
    pub fn evaluate(
        &self,
        rule: usize,
        view: FactView<'_>,
        key: ProcKey,
    ) -> Result<Option<Verdict>, EvalError> {
        let Some(rule) = self.rules.get(rule) else {
            return Err(EvalError {
                rule: format!("#{rule}"),
                message: format!("{} has {} rules", self.name, self.rules.len()),
            });
        };
        let Some(process) = view.table().get(key) else {
            return Ok(None);
        };
        let hit = process
            .cmdline()
            .is_some_and(|c| rule.matcher.is_match(&command_line(c)));
        if !hit {
            return Ok(None);
        }
        let Some(facts) = view.facts(key) else {
            return Ok(None);
        };
        let declarative = holds(rule, &facts).then_some(Verb::Kill);
        let (verb, judge_reason) = match &rule.judge {
            None => (declarative, None),
            Some(judge) => {
                let (verb, reason) = self.judge(rule, judge, view, key)?;
                (verb.or(declarative), reason)
            }
        };
        Ok(verb.map(|verb| Verdict {
            verb,
            reason: describe(&facts),
            judge_reason,
        }))
    }

    /// Calls `judge` with a view of `key`, within the time budget.
    fn judge(
        &self,
        rule: &Rule,
        judge: &mlua::RegistryKey,
        view: FactView<'_>,
        key: ProcKey,
    ) -> Result<(Option<Verb>, Option<String>), EvalError> {
        let error = |message: String| EvalError {
            rule: rule.name.clone(),
            message,
        };
        let resolver = Resolver::new(view, &self.env);
        self.deadline.set(Some(Instant::now() + JUDGE_BUDGET));
        let returned = self.lua.scope(|scope| {
            let resolver =
                scope.create_function(move |lua, (view, field): (AnyUserData, Value)| {
                    resolver.field(lua, &view, &field)
                })?;
            let p = ProcView::create(&self.lua, key, resolver)?;
            let judge: Function = self.lua.registry_value(judge)?;
            judge.call::<MultiValue>(p)
        });
        self.deadline.set(None);
        let returned = returned.map_err(|e| error(e.to_string()))?;
        judge_result(returned).map_err(error)
    }
}

/// Whether the declarative part of `rule` holds.
fn holds(rule: &Rule, facts: &ProcFacts) -> bool {
    rule.when.holds(facts) && rule.idle.is_none_or(|idle| facts.idle >= idle)
}

/// The daemon-written reason: the facts that drive a verdict, e.g.
/// `orphaned · origin agent dead · idle 47m`.
fn describe(facts: &ProcFacts) -> String {
    let mut parts = Vec::new();
    if facts.orphan {
        parts.push("orphaned".to_owned());
    }
    let kind = facts.origin.kind.map(|k| match k {
        OriginKind::Agent => "agent",
        OriginKind::Terminal => "terminal",
    });
    parts.push(match (kind, facts.origin.alive) {
        (Some(kind), Some(true)) => format!("origin {kind} alive"),
        (Some(kind), Some(false)) => format!("origin {kind} dead"),
        _ => "origin unknown".to_owned(),
    });
    parts.push(format!("idle {}", Human(facts.idle)));
    parts.join(" · ")
}

/// A judge returns nothing, `nil`, or a verb and an optional reason; anything else is garbage.
fn judge_result(returned: MultiValue) -> Result<(Option<Verb>, Option<String>), String> {
    let mut values = returned.into_iter();
    let (verb, reason) = (values.next(), values.next());
    if values.next().is_some() {
        return Err("judge returned more than a verb and a reason".to_owned());
    }
    let verb = match verb.unwrap_or(Value::Nil) {
        Value::Nil => None,
        Value::String(s) => Some(s.to_str().ok().and_then(|s| Verb::parse(&s)).ok_or_else(
            || {
                format!(
                    "judge returned verb {:?}; expected \"kill\", \"report\", \"protect\" or nil",
                    s.to_string_lossy()
                )
            },
        )?),
        other => {
            return Err(format!(
                "judge returned a value of type {} as its verb; expected a string or nil",
                other.type_name()
            ));
        }
    };
    let reason = match reason.unwrap_or(Value::Nil) {
        Value::Nil => None,
        Value::String(s) => Some(
            s.to_string_lossy()
                .chars()
                .take(MAX_JUDGE_REASON_CHARS)
                .collect(),
        ),
        other => {
            return Err(format!(
                "judge returned a value of type {} as its reason; expected a string or nil",
                other.type_name()
            ));
        }
    };
    Ok((verb, reason))
}

#[cfg(test)]
mod tests;
