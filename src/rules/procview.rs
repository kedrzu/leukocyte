//! `ProcView`: the process a `judge` is called with, as Lua userdata.
//!
//! Fields are computed on first read through the fact store and cached for the evaluation.
//! Durations are seconds, sizes bytes. A fact the daemon cannot establish reads as `nil`, and
//! so does a field outside the list (future fields are then not a breaking change). Arithmetic
//! or comparison on `nil` fails, so a misspelt field (`p.idel > 60`) makes the judge error, and
//! an erroring judge yields no verdict.
//!
//! A view is valid for one evaluation only. Every read goes through a resolver function scoped
//! to that evaluation; a view a judge stashed and reads later fails, and can never read the
//! facts of another process. Views and the tables they return are read-only.

use std::cell::RefCell;
use std::collections::HashMap;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use mlua::{
    AnyUserData, Function, IntoLua, Lua, MetaMethod, Table, UserData, UserDataMethods, Value,
};

use crate::facts::{FactView, OriginKind, ProcKey};
use crate::rules::schema::command_line;

/// The userdata handed to a `judge`.
pub(super) struct ProcView {
    key: ProcKey,
    /// The evaluation's [`Resolver`], as a scoped Lua function.
    resolver: Function,
}

impl ProcView {
    pub(super) fn create(lua: &Lua, key: ProcKey, resolver: Function) -> mlua::Result<AnyUserData> {
        lua.create_userdata(Self { key, resolver })
    }
}

impl UserData for ProcView {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        // No `__newindex`: assigning to a field fails.
        methods.add_meta_function(
            MetaMethod::Index,
            |_, (view, field): (AnyUserData, Value)| {
                let resolver = view.borrow::<Self>()?.resolver.clone();
                resolver.call::<Value>((view, field))
            },
        );
    }
}

/// Computes the fields of every view of one evaluation, and caches them for it.
pub(super) struct Resolver<'a> {
    view: FactView<'a>,
    /// The environment variables the rule source allowed.
    env: &'a [String],
    cache: RefCell<HashMap<(ProcKey, String), Value>>,
}

impl<'a> Resolver<'a> {
    pub(super) fn new(view: FactView<'a>, env: &'a [String]) -> Self {
        Self {
            view,
            env,
            cache: RefCell::default(),
        }
    }

    /// The value of `field` of the view `view`.
    pub(super) fn field(
        &self,
        lua: &Lua,
        view: &AnyUserData,
        field: &Value,
    ) -> mlua::Result<Value> {
        let Value::String(name) = field else {
            return Ok(Value::Nil);
        };
        let Ok(name) = name.to_str() else {
            return Ok(Value::Nil);
        };
        let (key, resolver) = {
            let view = view.borrow::<ProcView>()?;
            (view.key, view.resolver.clone())
        };
        let cache_key = (key, name.to_owned());
        if let Some(value) = self.cache.borrow().get(&cache_key) {
            return Ok(value.clone());
        }
        let value = self.compute(lua, key, &resolver, &name)?;
        self.cache.borrow_mut().insert(cache_key, value.clone());
        Ok(value)
    }

    fn compute(
        &self,
        lua: &Lua,
        key: ProcKey,
        resolver: &Function,
        name: &str,
    ) -> mlua::Result<Value> {
        let table = self.view.table();
        let Some(process) = table.get(key) else {
            return Ok(Value::Nil);
        };
        let facts = || self.view.facts(key);
        let secs = |d: std::time::Duration| d.as_secs_f64();
        match name {
            "pid" => f64::from(key.pid).into_lua(lua),
            "ppid" => f64::from(process.info.ppid).into_lua(lua),
            "exe" => process.cmdline().map(|c| c.exe.as_str()).into_lua(lua),
            "argv" => match process.cmdline() {
                Some(c) => frozen(lua.create_sequence_from(c.argv.iter().map(String::as_str))?),
                None => Ok(Value::Nil),
            },
            "cmd" => process.cmdline().map(command_line).into_lua(lua),
            "cwd" => path(lua, process.cwd()),
            "age" => facts().map(|f| secs(f.age)).into_lua(lua),
            "rss" => process.info.rss.map(|b| b as f64).into_lua(lua),
            "cpu" => facts().and_then(|f| f.cpu).into_lua(lua),
            "idle" => facts().map(|f| secs(f.idle)).into_lua(lua),
            "orphan" => (process.info.ppid == 1).into_lua(lua),
            "session_alive" => facts().and_then(|f| f.session_alive).into_lua(lua),
            "origin" => match facts() {
                Some(f) => {
                    let origin = lua.create_table()?;
                    let kind = f.origin.kind.map(|k| match k {
                        OriginKind::Agent => "agent",
                        OriginKind::Terminal => "terminal",
                    });
                    origin.raw_set("kind", kind)?;
                    origin.raw_set("alive", f.origin.alive)?;
                    frozen(origin)
                }
                None => Ok(Value::Nil),
            },
            "repo" => path(lua, facts().and_then(|f| f.repo).as_ref().map(|r| r.root())),
            "env" => match process.cmdline().and_then(|c| c.env.as_ref()) {
                Some(env) => {
                    let allowed = self
                        .env
                        .iter()
                        .filter_map(|name| Some((name.as_str(), env.get(name)?.as_str())));
                    frozen(lua.create_table_from(allowed)?)
                }
                // The kernel withheld the environment: unknown, not empty.
                None => Ok(Value::Nil),
            },
            "clients" => process.sockets().map(|s| s.inbound as f64).into_lua(lua),
            "listening" => match process.sockets() {
                Some(s) => frozen(lua.create_sequence_from(s.listening.iter().copied())?),
                None => Ok(Value::Nil),
            },
            "parent" => match table.parent_of(process) {
                Some(parent) => {
                    ProcView::create(lua, parent.key(), resolver.clone())?.into_lua(lua)
                }
                None => Ok(Value::Nil),
            },
            "children" => {
                let children = table
                    .children_of(process)
                    .map(|child| ProcView::create(lua, child.key(), resolver.clone()))
                    .collect::<mlua::Result<Vec<_>>>()?;
                frozen(lua.create_sequence_from(children)?)
            }
            "newer_twins" => self.view.newer_twins(key).map(|n| n as f64).into_lua(lua),
            _ => Ok(Value::Nil),
        }
    }
}

fn frozen(table: Table) -> mlua::Result<Value> {
    table.set_readonly(true);
    Ok(Value::Table(table))
}

/// A path as a Lua string of its bytes (paths need not be UTF-8).
fn path(lua: &Lua, path: Option<&Path>) -> mlua::Result<Value> {
    match path {
        Some(p) => lua
            .create_string(p.as_os_str().as_bytes())
            .map(Value::String),
        None => Ok(Value::Nil),
    }
}
