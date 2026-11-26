//! The typed form of a rules file (`api = 1`) and the verdicts a rule produces.

use std::fmt;
use std::time::Duration;

use mlua::RegistryKey;
use regex::Regex;

use crate::platform::Cmdline;

/// One rule of a rules file, validated.
#[derive(Debug)]
pub struct Rule {
    pub name: String,
    pub matcher: Matcher,
    pub when: When,
    /// The subtree must have been idle at least this long.
    pub idle: Option<Duration>,
    pub quarantine: Duration,
    pub grace: Duration,
    pub signal: Signal,
    /// `false` (the default) means the engine downgrades a kill to a report.
    pub enforce: bool,
    /// The rule's `judge` function, in the registry of the rule set's Lua state.
    pub(super) judge: Option<RegistryKey>,
}

/// What a rule's `match` or `re` selects, run in Rust over [`command_line`] before any Lua.
#[derive(Debug)]
pub enum Matcher {
    /// A substring of the command line, at least [`MIN_MATCH_CHARS`] characters long.
    Substring(String),
    Regex(Regex),
}

/// The shortest `match` (and `re` pattern) accepted: a shorter one selects too much.
pub const MIN_MATCH_CHARS: usize = 4;

impl Matcher {
    pub fn is_match(&self, cmd: &str) -> bool {
        match self {
            Self::Substring(needle) => cmd.contains(needle.as_str()),
            Self::Regex(re) => re.is_match(cmd),
        }
    }
}

/// The string `match` and `re` run against: the executable, a space, and argv joined by spaces.
pub fn command_line(cmdline: &Cmdline) -> String {
    let mut cmd = cmdline.exe.clone();
    for arg in &cmdline.argv {
        cmd.push(' ');
        cmd.push_str(arg);
    }
    cmd
}

/// The structural condition of a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum When {
    /// Orphaned, and the origin is known to be dead. An unknown origin protects.
    Abandoned,
    /// Reparented to launchd (ppid 1).
    Orphaned,
    /// No structural condition.
    Always,
}

/// The signals a rule may send first; the kill escalates to `SIGKILL` after `grace`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    Term,
    Int,
    Hup,
    Quit,
}

impl Signal {
    pub fn raw(self) -> libc::c_int {
        match self {
            Self::Term => libc::SIGTERM,
            Self::Int => libc::SIGINT,
            Self::Hup => libc::SIGHUP,
            Self::Quit => libc::SIGQUIT,
        }
    }

    pub(super) fn parse(name: &str) -> Option<Self> {
        match name {
            "TERM" => Some(Self::Term),
            "INT" => Some(Self::Int),
            "HUP" => Some(Self::Hup),
            "QUIT" => Some(Self::Quit),
            _ => None,
        }
    }
}

/// What a rule says about one process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Kill,
    Report,
    Protect,
}

impl Verb {
    pub(super) fn parse(name: &str) -> Option<Self> {
        match name {
            "kill" => Some(Self::Kill),
            "report" => Some(Self::Report),
            "protect" => Some(Self::Protect),
            _ => None,
        }
    }
}

/// A rule's raw opinion of a process. The engine applies the rule's flags (`enforce`,
/// `quarantine`, `grace`, `signal`) and merges verdicts across rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub verb: Verb,
    /// Written by the daemon from the facts, e.g. `orphaned · origin agent dead · idle 47m`.
    pub reason: String,
    /// What the `judge` returned as its second value, to be appended to `reason`.
    pub judge_reason: Option<String>,
}

/// Parses `"<n>s|m|h|d"`, or a sequence of them such as `"1h30m"`.
pub fn parse_duration(text: &str) -> Option<Duration> {
    let mut total: u64 = 0;
    let mut number: Option<u64> = None;
    for c in text.chars() {
        if let Some(digit) = c.to_digit(10) {
            let n = number
                .unwrap_or(0)
                .checked_mul(10)?
                .checked_add(digit.into())?;
            number = Some(n);
            continue;
        }
        let unit: u64 = match c {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86_400,
            _ => return None,
        };
        total = total.checked_add(number.take()?.checked_mul(unit)?)?;
    }
    if number.is_some() || text.is_empty() {
        return None;
    }
    Some(Duration::from_secs(total))
}

/// A duration for a reason: `47s`, `47m`, `2h5m`, `3d4h`.
pub struct Human(pub Duration);

impl fmt::Display for Human {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.0.as_secs();
        let (days, hours, mins) = (secs / 86_400, secs % 86_400 / 3600, secs % 3600 / 60);
        match (days, hours, mins) {
            (0, 0, 0) => write!(f, "{secs}s"),
            (0, 0, m) => write!(f, "{m}m"),
            (0, h, 0) => write!(f, "{h}h"),
            (0, h, m) => write!(f, "{h}h{m}m"),
            (d, 0, _) => write!(f, "{d}d"),
            (d, h, _) => write!(f, "{d}d{h}h"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_parse_single_units_and_combinations() {
        let secs = |s| Some(Duration::from_secs(s));
        assert_eq!(parse_duration("5s"), secs(5));
        assert_eq!(parse_duration("20m"), secs(1200));
        assert_eq!(parse_duration("2h"), secs(7200));
        assert_eq!(parse_duration("1d"), secs(86_400));
        assert_eq!(parse_duration("1h30m"), secs(5400));
        for bad in [
            "",
            "5",
            "m",
            "5x",
            "1h 30m",
            "-5s",
            "1.5h",
            "99999999999999999999d",
        ] {
            assert_eq!(parse_duration(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn durations_format_for_humans() {
        let human = |s| Human(Duration::from_secs(s)).to_string();
        assert_eq!(human(47), "47s");
        assert_eq!(human(47 * 60 + 3), "47m");
        assert_eq!(human(7200), "2h");
        assert_eq!(human(7500), "2h5m");
        assert_eq!(human(86_400 * 3 + 3600 * 4), "3d4h");
    }

    #[test]
    fn the_command_line_is_the_executable_and_argv() {
        let cmdline = Cmdline {
            exe: "/usr/bin/node".to_owned(),
            argv: vec!["node".to_owned(), "x.js".to_owned()],
            env: None,
        };
        assert_eq!(command_line(&cmdline), "/usr/bin/node node x.js");
    }
}
