//! The action log: one JSON object per line for every action, kill report, fuse trip and error,
//! at `<logs>/actions.jsonl`, rotated by size.
//!
//! The log is private: the file is 0600 in a 0700 directory, and argv reaches it only as a
//! [`RedactedArgv`].

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use super::redact::RedactedArgv;

/// The size at which the log is rotated.
pub const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;
/// Rotated files kept: `actions.jsonl.1` (newest) to `actions.jsonl.3`.
pub const KEEP_ROTATED: usize = 3;

/// One line of the action log. Fields that do not apply to the event are left out.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Event {
    /// RFC 3339, UTC, milliseconds.
    pub ts: String,
    /// `action`, `kill_report`, `kill_failed`, `fuse`, `eval_error`, `rules_error`,
    /// `rules_loaded`, `config_error`, `config_loaded`, `scan_error`, `keep`.
    pub event: &'static str,
    /// The action's kind: `kill`, `report`, `would_kill`, `blocked`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// The rules file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<i32>,
    /// The process's start time, microseconds since the Unix epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub argv: Option<RedactedArgv>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The pids of a kill's subtree.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subtree: Option<Vec<i32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<KillReportFields>,
    /// The kills a fuse trip held back.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kills: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl Event {
    pub fn new(event: &'static str) -> Self {
        Self {
            ts: rfc3339(SystemTime::now()),
            event,
            ..Self::default()
        }
    }
}

/// What a kill did, by pid.
#[derive(Debug, Clone, Default, Serialize)]
pub struct KillReportFields {
    pub signalled: Vec<i32>,
    pub escalated: Vec<i32>,
    pub skipped: Vec<Skipped>,
    pub survivors_after: Vec<i32>,
    pub failed: Vec<Failed>,
    pub aborted: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Skipped {
    pub pid: i32,
    pub guard: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Failed {
    pub pid: i32,
    pub error: String,
}

/// The open action log.
#[derive(Debug)]
pub struct ActionLog {
    path: PathBuf,
    file: File,
    size: u64,
    max_bytes: u64,
}

impl ActionLog {
    /// Opens (or creates) the log at `path`, 0600 whatever mode it had.
    pub fn open(path: &Path) -> io::Result<Self> {
        Self::with_limit(path, MAX_LOG_BYTES)
    }

    fn with_limit(path: &Path, max_bytes: u64) -> io::Result<Self> {
        let file = open_private(path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            path: path.to_owned(),
            file,
            size,
            max_bytes,
        })
    }

    /// Appends one event, rotating first when the line would take the file past the limit.
    pub fn write(&mut self, event: &Event) -> io::Result<()> {
        let mut line = serde_json::to_vec(event).map_err(io::Error::other)?;
        line.push(b'\n');
        let len = u64::try_from(line.len()).unwrap_or(u64::MAX);
        if self.size > 0 && self.size.saturating_add(len) > self.max_bytes {
            self.rotate()?;
        }
        self.file.write_all(&line)?;
        self.size = self.size.saturating_add(len);
        Ok(())
    }

    fn rotate(&mut self) -> io::Result<()> {
        let numbered = |n: usize| {
            let mut name = self.path.as_os_str().to_owned();
            name.push(format!(".{n}"));
            PathBuf::from(name)
        };
        for n in (1..KEEP_ROTATED).rev() {
            let from = numbered(n);
            if from.exists() {
                fs::rename(&from, numbered(n + 1))?;
            }
        }
        fs::rename(&self.path, numbered(1))?;
        self.file = open_private(&self.path)?;
        self.size = 0;
        Ok(())
    }
}

fn open_private(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

/// `time` as RFC 3339 in UTC with milliseconds, e.g. `2026-11-26T09:41:07.123Z`.
pub fn rfc3339(time: SystemTime) -> String {
    let since = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = since.as_secs();
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        since.subsec_millis()
    )
}

/// The proleptic Gregorian date of a day count since 1970-01-01 (Howard Hinnant's
/// `civil_from_days`, for non-negative day counts).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn rfc3339_formats_utc() {
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        let t = UNIX_EPOCH + Duration::from_millis(1_795_686_067_123);
        assert_eq!(rfc3339(t), "2026-11-26T09:41:07.123Z");
        let leap = UNIX_EPOCH + Duration::from_secs(951_782_400);
        assert_eq!(rfc3339(leap), "2000-02-29T00:00:00.000Z");
    }

    #[test]
    fn the_log_is_0600_even_when_it_existed_wider() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("actions.jsonl");
        fs::write(&path, "").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let mut log = ActionLog::open(&path).unwrap();
        log.write(&Event::new("keep")).unwrap();
        assert_eq!(mode(&path), 0o600);
        let fresh = tmp.path().join("fresh.jsonl");
        ActionLog::open(&fresh).unwrap();
        assert_eq!(mode(&fresh), 0o600);
    }

    #[test]
    fn the_log_rotates_by_size_and_keeps_three() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("actions.jsonl");
        let mut log = ActionLog::with_limit(&path, 200).unwrap();
        let mut event = Event::new("keep");
        event.message = Some("x".repeat(120));
        for _ in 0..6 {
            log.write(&event).unwrap();
        }
        let rotated = |n: usize| tmp.path().join(format!("actions.jsonl.{n}"));
        for n in 1..=KEEP_ROTATED {
            assert!(rotated(n).exists(), "missing .{n}");
            assert_eq!(mode(&rotated(n)), 0o600);
        }
        assert!(!rotated(KEEP_ROTATED + 1).exists());
        assert_eq!(mode(&path), 0o600);
        let line = fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(parsed["event"], "keep");
        assert!(parsed.get("pid").is_none());
    }
}
