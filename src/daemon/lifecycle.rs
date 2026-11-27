//! The daemon follows its own executable, so the Homebrew cask needs no install hooks.
//!
//! `brew upgrade` replaces `Leukocyte.app` under the running daemon, and `brew uninstall` removes
//! it; the cask cannot tell the two apart, and its hooks are deprecated. So the daemon re-reads
//! its executable's identity every scan:
//!
//! - replaced (the same identity, different from the one it started from, on
//!   [`RESTART_AFTER_SCANS`] scans in a row): it exits with [`RESTART_EXIT_CODE`], and launchd
//!   (`KeepAlive { SuccessfulExit = false }`) starts the new binary;
//! - missing for [`UNINSTALL_AFTER`] without a break: it removes its LaunchAgent plist when that
//!   runs this executable, and exits 0, which launchd does not restart. An upgrade leaves the path
//!   empty for seconds, far under the threshold.
//!
//! Off when `LEUKOCYTE_HOME` is set and outside an `.app` bundle (a `cargo` build).

use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::platform::{launchd, notify};

/// How long the executable must be missing, without a break, before the daemon takes the app as
/// uninstalled: with the scan interval on top, cleanup ends within two minutes.
pub const UNINSTALL_AFTER: Duration = Duration::from_secs(110);

/// How many scans in a row must see the same replaced executable before the daemon restarts.
pub const RESTART_AFTER_SCANS: u32 = 2;

/// The exit code that asks launchd for a restart: `EX_TEMPFAIL`, a non-zero code, so
/// `SuccessfulExit = false` applies.
const RESTART_EXIT_CODE: u8 = 75;

/// Which file a path names: a replaced file differs in at least one field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
}

impl Identity {
    fn of(meta: &fs::Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.size(),
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
        }
    }
}

/// One look at the executable's path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    Present(Identity),
    Missing,
    /// The path could not be read (not `NotFound`): never acted on.
    Unknown,
}

impl Observation {
    fn of(path: &Path) -> Self {
        match fs::metadata(path) {
            Ok(meta) => Self::Present(Identity::of(&meta)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Self::Missing,
            Err(_) => Self::Unknown,
        }
    }
}

/// What the daemon does after an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Continue,
    /// The executable was replaced: exit with [`RESTART_EXIT_CODE`].
    Restart,
    /// The executable is gone: remove the plist if it is ours, and exit 0.
    Uninstall,
}

/// The decision logic, fed with observations; no I/O.
#[derive(Debug)]
pub struct Tracker {
    active: bool,
    original: Identity,
    missing_since: Option<Instant>,
    /// A replacement seen and on how many scans in a row.
    replaced: Option<(Identity, u32)>,
}

impl Tracker {
    /// A tracker of the executable at `exe`, whose identity at startup was `original`. Inactive,
    /// always deciding [`Decision::Continue`], when `isolated` or when `exe` is not in an `.app`.
    pub fn new(isolated: bool, exe: &Path, original: Identity) -> Self {
        Self {
            active: !isolated && notify::app_bundle_of(exe).is_some(),
            original,
            missing_since: None,
            replaced: None,
        }
    }

    pub fn observe(&mut self, seen: Observation, now: Instant) -> Decision {
        if !self.active {
            return Decision::Continue;
        }
        match seen {
            Observation::Present(id) if id == self.original => {
                self.missing_since = None;
                self.replaced = None;
                Decision::Continue
            }
            Observation::Present(id) => {
                self.missing_since = None;
                let scans = match self.replaced {
                    Some((prev, n)) if prev == id => n.saturating_add(1),
                    _ => 1,
                };
                self.replaced = Some((id, scans));
                if scans >= RESTART_AFTER_SCANS {
                    Decision::Restart
                } else {
                    Decision::Continue
                }
            }
            Observation::Missing => {
                self.replaced = None;
                let since = *self.missing_since.get_or_insert(now);
                if now.saturating_duration_since(since) >= UNINSTALL_AFTER {
                    // Restart the clock, so a removal that failed is retried after another
                    // threshold rather than on every scan.
                    self.missing_since = Some(now);
                    Decision::Uninstall
                } else {
                    Decision::Continue
                }
            }
            Observation::Unknown => {
                self.missing_since = None;
                self.replaced = None;
                Decision::Continue
            }
        }
    }
}

/// How the daemon ends when its executable goes away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// Replaced: exit non-zero so launchd starts the new binary.
    Restart,
    /// Uninstalled: exit 0 so launchd does not.
    Uninstalled,
}

impl From<Exit> for std::process::ExitCode {
    fn from(exit: Exit) -> Self {
        match exit {
            Exit::Restart => Self::from(RESTART_EXIT_CODE),
            Exit::Uninstalled => Self::SUCCESS,
        }
    }
}

/// The tracker of this process's executable.
pub struct SelfWatch {
    exe: PathBuf,
    tracker: Tracker,
}

impl SelfWatch {
    /// `None` (logged) when the executable cannot be found or read; then nothing is watched.
    pub fn for_this_process(isolated: bool) -> Option<Self> {
        let found = std::env::current_exe()
            .and_then(|exe| exe.canonicalize())
            .and_then(|exe| fs::metadata(&exe).map(|meta| (exe, Identity::of(&meta))));
        match found {
            Ok((exe, original)) => Some(Self {
                tracker: Tracker::new(isolated, &exe, original),
                exe,
            }),
            Err(e) => {
                eprintln!("leukocyte: cannot read the executable ({e}); upgrades are not followed");
                None
            }
        }
    }

    /// Looks at the executable once; `Some` when the daemon should exit now.
    pub fn check(&mut self) -> Option<Exit> {
        match self
            .tracker
            .observe(Observation::of(&self.exe), Instant::now())
        {
            Decision::Continue => None,
            Decision::Restart => {
                eprintln!("leukocyte: binary replaced, restarting");
                Some(Exit::Restart)
            }
            Decision::Uninstall => self.uninstall(),
        }
    }

    fn uninstall(&self) -> Option<Exit> {
        match launchd::remove_if_owned(&self.exe) {
            Ok(launchd::Removal::Removed) => {
                eprintln!("leukocyte: app removed, uninstalling the login agent");
            }
            Ok(launchd::Removal::NotInstalled) => {
                eprintln!("leukocyte: app removed, and no login agent is installed; exiting");
            }
            Ok(launchd::Removal::NotOwned(program)) => {
                eprintln!(
                    "leukocyte: app removed; the login agent runs {program}, so it stays; exiting"
                );
            }
            Err(e) => {
                // Keep running: the tracker retries after another threshold.
                eprintln!("leukocyte: app removed, but the login agent could not be removed: {e}");
                return None;
            }
        }
        Some(Exit::Uninstalled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP_EXE: &str = "/Applications/Leukocyte.app/Contents/MacOS/leukocyte";

    fn id(ino: u64) -> Identity {
        Identity {
            dev: 1,
            ino,
            size: 100,
            mtime: 1_700_000_000,
            mtime_nsec: 0,
        }
    }

    /// Feeds one observation per 5 s scan, starting at `start`, and returns every decision.
    fn run(tracker: &mut Tracker, start: Instant, seen: &[Observation]) -> Vec<Decision> {
        seen.iter()
            .enumerate()
            .map(|(i, s)| {
                let at = start + Duration::from_secs(5 * u64::try_from(i).unwrap());
                tracker.observe(*s, at)
            })
            .collect()
    }

    fn missing_for(secs: u64) -> Vec<Observation> {
        vec![Observation::Missing; usize::try_from(secs / 5 + 1).unwrap()]
    }

    #[test]
    fn a_short_gap_then_the_same_binary_does_nothing() {
        let mut t = Tracker::new(false, Path::new(APP_EXE), id(1));
        let mut seen = missing_for(30);
        seen.push(Observation::Present(id(1)));
        // The clock restarts after the gap: another 105 s missing is still under the threshold.
        seen.extend(missing_for(105));
        let start = Instant::now();
        assert!(
            run(&mut t, start, &seen)
                .iter()
                .all(|d| *d == Decision::Continue)
        );
    }

    #[test]
    fn an_upgrade_gap_then_a_new_binary_restarts_without_uninstalling() {
        let mut t = Tracker::new(false, Path::new(APP_EXE), id(1));
        let mut seen = missing_for(30);
        seen.extend([Observation::Present(id(2)), Observation::Present(id(2))]);
        let decisions = run(&mut t, Instant::now(), &seen);
        assert!(!decisions.contains(&Decision::Uninstall));
        assert_eq!(decisions.last(), Some(&Decision::Restart));
        assert_eq!(
            decisions
                .iter()
                .filter(|d| **d != Decision::Continue)
                .count(),
            1
        );
    }

    #[test]
    fn missing_past_the_threshold_uninstalls() {
        let mut t = Tracker::new(false, Path::new(APP_EXE), id(1));
        let decisions = run(&mut t, Instant::now(), &missing_for(130));
        let first = decisions
            .iter()
            .position(|d| *d == Decision::Uninstall)
            .unwrap();
        // The first scan that is 110 s after the first missing one.
        assert_eq!(first, 22);
        assert!(decisions[..first].iter().all(|d| *d == Decision::Continue));
    }

    #[test]
    fn a_replaced_binary_restarts_only_when_stable_for_two_scans() {
        let mut t = Tracker::new(false, Path::new(APP_EXE), id(1));
        let seen = [
            Observation::Present(id(2)),
            Observation::Present(id(3)),
            Observation::Present(id(3)),
        ];
        assert_eq!(
            run(&mut t, Instant::now(), &seen),
            [Decision::Continue, Decision::Continue, Decision::Restart]
        );

        // A replacement that reverts in between does not count.
        let mut t = Tracker::new(false, Path::new(APP_EXE), id(1));
        let seen = [
            Observation::Present(id(2)),
            Observation::Present(id(1)),
            Observation::Present(id(2)),
        ];
        assert!(
            run(&mut t, Instant::now(), &seen)
                .iter()
                .all(|d| *d == Decision::Continue)
        );
    }

    #[test]
    fn an_unreadable_path_breaks_the_missing_streak() {
        let mut t = Tracker::new(false, Path::new(APP_EXE), id(1));
        let mut seen = missing_for(100);
        seen.push(Observation::Unknown);
        seen.extend(missing_for(100));
        assert!(
            run(&mut t, Instant::now(), &seen)
                .iter()
                .all(|d| *d == Decision::Continue)
        );
    }

    #[test]
    fn an_isolated_home_or_a_bare_binary_never_acts() {
        let mut seen = missing_for(600);
        seen.extend([Observation::Present(id(2)); 5]);
        for (isolated, exe) in [
            (true, APP_EXE),
            (false, "/Users/u/dev/leukocyte/target/debug/leukocyte"),
            (false, "/opt/homebrew/bin/leukocyte"),
        ] {
            let mut t = Tracker::new(isolated, Path::new(exe), id(1));
            assert!(
                run(&mut t, Instant::now(), &seen)
                    .iter()
                    .all(|d| *d == Decision::Continue),
                "isolated {isolated}, {exe}"
            );
        }
    }

    #[test]
    fn identity_tells_a_replaced_file_from_the_same_one() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("leukocyte");
        fs::write(&path, b"old").unwrap();
        let before = Observation::of(&path);
        assert_eq!(Observation::of(&path), before);

        // Homebrew moves the new app into place: a new file under the same path.
        let new = tmp.path().join("leukocyte.new");
        fs::write(&new, b"new").unwrap();
        fs::rename(&new, &path).unwrap();
        assert!(matches!(Observation::of(&path), Observation::Present(_)));
        assert_ne!(Observation::of(&path), before);

        fs::remove_file(&path).unwrap();
        assert_eq!(Observation::of(&path), Observation::Missing);
    }
}
