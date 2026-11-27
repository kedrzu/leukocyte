//! Reloading: each rules file and the config are re-read when they change, found by a
//! file-system watch on their directories and by a content check every tick as a backstop.
//!
//! Directories are watched, not files: editors replace a file atomically, and a watch on the
//! replaced file would die with it.

use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io;
use std::path::{Path, PathBuf};

use notify::{RecommendedWatcher, RecursiveMode, Watcher};

use crate::rules::{LoadError, RuleSet};

/// The name of a repo's rules file under `<repo>/.leukocyte/`, and of the personal one.
pub const RULES_FILE: &str = "rules.lua";
/// The directory of a repo's rules file.
pub const RULES_DIR: &str = ".leukocyte";

/// The content of a file as last seen: its hash, or `None` when it does not exist.
pub type Fingerprint = Option<u64>;

/// Reads a file whose absence is a valid state. `Ok(None)` when it does not exist.
pub fn read_optional(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

pub fn fingerprint(content: Option<&[u8]>) -> Fingerprint {
    content.map(|bytes| {
        let mut hasher = DefaultHasher::new();
        bytes.hash(&mut hasher);
        hasher.finish()
    })
}

/// What a [`RulesFile::refresh`] found.
#[derive(Debug, PartialEq, Eq)]
pub enum Refresh {
    /// The file is as it was.
    Unchanged,
    /// The file loaded; its rules are in force.
    Loaded,
    /// The file is gone; no rules from it.
    Removed,
    /// The file failed to load (or to be read); the previous rules stay in force.
    Failed(LoadError),
}

/// One rules file and the last valid rules loaded from it.
#[derive(Debug)]
pub struct RulesFile {
    path: PathBuf,
    rules: Option<RuleSet>,
    error: Option<LoadError>,
    seen: Option<Fingerprint>,
}

impl RulesFile {
    /// A file not read yet: the first [`refresh`](Self::refresh) loads it.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            rules: None,
            error: None,
            seen: None,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The rules in force: the last version of the file that loaded.
    pub fn rules(&self) -> Option<&RuleSet> {
        self.rules.as_ref()
    }

    /// Why the current version of the file did not load.
    pub fn error(&self) -> Option<&LoadError> {
        self.error.as_ref()
    }

    /// Re-reads the file and reloads it when its content changed. A file that fails keeps the
    /// previous rules in force; a deleted file drops them (an absent file means no rules).
    pub fn refresh(&mut self) -> Refresh {
        let name = self.path.display().to_string();
        let content = match read_optional(&self.path) {
            Ok(content) => content,
            Err(e) => {
                let error = LoadError {
                    file: name,
                    message: e.to_string(),
                };
                // A read error is retried every tick; it is reported only when it is new.
                self.seen = None;
                return self.fail(error);
            }
        };
        let print = fingerprint(content.as_deref());
        if self.seen == Some(print) {
            return Refresh::Unchanged;
        }
        self.seen = Some(print);
        let Some(content) = content else {
            self.rules = None;
            self.error = None;
            return Refresh::Removed;
        };
        let loaded = match &mut self.rules {
            Some(rules) => rules.reload(&content),
            None => RuleSet::load(&name, &content).map(|rules| {
                self.rules = Some(rules);
            }),
        };
        match loaded {
            Ok(()) => {
                self.error = None;
                Refresh::Loaded
            }
            Err(error) => self.fail(error),
        }
    }

    /// Records a failure; reported as [`Refresh::Failed`] only when it differs from the last
    /// one, so one broken edit is reported once.
    fn fail(&mut self, error: LoadError) -> Refresh {
        if self.error.as_ref() == Some(&error) {
            return Refresh::Unchanged;
        }
        self.error = Some(error.clone());
        Refresh::Failed(error)
    }
}

/// The watched directories. Without a watcher (it failed to start) the per-tick check alone
/// finds changes.
pub struct Watches {
    watcher: Option<RecommendedWatcher>,
    watched: HashSet<PathBuf>,
}

impl Watches {
    /// Starts a watcher that calls `on_change` with the paths of every event.
    pub fn new(on_change: impl Fn(Vec<PathBuf>) + Send + 'static) -> Result<Self, notify::Error> {
        let watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
            if let Ok(event) = event {
                on_change(event.paths);
            }
        })?;
        Ok(Self {
            watcher: Some(watcher),
            watched: HashSet::new(),
        })
    }

    /// No watcher: changes are found by the per-tick check only.
    pub fn none() -> Self {
        Self {
            watcher: None,
            watched: HashSet::new(),
        }
    }

    /// Watches exactly the directories of `wanted` that exist. Returns the errors of
    /// directories that could not be watched; they are retried on the next call.
    pub fn sync(&mut self, wanted: &[PathBuf]) -> Vec<(PathBuf, notify::Error)> {
        let Some(watcher) = &mut self.watcher else {
            return Vec::new();
        };
        let wanted: HashSet<&PathBuf> = wanted.iter().filter(|d| d.is_dir()).collect();
        let mut errors = Vec::new();
        let gone: Vec<PathBuf> = self
            .watched
            .iter()
            .filter(|d| !wanted.contains(d))
            .cloned()
            .collect();
        for dir in gone {
            // A directory that was deleted is no longer watched anyway.
            let _ = watcher.unwatch(&dir);
            self.watched.remove(&dir);
        }
        for dir in wanted {
            if self.watched.contains(dir) {
                continue;
            }
            match watcher.watch(dir, RecursiveMode::NonRecursive) {
                Ok(()) => {
                    self.watched.insert(dir.clone());
                }
                Err(e) => errors.push((dir.clone(), e)),
            }
        }
        errors
    }
}

/// Whether an event on `paths` may concern a rules file or the config.
pub fn is_relevant(paths: &[PathBuf]) -> bool {
    paths.iter().any(|p| {
        p.file_name()
            .is_some_and(|n| n == RULES_FILE || n == "config.toml")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"return { api = 1, rules = { { name = "a", match = "needle-a" } } }"#;
    const VALID_B: &str = r#"return { api = 1, rules = { { name = "b", match = "needle-b" } } }"#;
    const BROKEN: &str = "return { api = 1, rules = { { name = 1 } } }";

    fn rule_names(file: &RulesFile) -> Vec<String> {
        file.rules()
            .map(|r| r.rules().iter().map(|r| r.name.clone()).collect())
            .unwrap_or_default()
    }

    #[test]
    fn a_broken_edit_keeps_the_last_valid_rules_and_a_valid_edit_replaces_them() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(RULES_FILE);
        let mut file = RulesFile::new(path.clone());
        assert_eq!(file.refresh(), Refresh::Removed);
        assert!(file.rules().is_none());

        fs::write(&path, VALID).unwrap();
        assert_eq!(file.refresh(), Refresh::Loaded);
        assert_eq!(file.refresh(), Refresh::Unchanged);
        assert_eq!(rule_names(&file), ["a"]);

        fs::write(&path, BROKEN).unwrap();
        assert!(matches!(file.refresh(), Refresh::Failed(_)));
        assert_eq!(rule_names(&file), ["a"]);
        assert!(file.error().is_some());
        // Reported once.
        assert_eq!(file.refresh(), Refresh::Unchanged);

        fs::write(&path, VALID_B).unwrap();
        assert_eq!(file.refresh(), Refresh::Loaded);
        assert_eq!(rule_names(&file), ["b"]);
        assert!(file.error().is_none());

        fs::remove_file(&path).unwrap();
        assert_eq!(file.refresh(), Refresh::Removed);
        assert!(file.rules().is_none());
    }

    #[test]
    fn a_file_broken_from_the_start_has_no_rules_and_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(RULES_FILE);
        fs::write(&path, BROKEN).unwrap();
        let mut file = RulesFile::new(path);
        assert!(matches!(file.refresh(), Refresh::Failed(_)));
        assert!(file.rules().is_none());
        assert!(file.error().is_some());
    }

    #[test]
    fn only_rules_and_config_events_are_relevant() {
        assert!(is_relevant(&[PathBuf::from("/r/.leukocyte/rules.lua")]));
        assert!(is_relevant(&[PathBuf::from("/c/config.toml")]));
        assert!(!is_relevant(&[PathBuf::from(
            "/r/.leukocyte/rules.lua.swp"
        )]));
    }
}
