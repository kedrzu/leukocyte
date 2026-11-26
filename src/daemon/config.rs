//! Where the daemon keeps its files, and its one configuration file.

use std::ffi::OsString;
use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::engine::Mode;

/// The scan interval.
pub const SCAN_INTERVAL: Duration = Duration::from_secs(5);

/// Overrides every path of the daemon; tests and end-to-end runs set it so they never touch an
/// installed daemon.
pub const HOME_ENV: &str = "LEUKOCYTE_HOME";
/// Overrides [`SCAN_INTERVAL`], in milliseconds; honoured only together with [`HOME_ENV`], so an
/// installed daemon cannot be misconfigured.
pub const INTERVAL_ENV: &str = "LEUKOCYTE_SCAN_INTERVAL_MS";

/// The daemon's directories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// The socket and state.
    pub data: PathBuf,
    /// The action log and the daemon's own log.
    pub logs: PathBuf,
    /// `config.toml` and the personal rules.
    pub config: PathBuf,
    /// Set by [`HOME_ENV`]: the paths are a test's, not the installed daemon's.
    pub isolated: bool,
}

impl Paths {
    /// The paths from the environment: [`HOME_ENV`] when set, else the user's home.
    pub fn from_env() -> io::Result<Self> {
        Self::resolve(
            std::env::var_os(HOME_ENV),
            std::env::var_os("HOME").map(PathBuf::from),
        )
    }

    fn resolve(leukocyte_home: Option<OsString>, home: Option<PathBuf>) -> io::Result<Self> {
        if let Some(dir) = leukocyte_home.filter(|d| !d.is_empty()) {
            return Ok(Self::under(Path::new(&dir)));
        }
        let home = home
            .filter(|h| h.is_absolute())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
        Ok(Self {
            data: home.join("Library/Application Support/leukocyte"),
            logs: home.join("Library/Logs/leukocyte"),
            config: home.join(".config/leukocyte"),
            isolated: false,
        })
    }

    /// Every path under `dir`, as with [`HOME_ENV`] set to it.
    pub fn under(dir: &Path) -> Self {
        Self {
            data: dir.join("data"),
            logs: dir.join("logs"),
            config: dir.join("config"),
            isolated: true,
        }
    }

    pub fn socket(&self) -> PathBuf {
        self.data.join("leukocyte.sock")
    }

    pub fn config_file(&self) -> PathBuf {
        self.config.join("config.toml")
    }

    pub fn personal_rules(&self) -> PathBuf {
        self.config.join("rules.lua")
    }

    pub fn action_log(&self) -> PathBuf {
        self.logs.join("actions.jsonl")
    }

    /// Where launchd sends the daemon's stdout and stderr.
    pub fn daemon_log(&self) -> PathBuf {
        self.logs.join("daemon.log")
    }

    /// Creates the directories, each private to the user (0700), and tightens one that exists.
    pub fn create_dirs(&self) -> io::Result<()> {
        for dir in [&self.data, &self.logs, &self.config] {
            DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
}

/// The scan interval: [`SCAN_INTERVAL`], or [`INTERVAL_ENV`] when the paths are isolated.
pub fn scan_interval(isolated: bool, override_ms: Option<OsString>) -> Duration {
    override_ms
        .filter(|_| isolated)
        .and_then(|ms| ms.to_str()?.parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .map_or(SCAN_INTERVAL, Duration::from_millis)
}

/// `mode` in `config.toml`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfigMode {
    #[default]
    Observe,
    Enforce,
}

impl From<ConfigMode> for Mode {
    fn from(mode: ConfigMode) -> Self {
        match mode {
            ConfigMode::Observe => Self::Observe,
            ConfigMode::Enforce => Self::Enforce,
        }
    }
}

/// `config.toml`. Nothing else is configurable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub mode: ConfigMode,
    /// Absolute paths of the registered repos.
    #[serde(default)]
    pub repos: Vec<PathBuf>,
}

impl Config {
    pub fn parse(text: &str) -> Result<Self, String> {
        let config: Self = toml::from_str(text).map_err(|e| e.to_string())?;
        if let Some(relative) = config.repos.iter().find(|r| !r.is_absolute()) {
            return Err(format!(
                "repos: \"{}\" is not an absolute path",
                relative.display()
            ));
        }
        Ok(config)
    }

    /// Creates `path` with the default config (`mode = "observe"`, no repos) when it does not
    /// exist. Never overwrites a file.
    pub fn create_default(path: &Path) -> io::Result<()> {
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(file) => {
                drop(file);
                Self::default().write(path)
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Writes the config to `path`, replacing it atomically.
    pub fn write(&self, path: &Path) -> io::Result<()> {
        let text = toml::to_string(self).map_err(io::Error::other)?;
        let tmp = path.with_extension("toml.tmp");
        fs::write(&tmp, text)?;
        fs::rename(&tmp, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_existing_config_is_never_overwritten() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.toml");
        fs::write(&path, "mode = \"enforce\"\n").unwrap();
        Config::create_default(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "mode = \"enforce\"\n");
    }

    #[test]
    fn a_config_without_mode_observes() {
        assert_eq!(Config::parse("").unwrap().mode, ConfigMode::Observe);
    }

    #[test]
    fn config_rejects_unknown_keys_and_relative_repos() {
        assert!(Config::parse("mod = \"enforce\"").is_err());
        assert!(Config::parse("mode = \"kill\"").is_err());
        assert!(Config::parse("repos = [\"rel/path\"]").is_err());
        let ok = Config::parse("mode = \"enforce\"\nrepos = [\"/a/b\"]").unwrap();
        assert_eq!(ok.mode, ConfigMode::Enforce);
        assert_eq!(ok.repos, vec![PathBuf::from("/a/b")]);
    }

    #[test]
    fn leukocyte_home_overrides_every_path() {
        let paths = Paths::resolve(Some("/tmp/lk".into()), Some("/Users/u".into())).unwrap();
        assert!(paths.isolated);
        for p in [
            paths.socket(),
            paths.config_file(),
            paths.personal_rules(),
            paths.action_log(),
            paths.daemon_log(),
        ] {
            assert!(p.starts_with("/tmp/lk"), "{}", p.display());
        }
    }

    #[test]
    fn default_paths_live_under_home() {
        let paths = Paths::resolve(None, Some("/Users/u".into())).unwrap();
        assert!(!paths.isolated);
        assert_eq!(
            paths.socket(),
            Path::new("/Users/u/Library/Application Support/leukocyte/leukocyte.sock")
        );
        assert_eq!(
            paths.action_log(),
            Path::new("/Users/u/Library/Logs/leukocyte/actions.jsonl")
        );
        assert_eq!(
            paths.personal_rules(),
            Path::new("/Users/u/.config/leukocyte/rules.lua")
        );
        assert!(Paths::resolve(None, None).is_err());
    }

    #[test]
    fn the_interval_override_needs_an_isolated_home() {
        assert_eq!(scan_interval(false, Some("100".into())), SCAN_INTERVAL);
        assert_eq!(
            scan_interval(true, Some("100".into())),
            Duration::from_millis(100)
        );
        assert_eq!(scan_interval(true, Some("x".into())), SCAN_INTERVAL);
        assert_eq!(scan_interval(true, Some("0".into())), SCAN_INTERVAL);
        assert_eq!(scan_interval(true, None), SCAN_INTERVAL);
    }

    #[test]
    fn created_dirs_are_private() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::under(tmp.path());
        fs::create_dir_all(&paths.logs).unwrap();
        fs::set_permissions(&paths.logs, fs::Permissions::from_mode(0o755)).unwrap();
        paths.create_dirs().unwrap();
        for dir in [&paths.data, &paths.logs, &paths.config] {
            let mode = fs::metadata(dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{}", dir.display());
        }
    }
}
