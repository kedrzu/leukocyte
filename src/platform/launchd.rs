//! Installing and removing the daemon's LaunchAgent.
//!
//! Refused while `LEUKOCYTE_HOME` is set: a test or an end-to-end run never installs or removes
//! the real LaunchAgent.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The LaunchAgent's label, and its plist's name.
pub const LABEL: &str = "dev.leukocyte.daemon";

const LAUNCHCTL: &str = "/bin/launchctl";
const PLUTIL: &str = "/usr/bin/plutil";

/// Writes `~/Library/LaunchAgents/dev.leukocyte.daemon.plist`, running the current executable
/// as `daemon` with its output in `log`, and bootstraps it into the user's GUI domain. An
/// already loaded agent is booted out first, so installing again picks up a moved binary.
/// Returns the plist's path.
pub fn install(log: &Path) -> io::Result<PathBuf> {
    refuse_if_isolated(std::env::var_os("LEUKOCYTE_HOME"))?;
    let exe = std::env::current_exe()?.canonicalize()?;
    let plist = plist_path()?;
    if let Some(dir) = plist.parent() {
        fs::create_dir_all(dir)?;
    }
    // Not loaded is the usual case; any other failure shows up in the bootstrap below.
    let _ = launchctl(&["bootout", &service_target()]);
    fs::write(&plist, render(&exe, log))?;
    launchctl(&["bootstrap", &domain_target(), &plist.to_string_lossy()])?;
    Ok(plist)
}

/// Boots the agent out and removes its plist. Not being loaded or installed is not an error.
pub fn uninstall() -> io::Result<()> {
    refuse_if_isolated(std::env::var_os("LEUKOCYTE_HOME"))?;
    let plist = plist_path()?;
    // Booting out a job that is not loaded fails, and not loaded is the goal state; a job
    // that is still loaded afterwards is the real failure.
    if let Err(e) = launchctl(&["bootout", &service_target()])
        && launchctl(&["print", &service_target()]).is_ok()
    {
        return Err(e);
    }
    match fs::remove_file(&plist) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// What [`remove_if_owned`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Removal {
    /// The plist ran `exe` and is gone.
    Removed,
    /// There was no plist.
    NotInstalled,
    /// The plist runs another program, given here; it was left in place.
    NotOwned(String),
}

/// Removes the agent's plist, but only when its program (`ProgramArguments[0]`) is `exe`: the
/// daemon of a removed app cleans up after itself without deleting the agent of another install.
/// It does not boot the agent out: the caller is that agent, and exits after this.
pub fn remove_if_owned(exe: &Path) -> io::Result<Removal> {
    refuse_if_isolated(std::env::var_os("LEUKOCYTE_HOME"))?;
    remove_plist_if_owned(&plist_path()?, exe)
}

fn remove_plist_if_owned(plist: &Path, exe: &Path) -> io::Result<Removal> {
    match fs::symlink_metadata(plist) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Removal::NotInstalled),
        Err(e) => return Err(e),
    }
    let program = program_of(plist)?;
    if Path::new(&program) != exe {
        return Ok(Removal::NotOwned(program));
    }
    match fs::remove_file(plist) {
        Ok(()) => Ok(Removal::Removed),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Removal::NotInstalled),
        Err(e) => Err(e),
    }
}

/// The plist's `ProgramArguments[0]`.
fn program_of(plist: &Path) -> io::Result<String> {
    let output = Command::new(PLUTIL)
        .args(["-extract", "ProgramArguments.0", "raw", "-o", "-"])
        .arg(plist)
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "no ProgramArguments in {} ({}): {}",
            plist.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let text = String::from_utf8(output.stdout).map_err(io::Error::other)?;
    // `raw` ends the value with one newline.
    Ok(text.strip_suffix('\n').unwrap_or(&text).to_owned())
}

fn refuse_if_isolated(leukocyte_home: Option<OsString>) -> io::Result<()> {
    match leukocyte_home {
        Some(dir) if !dir.is_empty() => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "LEUKOCYTE_HOME is set: refusing to touch the installed LaunchAgent",
        )),
        _ => Ok(()),
    }
}

fn plist_path() -> io::Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|h| h.is_absolute())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
    Ok(home
        .join("Library/LaunchAgents")
        .join(format!("{LABEL}.plist")))
}

fn domain_target() -> String {
    format!("gui/{}", super::current_uid())
}

fn service_target() -> String {
    format!("{}/{LABEL}", domain_target())
}

/// Runs `launchctl` with `args`; a non-zero exit is an error carrying its stderr.
fn launchctl(args: &[&str]) -> io::Result<()> {
    let output = Command::new(LAUNCHCTL)
        .args(args)
        .stdin(Stdio::null())
        .output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "launchctl {} failed ({}): {}",
        args.first().copied().unwrap_or_default(),
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

/// The plist of the agent.
fn render(exe: &Path, log: &Path) -> String {
    let exe = xml_escape(&exe.to_string_lossy());
    let log = xml_escape(&log.to_string_lossy());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{LABEL}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{exe}</string>
		<string>daemon</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ProcessType</key>
	<string>Background</string>
	<key>LowPriorityIO</key>
	<true/>
	<key>Nice</key>
	<integer>10</integer>
	<key>StandardOutPath</key>
	<string>{log}</string>
	<key>StandardErrorPath</key>
	<string>{log}</string>
</dict>
</plist>
"#
    )
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_isolated_home_refuses_to_touch_the_launch_agent() {
        assert!(refuse_if_isolated(Some("/tmp/x".into())).is_err());
        assert!(refuse_if_isolated(Some("".into())).is_ok());
        assert!(refuse_if_isolated(None).is_ok());
    }

    #[test]
    fn only_a_plist_that_runs_this_executable_is_removed() {
        let tmp = tempfile::tempdir().unwrap();
        let log = Path::new("/tmp/daemon.log");
        let exe = Path::new("/Applications/Leuko & co.app/Contents/MacOS/leukocyte");
        let plist = tmp.path().join("agent.plist");

        // Another install's agent stays.
        let other = "/opt/homebrew/bin/leukocyte";
        fs::write(&plist, render(Path::new(other), log)).unwrap();
        assert_eq!(
            remove_plist_if_owned(&plist, exe).unwrap(),
            Removal::NotOwned(other.to_owned())
        );
        assert!(plist.exists());

        // A plist without a program is an error, and stays.
        fs::write(&plist, "<plist version=\"1.0\"><dict/></plist>").unwrap();
        assert!(remove_plist_if_owned(&plist, exe).is_err());
        assert!(plist.exists());

        // This executable's agent goes.
        fs::write(&plist, render(exe, log)).unwrap();
        assert_eq!(
            remove_plist_if_owned(&plist, exe).unwrap(),
            Removal::Removed
        );
        assert!(!plist.exists());

        // No plist: nothing to do.
        assert_eq!(
            remove_plist_if_owned(&plist, exe).unwrap(),
            Removal::NotInstalled
        );
    }

    #[test]
    fn the_plist_is_valid_and_runs_the_daemon() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("agent.plist");
        let text = render(
            Path::new("/opt/leuko & co/leukocyte"),
            Path::new("/Users/u/Library/Logs/leukocyte/daemon.log"),
        );
        fs::write(&path, &text).unwrap();
        // plutil validates the XML and the plist structure.
        let lint =
            crate::test_support::output(Command::new("/usr/bin/plutil").arg("-lint").arg(&path))
                .unwrap();
        assert!(
            lint.status.success(),
            "{}",
            String::from_utf8_lossy(&lint.stdout)
        );
        let json = crate::test_support::output(
            Command::new("/usr/bin/plutil")
                .args(["-convert", "json", "-o", "-"])
                .arg(&path),
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
        assert_eq!(v["Label"], LABEL);
        assert_eq!(
            v["ProgramArguments"],
            serde_json::json!(["/opt/leuko & co/leukocyte", "daemon"])
        );
        assert_eq!(v["KeepAlive"]["SuccessfulExit"], false);
        assert_eq!(v["ProcessType"], "Background");
        assert_eq!(v["LowPriorityIO"], true);
        assert_eq!(v["Nice"], 10);
        assert_eq!(
            v["StandardErrorPath"],
            "/Users/u/Library/Logs/leukocyte/daemon.log"
        );
        assert_eq!(v["StandardOutPath"], v["StandardErrorPath"]);
    }
}
