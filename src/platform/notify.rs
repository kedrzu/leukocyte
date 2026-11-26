//! User notifications through `osascript`, fire-and-forget.

use std::io;
use std::process::{Command, Stdio};

const OSASCRIPT: &str = "/usr/bin/osascript";

/// Shows a notification. Returns once `osascript` is started; a thread reaps it. Best effort:
/// whether a LaunchAgent's notification is visible is up to the system.
pub fn notify(title: &str, body: &str) -> io::Result<()> {
    let script = format!(
        "display notification {} with title {}",
        applescript_string(body),
        applescript_string(title)
    );
    let mut child = Command::new(OSASCRIPT)
        .arg("-e")
        .arg(script)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    std::thread::Builder::new()
        .name("notify".to_owned())
        .spawn(move || {
            // Its exit status changes nothing: the notification is best effort.
            let _ = child.wait();
        })?;
    Ok(())
}

/// `text` as an AppleScript string literal: quoted, with `\` and `"` escaped and control
/// characters turned into spaces.
fn applescript_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applescript_strings_escape_quotes_backslashes_and_control_characters() {
        assert_eq!(applescript_string("plain"), "\"plain\"");
        assert_eq!(applescript_string(r#"a "b" \c"#), r#""a \"b\" \\c""#);
        assert_eq!(applescript_string("x\ny\tz"), "\"x y z\"");
        // A quote cannot end the literal early and inject a command.
        assert_eq!(
            applescript_string(r#"" & do shell script "id"#),
            r#""\" & do shell script \"id""#
        );
    }
}
