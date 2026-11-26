//! Redaction of argv before it is written to the action log or shown by `status` and `check`.
//!
//! What it replaces with `***`:
//! - the value of a flag whose name holds `key`, `token`, `secret`, `pass`, `auth`,
//!   `credential` or `cookie`, as `--flag=value` and as `--flag value`, and the value of an
//!   environment-style `NAME=value` argument whose name does;
//! - the value of such a parameter in a URL query (`?token=…`);
//! - `user:pass@` in a URL;
//! - token-shaped strings anywhere: `sk-…`, `ghp_…` (and the other GitHub prefixes), `xox…`
//!   (Slack), JWTs, and long high-entropy runs.
//!
//! It errs on the side of hiding: a redacted harmless value costs a less useful log line, a
//! missed secret leaks it.

use regex::Regex;
use serde::Serialize;

const MASK: &str = "***";

/// Substrings of a flag or variable name that mark its value as secret.
const SECRET_NAMES: [&str; 7] = [
    "key",
    "token",
    "secret",
    "pass",
    "auth",
    "credential",
    "cookie",
];

/// The shortest run of token characters judged by its entropy.
const MIN_ENTROPY_RUN: usize = 24;
/// The shortest hex-only run treated as a secret (a 40-char SHA-1 is one, by design).
const MIN_HEX_RUN: usize = 32;

/// An argv that went through [`Redactor::argv`]; the only way to build one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct RedactedArgv(Vec<String>);

impl RedactedArgv {
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }
}

/// The compiled redaction patterns.
#[derive(Debug)]
pub struct Redactor {
    /// Token-shaped strings with a known prefix, JWTs.
    tokens: Regex,
    /// `scheme://user:pass@`.
    userinfo: Regex,
    /// `?name=value` / `&name=value` in a URL query.
    query: Regex,
    /// Runs of characters a random token is made of.
    runs: Regex,
}

impl Redactor {
    pub fn new() -> Result<Self, regex::Error> {
        Ok(Self {
            tokens: Regex::new(concat!(
                r"\bsk-[A-Za-z0-9_\-]{8,}",
                r"|\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{16,}",
                r"|\bxox[abposr]-[A-Za-z0-9\-]{8,}",
                r"|\beyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}",
            ))?,
            userinfo: Regex::new(r"([A-Za-z][A-Za-z0-9+.\-]*://)[^/@\s]+@")?,
            query: Regex::new(
                r"(?i)([?&;][^=&;#\s]*(?:key|token|secret|pass|auth|credential|cookie|sig)[^=&;#\s]*=)[^&;#\s]+",
            )?,
            runs: Regex::new(r"[A-Za-z0-9_\-+]{24,}={0,2}")?,
        })
    }

    /// Redacts one argv.
    pub fn argv(&self, argv: &[String]) -> RedactedArgv {
        let mut out = Vec::with_capacity(argv.len());
        let mut value_of_secret_flag = false;
        for arg in argv {
            if std::mem::take(&mut value_of_secret_flag) && !arg.starts_with("--") {
                out.push(MASK.to_owned());
                continue;
            }
            if let Some(name) = flag_name(arg) {
                // A flag's dashes hold no `=`, so the arg splits where its name does.
                match (name.split_once('='), arg.split_once('=')) {
                    (Some((name, _)), Some((flag, _))) if is_secret_name(name) => {
                        out.push(format!("{flag}={MASK}"));
                        continue;
                    }
                    (Some(_), _) => {}
                    (None, _) => value_of_secret_flag = is_secret_name(name),
                }
            } else if let Some((name, _)) = arg.split_once('=')
                && is_env_name(name)
                && is_secret_name(name)
            {
                out.push(format!("{name}={MASK}"));
                continue;
            }
            out.push(self.text(arg));
        }
        RedactedArgv(out)
    }

    /// Redacts the token-shaped parts of one string.
    pub fn text(&self, text: &str) -> String {
        let text = self.userinfo.replace_all(text, format!("${{1}}{MASK}@"));
        let text = self.query.replace_all(&text, format!("${{1}}{MASK}"));
        let text = self.tokens.replace_all(&text, MASK);
        self.runs
            .replace_all(&text, |c: &regex::Captures<'_>| {
                let run = c.get(0).map_or("", |m| m.as_str());
                if looks_random(run) {
                    MASK.to_owned()
                } else {
                    run.to_owned()
                }
            })
            .into_owned()
    }
}

/// The name of a flag argument without its dashes (and with any `=value`), or `None` when
/// `arg` is not a flag.
fn flag_name(arg: &str) -> Option<&str> {
    let name = arg.trim_start_matches('-');
    let dashes = arg.len() - name.len();
    (dashes > 0 && name.starts_with(|c: char| c.is_ascii_alphabetic())).then_some(name)
}

fn is_secret_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    SECRET_NAMES.iter().any(|s| name.contains(s))
}

fn is_env_name(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Whether a run of token characters looks like a random secret: long hex, or long, mixing
/// lower case, upper case and digits, with high entropy.
fn looks_random(run: &str) -> bool {
    let body = run.trim_end_matches('=');
    if body.len() >= MIN_HEX_RUN && body.chars().all(|c| c.is_ascii_hexdigit()) {
        return entropy(body) >= 3.0;
    }
    let lower = body.chars().any(|c| c.is_ascii_lowercase());
    let upper = body.chars().any(|c| c.is_ascii_uppercase());
    let digit = body.chars().any(|c| c.is_ascii_digit());
    body.len() >= MIN_ENTROPY_RUN && lower && upper && digit && entropy(body) >= 3.5
}

/// Shannon entropy in bits per character.
fn entropy(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[usize::from(b)] += 1;
    }
    let len = s.len() as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = f64::from(*c) / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redact(argv: &[&str]) -> Vec<String> {
        let argv: Vec<String> = argv.iter().map(|s| (*s).to_owned()).collect();
        Redactor::new().unwrap().argv(&argv).0
    }

    #[test]
    fn secret_flag_values_are_redacted_in_both_forms() {
        assert_eq!(
            redact(&[
                "x",
                "--api-key=abc",
                "--token",
                "t0k",
                "--client-secret=s",
                "--password",
                "pw"
            ]),
            [
                "x",
                "--api-key=***",
                "--token",
                "***",
                "--client-secret=***",
                "--password",
                "***"
            ]
        );
        assert_eq!(redact(&["-password", "pw"]), ["-password", "***"]);
        assert_eq!(
            redact(&["--auth-header", "Bearer x"]),
            ["--auth-header", "***"]
        );
        assert_eq!(redact(&["--KEY=v"]), ["--KEY=***"]);
    }

    #[test]
    fn a_secret_flag_followed_by_another_flag_redacts_nothing_more() {
        assert_eq!(
            redact(&["--token", "--port", "3000"]),
            ["--token", "--port", "3000"]
        );
    }

    #[test]
    fn harmless_flags_are_kept() {
        assert_eq!(
            redact(&["node", "--port=3000", "--watch", "src/index.ts", "-v"]),
            ["node", "--port=3000", "--watch", "src/index.ts", "-v"]
        );
    }

    #[test]
    fn env_style_secrets_are_redacted() {
        assert_eq!(
            redact(&["env", "GITHUB_TOKEN=abc", "NODE_ENV=dev"]),
            ["env", "GITHUB_TOKEN=***", "NODE_ENV=dev"]
        );
    }

    #[test]
    fn prefixed_tokens_are_redacted_anywhere() {
        assert_eq!(redact(&["sk-ant-api03-abcdefgh1234"]), ["***"]);
        assert_eq!(redact(&["sk-test-0123456789"]), ["***"]);
        assert_eq!(
            redact(&["Authorization: ghp_abcdefghijklmnopqrstuvwx"]),
            ["Authorization: ***"]
        );
        assert_eq!(redact(&["github_pat_11ABCDEFG0123456789_x"]), ["***"]);
        assert_eq!(redact(&["xoxb-1234-5678-abcdef"]), ["***"]);
        assert_eq!(redact(&["xoxp-1234567890-abc"]), ["***"]);
    }

    #[test]
    fn a_word_ending_in_sk_is_not_a_token() {
        assert_eq!(redact(&["risk-assessment"]), ["risk-assessment"]);
    }

    #[test]
    fn jwts_are_redacted() {
        assert_eq!(
            redact(&["Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"]),
            ["Bearer ***"]
        );
    }

    #[test]
    fn high_entropy_runs_are_redacted() {
        assert_eq!(redact(&["aB3dE5gH7jK9mN1pQ3sT5vW7yZ"]), ["***"]);
        assert_eq!(
            redact(&["key:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b"]),
            ["key:***"]
        );
        // Paths, words and UUIDs stay readable.
        assert_eq!(
            redact(&["/Users/me/dev/project/node_modules/.bin/vitest"]),
            ["/Users/me/dev/project/node_modules/.bin/vitest"]
        );
        assert_eq!(
            redact(&["webpack-dev-server-integration2"]),
            ["webpack-dev-server-integration2"]
        );
        assert_eq!(
            redact(&["550e8400-e29b-41d4-a716-446655440000"]),
            ["550e8400-e29b-41d4-a716-446655440000"]
        );
    }

    #[test]
    fn url_credentials_and_secret_query_values_are_redacted() {
        assert_eq!(
            redact(&["postgres://admin:hunter2@db.local:5432/app"]),
            ["postgres://***@db.local:5432/app"]
        );
        assert_eq!(
            redact(&["https://api.example.com/v1?access_token=abc&page=2"]),
            ["https://api.example.com/v1?access_token=***&page=2"]
        );
        assert_eq!(
            redact(&["https://example.com/path"]),
            ["https://example.com/path"]
        );
    }
}
