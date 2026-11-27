# Secrets

The Apple signing and notarization secrets that `scripts/bundle.sh` reads live in Bitwarden Secrets
Manager (the project shared with the other repos), under the prefix `LEUKOCYTE_`. `bun secrets` is the
only way to touch them; no command here ever prints a value. Design: `decisions/secrets-in-a-bun-sidecar.md`.

| Secret                       | What                                                             |
| ---------------------------- | ---------------------------------------------------------------- |
| `APPLE_CERTIFICATE`          | The Developer ID Application certificate, a base64 `.p12`        |
| `APPLE_CERTIFICATE_PASSWORD` | The `.p12`'s export password                                     |
| `APPLE_SIGNING_IDENTITY`     | `Developer ID Application: Name (TEAMID)`                        |
| `APPLE_ID`                   | The Apple Account's email, for notarization                      |
| `APPLE_PASSWORD`             | An app-specific password of `APPLE_ID`                           |
| `APPLE_TEAM_ID`              | The Apple Developer team ID                                      |

## Commands

Run from the repo root after `bun install`.

```bash
bun secrets login                 # sign in to Bitwarden (asks for the access token)
bun secrets set APPLE_ID          # hidden prompt; or `< file`, or --prompt for a desktop dialog
bun secrets list                  # keys in the store, never values
bun secrets refresh               # re-read the store, dropping the 8 h cache
bun secrets push-github           # set every secret in the repo's GitHub Actions secrets
bun secrets push-github --repo owner/name
bun secrets run -- scripts/bundle.sh --notarize   # a command with the secrets in its environment
```

`push-github` needs `gh` logged in with access to the repository's secrets. It reads the store, refuses
to start when any secret is missing (naming them), then runs `gh secret set <NAME>` per secret with the
value on stdin, printing `set <NAME>` only.

CI reads the GitHub secrets only; it never reaches Bitwarden.
