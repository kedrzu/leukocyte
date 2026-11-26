---
name: git-workflow
description: How a change moves in leukocyte — branch naming, Conventional Commit messages, pushing, opening and readying PRs into the protected main, landing and releasing. The dev pipeline relies on it; use it before any commit, push, PR, merge or release.
---

# Git workflow

Fulfils the `dev` pipeline's `git-workflow` contract. `main` takes pull requests only
(`.claude/git.json` protects it); every PR is squash-merged, and its title becomes the commit on `main`.
There is no issue tracker: work is tied to a branch and its PR.

## Start

Branch from an up-to-date `main`: `git fetch origin && git switch -c <type>/<kebab-slug> origin/main`.
`<type>` is a Conventional Commit type (`feat`, `fix`, `chore`, `docs`, `refactor`, `test`, `ci`), the
slug a few words naming the change (`feat/initial-daemon`). No draft PR at this point; it opens in
Publish.

## Checkpoint

Commit with a Conventional Commit subject (`feat(rules): load Luau rule files`), imperative, at most 72
characters, then the attribution lines from the session's system reminder. Run `scripts/verify-scoped.sh`
first and never commit red.

- **Everything:** `git add -A && git commit -m "…"`.
- **A given set of files only:** `git add -- <paths>`, check `git diff --cached --name-only` lists
  nothing else, then commit.
- **Push what is committed:** `git push -u origin HEAD`. It landed when `git rev-parse HEAD` equals
  `git rev-parse @{u}`.

Merge `origin/main` into the branch (`git fetch origin main && git merge --no-edit origin/main`), never
rebase or force-push. There are no submodules or other repositories to publish first.

## Publish

Once `scripts/verify.sh` is green: push, then, if the branch has no PR,
`gh pr create --base main --title "<Conventional Commit title>" --body-file <file>`, ready (not draft).
The title is what lands on `main`, so it follows Conventional Commits (CI's `pr-title` check enforces
it); the body says in English what changed and why. An open PR gets the push, and a new body when the
scope grew.

## Stack

Not supported: a change is one PR. Split work that is too big into separate PRs that each land on `main`.

## Land

Only on the owner's request. Merge `origin/main` in, run `scripts/verify.sh`, push, wait for CI, then
`gh pr merge <n> --squash`. Afterwards `git fetch origin && git switch main && git pull --ff-only`.

## Release

See Release: filled in with the release pipeline (a version-bump commit, then a manual dispatch of the
release workflow).
