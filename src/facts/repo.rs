//! Repo attribution: which registered repo a directory belongs to, read from the `.git` entries
//! on disk (never a `git` subprocess).

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A registered repo, named by its root as registered (canonicalised). Every worktree of the
/// repo maps to the same id, because they share one git common dir.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RepoId(Arc<Path>);

impl RepoId {
    pub fn root(&self) -> &Path {
        &self.0
    }
}

/// The registered repos, keyed by their canonical git common dir.
#[derive(Debug, Default, Clone)]
pub struct Repos {
    by_common_dir: HashMap<PathBuf, RepoId>,
}

impl Repos {
    /// Registers the repo whose root (or any worktree) is `root`. Fails when `root` is not a
    /// git checkout.
    pub fn register(&mut self, root: &Path) -> io::Result<RepoId> {
        let root = fs::canonicalize(root)?;
        let common = git_common_dir(&root)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} has no .git", root.display()),
            )
        })?;
        let id = self
            .by_common_dir
            .entry(common)
            .or_insert_with(|| RepoId(Arc::from(root)));
        Ok(id.clone())
    }

    fn get(&self, common_dir: &Path) -> Option<&RepoId> {
        self.by_common_dir.get(common_dir)
    }
}

/// Resolves directories to registered repos, memoising every directory it visits. Meant to
/// live for one scan: a `.git` created or removed later is seen by the next resolver.
#[derive(Debug, Default)]
pub(crate) struct Resolver {
    memo: HashMap<PathBuf, Option<RepoId>>,
}

impl Resolver {
    /// The registered repo `dir` is in: the nearest ancestor (or `dir` itself) holding a `.git`
    /// whose common dir is registered. An unregistered checkout on the way (a submodule, a
    /// vendored clone) is passed over, so a submodule belongs to its registered superproject.
    pub(crate) fn resolve(&mut self, repos: &Repos, dir: &Path) -> Option<RepoId> {
        let mut visited = Vec::new();
        let mut found = None;
        for candidate in dir.ancestors() {
            if let Some(known) = self.memo.get(candidate) {
                found = known.clone();
                break;
            }
            visited.push(candidate.to_path_buf());
            // An unreadable `.git` is unknown, and unknown is no attribution.
            if let Ok(Some(common)) = git_common_dir(candidate)
                && let Some(id) = repos.get(&common)
            {
                found = Some(id.clone());
                break;
            }
        }
        for dir in visited {
            self.memo.insert(dir, found.clone());
        }
        found
    }
}

/// The canonical git common dir of the checkout rooted at `dir`; `None` when `dir` has no
/// `.git`.
///
/// A `.git` directory is itself the common dir. A `.git` file (a linked worktree or a
/// submodule) holds `gitdir: <path>`; a worktree's gitdir holds `commondir`, a path relative to
/// the gitdir, and a gitdir without one (a submodule) is its own common dir.
fn git_common_dir(dir: &Path) -> io::Result<Option<PathBuf>> {
    let dot_git = dir.join(".git");
    let meta = match fs::metadata(&dot_git) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    if meta.is_dir() {
        return fs::canonicalize(dot_git).map(Some);
    }
    let content = fs::read_to_string(&dot_git)?;
    let gitdir = content
        .lines()
        .find_map(|line| line.strip_prefix("gitdir:"))
        .map(str::trim)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} has no gitdir line", dot_git.display()),
            )
        })?;
    let gitdir = dir.join(gitdir);
    let common = match fs::read_to_string(gitdir.join("commondir")) {
        Ok(common) => gitdir.join(common.trim()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => gitdir,
        Err(err) => return Err(err),
    };
    fs::canonicalize(common).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, content: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    #[test]
    fn a_linked_worktree_resolves_to_its_main_repo() {
        let tmp = tempfile::tempdir().unwrap();
        let main = tmp.path().join("main");
        fs::create_dir_all(main.join(".git/worktrees/wt")).unwrap();
        write(&main.join(".git/worktrees/wt/commondir"), "../..\n");
        let wt = tmp.path().join("wt");
        write(
            &wt.join(".git"),
            &format!("gitdir: {}\n", main.join(".git/worktrees/wt").display()),
        );

        let mut repos = Repos::default();
        let id = repos.register(&main).unwrap();
        assert_eq!(repos.register(&wt).unwrap(), id);

        let mut resolver = Resolver::default();
        let deep = wt.join("packages/a/src");
        fs::create_dir_all(&deep).unwrap();
        assert_eq!(resolver.resolve(&repos, &deep), Some(id.clone()));
        assert_eq!(resolver.resolve(&repos, &main), Some(id));
        assert_eq!(resolver.resolve(&repos, tmp.path()), None);
    }

    #[test]
    fn a_submodule_belongs_to_its_registered_superproject() {
        let tmp = tempfile::tempdir().unwrap();
        let sup = tmp.path().join("product");
        fs::create_dir_all(sup.join(".git/modules/lib")).unwrap();
        // The submodule's gitdir is relative and has no `commondir`.
        write(&sup.join("lib/.git"), "gitdir: ../.git/modules/lib\n");

        let mut repos = Repos::default();
        let id = repos.register(&sup).unwrap();
        let mut resolver = Resolver::default();
        assert_eq!(resolver.resolve(&repos, &sup.join("lib")), Some(id));
    }

    #[test]
    fn an_unregistered_or_missing_checkout_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("other/.git")).unwrap();
        let repos = Repos::default();
        let mut resolver = Resolver::default();
        assert_eq!(resolver.resolve(&repos, &tmp.path().join("other")), None);
        assert_eq!(resolver.resolve(&repos, &tmp.path().join("gone")), None);
        assert!(Repos::default().register(tmp.path()).is_err());
    }
}
