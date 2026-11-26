//! Reading the action log as it grows, across the rotation that replaces the file.

use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

/// Yields the complete lines appended to the file at `path` since the last [`poll`](Self::poll),
/// starting from the beginning of whatever file is there first.
pub struct LogReader {
    path: PathBuf,
    open: Option<(BufReader<File>, u64)>,
    /// A line whose end has not been written yet.
    pending: String,
}

impl LogReader {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            open: None,
            pending: String::new(),
        }
    }

    pub fn poll(&mut self) -> io::Result<Vec<String>> {
        let mut lines = Vec::new();
        // Rotation renames the file and creates another: finish the old one through the open
        // handle, then switch to the new one.
        self.read_lines(&mut lines)?;
        let current = match std::fs::metadata(&self.path) {
            Ok(meta) => Some(meta),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        let replaced = match (&self.open, &current) {
            (Some((_, ino)), Some(meta)) => meta.ino() != *ino,
            (Some(_), None) => false,
            (None, _) => true,
        };
        if replaced && let Some(meta) = current {
            self.open = Some((BufReader::new(File::open(&self.path)?), meta.ino()));
            self.pending.clear();
            self.read_lines(&mut lines)?;
        }
        Ok(lines)
    }

    fn read_lines(&mut self, lines: &mut Vec<String>) -> io::Result<()> {
        let Some((reader, _)) = &mut self.open else {
            return Ok(());
        };
        loop {
            if reader.read_line(&mut self.pending)? == 0 {
                return Ok(());
            }
            if self.pending.ends_with('\n') {
                lines.push(self.pending.trim_end().to_owned());
                self.pending.clear();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;

    use super::*;

    #[test]
    fn follows_appends_partial_lines_and_rotation() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("actions.jsonl");
        let mut reader = LogReader::new(path.clone());
        assert!(reader.poll().unwrap().is_empty());

        fs::write(&path, "one\ntw").unwrap();
        assert_eq!(reader.poll().unwrap(), ["one"]);
        let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"o\nthree\n").unwrap();
        assert_eq!(reader.poll().unwrap(), ["two", "three"]);
        assert!(reader.poll().unwrap().is_empty());

        // Rotation: a last line lands in the old file, which is renamed; a new file starts.
        file.write_all(b"four\n").unwrap();
        fs::rename(&path, tmp.path().join("actions.jsonl.1")).unwrap();
        fs::write(&path, "five\n").unwrap();
        assert_eq!(reader.poll().unwrap(), ["four", "five"]);
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"six\n")
            .unwrap();
        assert_eq!(reader.poll().unwrap(), ["six"]);
    }
}
