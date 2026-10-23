//! Analyst tuning: suppressed findings and allow-listed paths, persisted as JSON.

use crate::model::Finding;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct Suppressions {
    /// Exact finding ids (stable across scans).
    #[serde(default)]
    pub finding_ids: BTreeSet<String>,
    /// Case-insensitive substrings matched against a finding's path.
    #[serde(default)]
    pub path_patterns: BTreeSet<String>,
}

impl Suppressions {
    pub fn load(path: &Path) -> std::io::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(s) => serde_json::from_str(&s).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        write_atomic(path, serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?.as_slice())
    }

    pub fn matches(&self, f: &Finding) -> bool {
        if self.finding_ids.contains(&f.id) {
            return true;
        }
        if let Some(p) = &f.path {
            let lower = p.to_ascii_lowercase();
            return self.path_patterns.iter().any(|pat| !pat.trim().is_empty() && lower.contains(&pat.to_ascii_lowercase()));
        }
        false
    }

    pub fn apply(&self, findings: &mut [Finding]) {
        for f in findings {
            f.suppressed = self.matches(f);
        }
    }
}

/// Write via a temp file + rename so a crash never leaves a truncated file.
pub fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)?;
        }
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    std::fs::write(&tmp, data)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FindingCategory, Severity};

    #[test]
    fn roundtrip_and_match() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sub/s.json");
        assert_eq!(Suppressions::load(&p).unwrap(), Suppressions::default());
        let mut s = Suppressions::default();
        let f = Finding::new(FindingCategory::Persistence, Severity::High, "x", "t", "d").path("C:\\Tools\\Agent.exe");
        s.path_patterns.insert("\\tools\\".into());
        s.save(&p).unwrap();
        let s2 = Suppressions::load(&p).unwrap();
        assert!(s2.matches(&f));
        let mut s3 = Suppressions::default();
        s3.finding_ids.insert(f.id.clone());
        assert!(s3.matches(&f));
        assert!(!Suppressions::default().matches(&f));
    }
}
