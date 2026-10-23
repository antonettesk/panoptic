//! User preferences and onboarding state, persisted as JSON in the app data dir.

use crate::asff::AsffTarget;
use crate::config::write_atomic;
use crate::scanner::ScanOptions;
use crate::schedule::ScheduleConfig;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const SETTINGS_VERSION: u32 = 1;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(default)]
pub struct AppSettings {
    pub version: u32,
    pub onboarding_completed: bool,
    /// BCP-47 language tag chosen in the UI (`en`, `es`, `ar`, ...).
    pub language: String,
    /// `system`, `dark` or `light`.
    pub theme: String,
    pub scan_options: ScanOptions,
    pub auto_scan_on_launch: bool,
    /// Offer to capture a baseline after the first clean scan.
    pub baseline_after_first_scan: bool,
    /// AWS Security Hub export target; `None` = integration not enabled.
    pub aws: Option<AsffTarget>,
    pub schedule: ScheduleConfig,
}

impl Default for AppSettings {
    fn default() -> Self {
        AppSettings {
            version: SETTINGS_VERSION,
            onboarding_completed: false,
            language: "en".into(),
            theme: "system".into(),
            scan_options: ScanOptions::default(),
            auto_scan_on_launch: false,
            baseline_after_first_scan: true,
            aws: None,
            schedule: ScheduleConfig::default(),
        }
    }
}

impl AppSettings {
    /// Missing file → defaults; corrupt file → defaults (never block startup),
    /// with the error returned so the caller can tell the user.
    pub fn load(path: &Path) -> (Self, Option<String>) {
        match std::fs::read_to_string(path) {
            Ok(s) => match serde_json::from_str::<AppSettings>(&s) {
                Ok(v) => (v, None),
                Err(e) => (Self::default(), Some(format!("settings file was unreadable and has been reset: {e}"))),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (Self::default(), None),
            Err(e) => (Self::default(), Some(e.to_string())),
        }
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        write_atomic(path, serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?.as_slice())
    }

    pub fn validate(&self) -> Result<(), String> {
        if !["system", "dark", "light"].contains(&self.theme.as_str()) {
            return Err(format!("unknown theme `{}`", self.theme));
        }
        if self.language.is_empty() || self.language.len() > 16 || !self.language.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(format!("invalid language tag `{}`", self.language));
        }
        if let Some(a) = &self.aws {
            a.validate()?;
        }
        self.schedule.validate()?;
        if !(1..=10).contains(&self.scan_options.confirm_rounds) {
            return Err("confirmation passes must be between 1 and 10".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_roundtrip_and_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("settings.json");
        let (s, err) = AppSettings::load(&p);
        assert!(err.is_none() && !s.onboarding_completed);
        let mut s2 = s.clone();
        s2.onboarding_completed = true;
        s2.language = "pt-BR".into();
        s2.validate().unwrap();
        s2.save(&p).unwrap();
        assert_eq!(AppSettings::load(&p).0, s2);
        std::fs::write(&p, "{not json").unwrap();
        let (s3, err) = AppSettings::load(&p);
        assert!(err.is_some());
        assert_eq!(s3, AppSettings::default());
    }

    #[test]
    fn partial_files_fill_defaults() {
        let s: AppSettings = serde_json::from_str(r#"{"language":"ja"}"#).unwrap();
        assert_eq!(s.language, "ja");
        assert_eq!(s.theme, "system");
    }

    #[test]
    fn rejects_bad_values() {
        let s = AppSettings { theme: "neon".into(), ..Default::default() };
        assert!(s.validate().is_err());
        let s = AppSettings { language: "en; rm -rf".into(), ..Default::default() };
        assert!(s.validate().is_err());
    }
}
