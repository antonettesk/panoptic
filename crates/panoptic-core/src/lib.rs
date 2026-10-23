//! # panoptic-core
//!
//! Cross-Layer Truth Analysis for Linux and Windows: every artefact a rootkit
//! might hide (processes, sockets, kernel modules) is observed through several
//! independent OS layers, and any disagreement between them is reported.
//!
//! ```no_run
//! use panoptic_core::{Scanner, ScanOptions, Suppressions, CancelToken};
//! let report = Scanner::new().run(&ScanOptions::default(), &Suppressions::default(), None, &CancelToken::new(), &|p| eprintln!("{}% {}", p.percent, p.message));
//! println!("risk {}/100, {} findings", report.risk_score, report.findings.len());
//! ```

pub mod asff;
pub mod baseline;
pub mod config;
pub mod engine;
pub mod model;
pub mod report;
pub mod scanner;
pub mod schedule;
pub mod settings;
pub mod workspace;

pub use baseline::Baseline;
pub use config::Suppressions;
pub use engine::{platform_engine, CancelToken, EngineError, ProcessAction, TruthEngine};
pub use model::*;
pub use scanner::{Progress, ScanOptions, Scanner};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
