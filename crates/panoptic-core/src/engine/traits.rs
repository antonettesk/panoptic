pub use crate::model::{Finding, KernelModule, PersistenceEntry, ProcessInfo, Protocol, SocketInfo, Visibility};
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("System API Error: {0}")]
    ApiError(String),
    #[error("Permission Denied: Run as root/Administrator")]
    PermissionDenied,
    #[error("Unsupported on this platform: {0}")]
    Unsupported(String),
    #[error("Refused: {0}")]
    Refused(String),
    #[error("Process {0} not found (it may have already exited)")]
    NotFound(u32),
    #[error("Scan cancelled")]
    Cancelled,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type EngineResult<T> = Result<T, EngineError>;

/// Cooperative cancellation shared between the scanner and long-running probes.
#[derive(Debug, Default)]
pub struct CancelToken(AtomicBool);

impl CancelToken {
    pub fn new() -> Self {
        Self(AtomicBool::new(false))
    }
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    pub fn reset(&self) {
        self.0.store(false, Ordering::SeqCst);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
    pub fn check(&self) -> EngineResult<()> {
        if self.is_cancelled() {
            Err(EngineError::Cancelled)
        } else {
            Ok(())
        }
    }
}

/// What to do with a live process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProcessAction {
    Terminate,
    Suspend,
    Resume,
}

/// A platform implementation of Cross-Layer Truth Analysis.
///
/// Each method returns what one layer of the OS reports; the comparison and
/// verdicts live in [`crate::engine::anomaly`] so they are testable without
/// a live system.
pub trait TruthEngine: Send + Sync {
    fn name(&self) -> &'static str;

    /// Whether the current process runs with root / Administrator rights.
    fn is_elevated(&self) -> bool;

    /// High-level API view of running processes, enriched with metadata.
    fn scan_user_space(&self) -> EngineResult<Vec<ProcessInfo>>;

    /// Low-level "reality": every PID the kernel will acknowledge, gathered
    /// without trusting the normal enumeration APIs.
    fn scan_kernel_reality(&self, cancel: &CancelToken) -> EngineResult<Vec<ProcessInfo>>;

    /// Cheap re-enumeration of the high-level API view (PIDs only), used to
    /// rule out processes that merely started between two snapshots.
    fn api_pids(&self) -> EngineResult<Vec<u32>>;

    /// PIDs from the secondary enumeration path (raw syscall / alternate API).
    fn scan_syscall_view(&self) -> EngineResult<Vec<u32>>;

    /// Re-verify that a PID is alive using the lowest-level probe available.
    fn pid_alive(&self, pid: u32) -> bool;

    /// Socket table as reported by the OS.
    fn scan_network_sockets(&self) -> EngineResult<Vec<SocketInfo>>;

    /// Autostart / persistence locations.
    fn scan_persistence(&self) -> EngineResult<Vec<PersistenceEntry>>;

    /// Loaded kernel modules / drivers, cross-checked where possible.
    fn scan_kernel_modules(&self) -> EngineResult<Vec<KernelModule>>;

    /// Platform specific process heuristics (masquerading, fileless, ...).
    fn inspect_processes(&self, processes: &[ProcessInfo]) -> Vec<Finding>;

    /// System-wide integrity checks (loader hijacks, kernel taint, ...).
    fn integrity_checks(&self) -> Vec<Finding>;

    /// Act on a process. `expected_start_time` (epoch secs) guards against PID
    /// reuse: if non-zero and the live process started at a different time the
    /// action is refused.
    fn act_on_process(&self, pid: u32, expected_start_time: u64, action: ProcessAction) -> EngineResult<()>;
}
