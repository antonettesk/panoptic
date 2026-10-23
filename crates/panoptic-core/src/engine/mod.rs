pub mod anomaly;
pub mod heuristics;
pub mod portprobe;
pub mod traits;

#[cfg(target_os = "linux")]
pub mod linux_engine;
#[cfg(target_os = "windows")]
pub mod windows_engine;

pub use traits::{CancelToken, EngineError, EngineResult, ProcessAction, TruthEngine};

/// The engine for the platform Panoptic was compiled for.
pub fn platform_engine() -> Box<dyn TruthEngine> {
    #[cfg(target_os = "linux")]
    {
        Box::new(linux_engine::LinuxEngine::new())
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(windows_engine::WindowsEngine::new())
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        compile_error!("Panoptic supports Linux and Windows only");
    }
}
