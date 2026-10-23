//! The detection engine lives in the `panoptic-core` crate so the desktop
//! shell and the headless CLI share one implementation. This module keeps the
//! blueprint's `crate::engine::traits::*` paths working inside the Tauri app.

pub mod traits {
    pub use panoptic_core::engine::traits::*;
}
