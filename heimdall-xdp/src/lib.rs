//! HEIMDALL XDP Loader Library
//! Provides XDP program loading, map management, and event handling

pub mod loader;
pub mod maps;
pub mod events;
pub mod stats;
pub mod types;

pub use loader::XdpLoader;
pub use events::EventReader;
pub use stats::StatsReader;
pub use types::*;

// Re-export map functions
pub use maps::{block_ipv4, block_ipv6, unblock_ipv4, is_ipv4_blocked};
