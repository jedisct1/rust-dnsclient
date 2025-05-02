#![doc = include_str!("../README.md")]

#[cfg(any(feature = "async-smol", feature = "async-tokio"))]
pub mod r#async;
mod backend;
pub mod sync;

pub mod system;
mod upstream_server;

pub use crate::upstream_server::*;

// If async-smol is specified as a feature, it will be used even if tokio is available via default features
// We avoid compiling modules that won't be used

pub mod reexports {
    pub use dnssector;
    #[cfg(feature = "async-smol")]
    pub use futures_lite;
    pub use rand;
    #[cfg(feature = "async-smol")]
    pub use smol;
    #[cfg(all(feature = "async-tokio", not(feature = "async-smol")))]
    pub use tokio;
}
