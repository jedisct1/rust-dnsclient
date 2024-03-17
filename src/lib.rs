#![doc = include_str!("../README.md")]

#[cfg(any(feature = "async", feature = "async-tokio"))]
pub mod r#async;
mod backend;
pub mod sync;

pub mod system;
mod upstream_server;

pub use crate::upstream_server::*;

#[cfg(all(feature = "async", feature = "async-tokio"))]
compile_error!(
    "Multiple, incompatible backends have been enabled. Use `default-features = false` in order \
     to disable the default backend, and only pick the one you need."
);

pub mod reexports {
    #[cfg(feature = "async")]
    pub use async_std;
    pub use dnssector;
    pub use rand;
    #[cfg(feature = "async-tokio")]
    pub use tokio;
}
