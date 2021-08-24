#[cfg(any(feature = "async", feature = "async-tokio"))]
pub mod r#async;
mod backend;
pub mod sync;

pub mod system;
mod upstream_server;

pub use crate::upstream_server::*;

pub mod reexports {
    #[cfg(feature = "async")]
    pub use async_std;

    #[cfg(feature = "async-tokio")]
    pub use tokio;

    pub use dnssector;
    pub use rand;
}
