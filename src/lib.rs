#[cfg(feature = "async")]
pub mod r#async;
mod backend;
pub mod sync;
mod upstream_server;

pub use crate::upstream_server::*;

pub mod reexports {
    #[cfg(feature = "async")]
    pub use async_std;
    pub use dnssector;
    pub use rand;
}
