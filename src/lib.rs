use dnssector;

pub mod r#async;
pub mod sync;
mod upstream_server;

pub use crate::upstream_server::*;
