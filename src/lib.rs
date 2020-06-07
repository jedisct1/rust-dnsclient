#![feature(proc_macro_hygiene)]

#[rustversion::since(1.38)]
pub mod r#async;
pub mod sync;
mod upstream_server;

pub use crate::upstream_server::*;
