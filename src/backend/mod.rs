#[cfg(feature = "async-smol")]
pub(crate) mod async_smol;

#[cfg(all(feature = "async-tokio", not(feature = "async-smol")))]
pub(crate) mod async_tokio;

pub(crate) mod sync;
