use std::net::SocketAddr;

#[derive(Clone, Debug)]
pub struct UpstreamServer {
    pub addr: SocketAddr,
}

impl UpstreamServer {
    pub fn new<T: Into<SocketAddr>>(addr: T) -> Self {
        UpstreamServer { addr: addr.into() }
    }
}
