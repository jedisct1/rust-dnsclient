use crate::UpstreamServer;
use std::fs;
use std::io;
use std::net::{IpAddr, SocketAddr};

/// Return the set of default (system) resolvers, by parsing /etc/resolv.conf
#[cfg(unix)]
pub fn default_resolvers() -> Result<Vec<UpstreamServer>, io::Error> {
    let data = fs::read_to_string("/etc/resolv.conf")?;
    let mut upstream_servers = vec![];
    for line in data.lines() {
        let line = line.trim();
        if !line.starts_with("nameserver") {
            continue;
        }
        let mut it = line.split_whitespace();
        if it.next().is_none() {
            continue;
        }
        if let Some(addr) = it.next() {
            let ip = match addr.parse::<IpAddr>() {
                Ok(ip) => ip,
                _ => continue,
            };
            let addr = SocketAddr::new(ip.into(), 53);
            let upstream_server = UpstreamServer::new(addr);
            upstream_servers.push(upstream_server);
        }
    }
    if upstream_servers.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No upstream servers found",
        ));
    }
    Ok(upstream_servers)
}

#[cfg(not(unix))]
pub fn default_resolvers() -> Result<Vec<UpstreamServer>, io::Error> {
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "System resolvers are not supported by the software on this platform",
    ))
}
