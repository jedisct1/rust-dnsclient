use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

use dnssector::constants::DNS_MAX_COMPRESSED_SIZE;

use crate::upstream_server::UpstreamServer;

#[derive(Clone, Debug)]
pub struct SyncBackend {
    pub upstream_server_timeout: Duration,
}

impl SyncBackend {
    pub fn new(upstream_server_timeout: Duration) -> Self {
        SyncBackend {
            upstream_server_timeout,
        }
    }

    pub fn dns_exchange_udp(
        &self,
        local_addr: &SocketAddr,
        upstream_server: &UpstreamServer,
        query: &[u8],
    ) -> io::Result<Vec<u8>> {
        let socket = UdpSocket::bind(local_addr)?;
        let _ = socket.set_read_timeout(Some(self.upstream_server_timeout));
        socket.connect(upstream_server.addr)?;
        socket.send(query)?;
        let mut response = vec![0; DNS_MAX_COMPRESSED_SIZE];
        let response_len = socket
            .recv(&mut response)
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "Timeout"))?;
        response.truncate(response_len);
        Ok(response)
    }

    pub fn dns_exchange_tcp(
        &self,
        _local_addr: &SocketAddr,
        upstream_server: &UpstreamServer,
        query: &[u8],
    ) -> io::Result<Vec<u8>> {
        let mut stream =
            TcpStream::connect_timeout(&upstream_server.addr, self.upstream_server_timeout)?;
        let _ = stream.set_read_timeout(Some(self.upstream_server_timeout));
        let _ = stream.set_write_timeout(Some(self.upstream_server_timeout));
        let _ = stream.set_nodelay(true);
        let query_len = query.len();
        let mut tcp_query = Vec::with_capacity(2 + query_len);
        tcp_query.push((query_len >> 8) as u8);
        tcp_query.push(query_len as u8);
        tcp_query.extend_from_slice(query);
        stream.write_all(&tcp_query)?;
        let mut response_len_bytes = [0u8; 2];
        stream.read_exact(&mut response_len_bytes)?;
        let response_len =
            ((response_len_bytes[0] as usize) << 8) | (response_len_bytes[1] as usize);
        if response_len > DNS_MAX_COMPRESSED_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Response too large",
            ));
        }
        let mut response = vec![0; response_len];
        stream.read_exact(&mut response)?;
        Ok(response)
    }
}
