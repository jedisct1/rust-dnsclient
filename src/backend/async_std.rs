use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use async_std::net::{TcpStream, UdpSocket};
use async_std::prelude::*;
use dnssector::constants::DNS_MAX_COMPRESSED_SIZE;

use crate::upstream_server::UpstreamServer;

#[derive(Clone, Debug)]
pub struct AsyncBackend {
    pub upstream_server_timeout: Duration,
}

impl AsyncBackend {
    pub fn new(upstream_server_timeout: Duration) -> Self {
        AsyncBackend {
            upstream_server_timeout,
        }
    }

    pub async fn dns_exchange_udp(
        &self,
        local_addr: &SocketAddr,
        upstream_server: &UpstreamServer,
        query: &[u8],
    ) -> io::Result<Vec<u8>> {
        async_std::io::timeout(self.upstream_server_timeout, async {
            let socket = UdpSocket::bind(local_addr).await?;
            socket.connect(upstream_server.addr).await?;
            socket.send(query).await?;
            let mut response = vec![0; DNS_MAX_COMPRESSED_SIZE];
            let response_len = socket
                .recv(&mut response)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "Timeout"))?;
            response.truncate(response_len);
            Ok(response)
        })
        .await
    }

    pub async fn dns_exchange_tcp(
        &self,
        _local_addr: &SocketAddr,
        upstream_server: &UpstreamServer,
        query: &[u8],
    ) -> io::Result<Vec<u8>> {
        async_std::io::timeout(self.upstream_server_timeout, async {
            let mut stream = TcpStream::connect(&upstream_server.addr).await?;
            let _ = stream.set_nodelay(true);
            let query_len = query.len();
            let mut tcp_query = Vec::with_capacity(2 + query_len);
            tcp_query.push((query_len >> 8) as u8);
            tcp_query.push(query_len as u8);
            tcp_query.extend_from_slice(query);
            stream.write_all(&tcp_query).await?;
            let mut response_len_bytes = [0u8; 2];
            stream.read_exact(&mut response_len_bytes).await?;
            let response_len =
                ((response_len_bytes[0] as usize) << 8) | (response_len_bytes[1] as usize);
            if response_len > DNS_MAX_COMPRESSED_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Response too large",
                ));
            }
            let mut response = vec![0; response_len];
            stream.read_exact(&mut response).await?;
            Ok(response)
        })
        .await
    }

    pub async fn join<F1: Future, F2: Future>(&self, f1: F1, f2: F2) -> (F1::Output, F2::Output) {
        f1.join(f2).await
    }
}
