use super::dnssector::constants::{Class, Type, DNS_MAX_COMPRESSED_SIZE};
use super::dnssector::*;
use super::upstream_server::UpstreamServer;
use async_std::net::{TcpStream, UdpSocket};
use async_std::prelude::*;
use rand::Rng;
use std::io;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct DNSClient {
    upstream_server_timeout: Duration,
    upstream_servers: Vec<UpstreamServer>,
    local_v4_addr: SocketAddr,
    local_v6_addr: SocketAddr,
}

impl DNSClient {
    pub fn new(upstream_servers: Vec<UpstreamServer>) -> Self {
        DNSClient {
            upstream_server_timeout: Duration::new(5, 0),
            upstream_servers,
            local_v4_addr: ([0; 4], 0).into(),
            local_v6_addr: ([0; 16], 0).into(),
        }
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.upstream_server_timeout = timeout
    }

    pub fn set_local_v4_addr<T: Into<SocketAddr>>(&mut self, addr: T) {
        self.local_v4_addr = addr.into()
    }

    pub fn set_local_v6_addr<T: Into<SocketAddr>>(&mut self, addr: T) {
        self.local_v6_addr = addr.into()
    }

    async fn send_query_to_upstream_server(
        &self,
        upstream_server: &UpstreamServer,
        query_tid: u16,
        query_question: &Option<(Vec<u8>, u16, u16)>,
        query: &[u8],
    ) -> Result<ParsedPacket, io::Error> {
        let local_addr = match upstream_server.addr {
            SocketAddr::V4(_) => &self.local_v4_addr,
            SocketAddr::V6(_) => &self.local_v6_addr,
        };
        // UDP
        let response = async_std::io::timeout(self.upstream_server_timeout, async {
            let socket = UdpSocket::bind(local_addr).await?;

            socket.connect(upstream_server.addr).await?;
            socket.send(&query).await?;
            let mut response = vec![0; DNS_MAX_COMPRESSED_SIZE];
            let response_len = socket
                .recv(&mut response)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "Timeout"))?;
            response.truncate(response_len);
            Ok(response)
        })
        .await?;
        let mut parsed_response = DNSSector::new(response)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        if parsed_response.flags() & DNS_FLAG_TC == DNS_FLAG_TC {
            parsed_response = {
                // TCP
                let response = async_std::io::timeout(self.upstream_server_timeout, async {
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
                    let mut response = vec![0; response_len];
                    stream.read_exact(&mut response).await?;
                    Ok(response)
                })
                .await?;
                DNSSector::new(response)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?
                    .parse()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?
            };
        }
        if parsed_response.tid() != query_tid || &parsed_response.question() != query_question {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Unexpected response",
            ));
        }
        Ok(parsed_response)
    }

    async fn query_from_parsed_query(
        &self,
        mut parsed_query: ParsedPacket,
    ) -> Result<ParsedPacket, io::Error> {
        let query_tid = parsed_query.tid();
        let query_question = parsed_query.question();
        if query_question.is_none() || parsed_query.flags() & DNS_FLAG_QR != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "No DNS question",
            ));
        }
        let valid_query = parsed_query.into_packet();
        for upstream_server in &self.upstream_servers {
            if let Ok(parsed_response) = self
                .send_query_to_upstream_server(
                    upstream_server,
                    query_tid,
                    &query_question,
                    &valid_query,
                )
                .await
            {
                return Ok(parsed_response);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "No response received from any servers",
        ))
    }

    pub async fn query_raw(&self, query: &[u8], tid_masking: bool) -> Result<Vec<u8>, io::Error> {
        let mut parsed_query = DNSSector::new(query.to_vec())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let mut tid = 0;
        if tid_masking {
            tid = parsed_query.tid();
            let mut rnd = rand::thread_rng();
            let masked_tid: u16 = rnd.gen();
            parsed_query.set_tid(masked_tid);
        }
        let mut parsed_response = self.query_from_parsed_query(parsed_query).await?;
        if tid_masking {
            parsed_response.set_tid(tid);
        }
        let response = parsed_response.into_packet();
        Ok(response)
    }

    pub async fn query_a(&self, name: &str) -> Result<Vec<Ipv4Addr>, io::Error> {
        let parsed_query = dnssector::gen::query(
            name.as_bytes(),
            Type::from_string("A").unwrap(),
            Class::from_string("IN").unwrap(),
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let mut parsed_response = self.query_from_parsed_query(parsed_query).await?;
        let mut ips = vec![];
        {
            let mut it = parsed_response.into_iter_answer();
            while let Some(item) = it {
                if let Ok(IpAddr::V4(addr)) = item.rr_ip() {
                    ips.push(addr);
                }
                it = item.next();
            }
        }
        Ok(ips)
    }

    pub async fn query_txt(&self, name: &str) -> Result<Vec<String>, io::Error> {
        let parsed_query = dnssector::gen::query(
            name.as_bytes(),
            Type::TXT,
            Class::IN,
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let mut parsed_response = self.query_from_parsed_query(parsed_query).await?;
        let mut txts = vec![];
        {
            let mut it = parsed_response.into_iter_answer();
            while let Some(item) = it {
                if let Ok(s) = item.rr_txt() {
                    txts.push(s);
                }
                it = item.next();
            }
        }
        Ok(txts)
    }

    pub async fn query_aaaa(&self, name: &str) -> Result<Vec<Ipv6Addr>, io::Error> {
        let parsed_query = dnssector::gen::query(
            name.as_bytes(),
            Type::from_string("AAAA").unwrap(),
            Class::from_string("IN").unwrap(),
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let mut parsed_response = self.query_from_parsed_query(parsed_query).await?;
        let mut ips = vec![];
        {
            let mut it = parsed_response.into_iter_answer();
            while let Some(item) = it {
                if let Ok(IpAddr::V6(addr)) = item.rr_ip() {
                    ips.push(addr);
                }
                it = item.next();
            }
        }
        Ok(ips)
    }
}

#[test]
fn test_query_a() {
    use async_std::task;
    use std::str::FromStr;

    let dns_client = DNSClient::new(vec![
        UpstreamServer::new(SocketAddr::from_str("1.0.0.1:53").unwrap()),
        UpstreamServer::new(SocketAddr::from_str("1.1.1.1:53").unwrap()),
    ]);
    task::block_on(async {
        let r = dns_client.query_a("one.one.one.one").await.unwrap();
        assert!(r.contains(&Ipv4Addr::new(1, 1, 1, 1)));
    })
}
