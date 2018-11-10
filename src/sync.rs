use super::dnssector::constants::{Class, Type, DNS_MAX_COMPRESSED_SIZE};
use super::dnssector::*;
use super::upstream_server::UpstreamServer;
use rand::Rng;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
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

    fn send_query_to_upstream_server(
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
        let mut parsed_response = {
            // UDP
            let socket = UdpSocket::bind(local_addr)?;
            let _ = socket.set_read_timeout(Some(Duration::new(5, 0)));
            socket.connect(upstream_server.addr)?;
            socket.send(&query)?;
            let mut response = vec![0; DNS_MAX_COMPRESSED_SIZE];
            let response_len = socket
                .recv(&mut response)
                .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "Timeout"))?;
            response.truncate(response_len);
            DNSSector::new(response)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?
                .parse()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?
        };
        if parsed_response.flags() & DNS_FLAG_TC == DNS_FLAG_TC {
            parsed_response = {
                // TCP
                let mut stream = TcpStream::connect_timeout(
                    &upstream_server.addr,
                    self.upstream_server_timeout,
                )?;
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
                let mut response = vec![0; response_len];
                stream.read_exact(&mut response)?;
                DNSSector::new(response)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?
                    .parse()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?
            }
        }
        if parsed_response.tid() != query_tid || &parsed_response.question() != query_question {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Unexpected response",
            ))?
        }
        Ok(parsed_response)
    }

    fn query_from_parsed_query(
        &self,
        mut parsed_query: ParsedPacket,
    ) -> Result<ParsedPacket, io::Error> {
        let query_tid = parsed_query.tid();
        let query_question = parsed_query.question();
        if query_question.is_none() || parsed_query.flags() & DNS_FLAG_QR != 0 {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "No DNS question",
            ))?
        }
        let valid_query = parsed_query.into_packet();
        for upstream_server in &self.upstream_servers {
            if let Ok(parsed_response) = self.send_query_to_upstream_server(
                upstream_server,
                query_tid,
                &query_question,
                &valid_query,
            ) {
                return Ok(parsed_response);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "No response received from any servers",
        ))?
    }

    pub fn query_raw(&self, query: &[u8], tid_masking: bool) -> Result<Vec<u8>, io::Error> {
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
        let mut parsed_response = self.query_from_parsed_query(parsed_query)?;
        if tid_masking {
            parsed_response.set_tid(tid);
        }
        let response = parsed_response.into_packet();
        Ok(response)
    }

    pub fn query_a(&self, name: &str) -> Result<Vec<Ipv4Addr>, io::Error> {
        let parsed_query = dnssector::gen::query(
            name.as_bytes(),
            Type::from_string("A").unwrap(),
            Class::from_string("IN").unwrap(),
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let mut parsed_response = self.query_from_parsed_query(parsed_query)?;
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

    pub fn query_aaaa(&self, name: &str) -> Result<Vec<Ipv6Addr>, io::Error> {
        let parsed_query = dnssector::gen::query(
            name.as_bytes(),
            Type::from_string("AAAA").unwrap(),
            Class::from_string("IN").unwrap(),
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let mut parsed_response = self.query_from_parsed_query(parsed_query)?;
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
    use std::str::FromStr;

    let dns_client = DNSClient::new(vec![
        UpstreamServer::new(SocketAddr::from_str("1.1.1.10:53").unwrap()),
        UpstreamServer::new(SocketAddr::from_str("1.1.1.1:53").unwrap()),
    ]);
    let r = dns_client.query_a("one.one.one.one").unwrap();
    assert!(r.contains(&Ipv4Addr::new(1, 1, 1, 1)));
}
