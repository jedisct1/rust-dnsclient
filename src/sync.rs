use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use dnssector::constants::{Class, Type};
use dnssector::*;
use rand::{seq::SliceRandom, Rng};

use crate::backend::sync::SyncBackend;
use crate::upstream_server::UpstreamServer;

#[derive(Clone, Debug)]
pub struct DNSClient {
    backend: SyncBackend,
    upstream_servers: Vec<UpstreamServer>,
    local_v4_addr: SocketAddr,
    local_v6_addr: SocketAddr,
    force_tcp: bool,
}

impl DNSClient {
    pub fn new(upstream_servers: Vec<UpstreamServer>) -> Self {
        DNSClient {
            backend: SyncBackend::new(Duration::new(6, 0)),
            upstream_servers,
            local_v4_addr: ([0; 4], 0).into(),
            local_v6_addr: ([0; 16], 0).into(),
            force_tcp: false,
        }
    }

    #[cfg(unix)]
    pub fn new_with_system_resolvers() -> Result<Self, io::Error> {
        Ok(DNSClient::new(crate::system::default_resolvers()?))
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.backend.upstream_server_timeout = timeout
    }

    pub fn set_local_v4_addr<T: Into<SocketAddr>>(&mut self, addr: T) {
        self.local_v4_addr = addr.into()
    }

    pub fn set_local_v6_addr<T: Into<SocketAddr>>(&mut self, addr: T) {
        self.local_v6_addr = addr.into()
    }

    pub fn force_tcp(&mut self, force_tcp: bool) {
        self.force_tcp = force_tcp;
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
        let response = if self.force_tcp {
            self.backend
                .dns_exchange_tcp(local_addr, upstream_server, query)?
        } else {
            self.backend
                .dns_exchange_udp(local_addr, upstream_server, query)?
        };
        let mut parsed_response = DNSSector::new(response)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        if !self.force_tcp && parsed_response.flags() & DNS_FLAG_TC == DNS_FLAG_TC {
            parsed_response = {
                let response = self
                    .backend
                    .dns_exchange_tcp(local_addr, upstream_server, query)?;
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

    fn query_from_parsed_query(
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
        ))
    }

    /// Send a raw query to the DNS server and return the response.
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

    /// Return IPv4 addresses.
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
        ips.shuffle(&mut rand::thread_rng());
        Ok(ips)
    }

    /// Return IPv6 addresses.
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
        ips.shuffle(&mut rand::thread_rng());
        Ok(ips)
    }

    /// Return both IPv4 and IPv6 addresses.
    pub fn query_addrs(&self, name: &str) -> Result<Vec<IpAddr>, io::Error> {
        let ipv4_ips = self.query_a(name)?;
        let ipv6_ips = self.query_aaaa(name)?;
        let mut ips: Vec<_> = ipv4_ips
            .into_iter()
            .map(IpAddr::from)
            .chain(ipv6_ips.into_iter().map(IpAddr::from))
            .collect();
        ips.shuffle(&mut rand::thread_rng());
        Ok(ips)
    }

    /// Return TXT records.
    pub fn query_txt(&self, name: &str) -> Result<Vec<Vec<u8>>, io::Error> {
        let rr_class = Class::from_string("IN").unwrap();
        let rr_type = Type::from_string("TXT").unwrap();
        let parsed_query = dnssector::gen::query(name.as_bytes(), rr_type, rr_class)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let mut parsed_response = self.query_from_parsed_query(parsed_query)?;
        let mut txts: Vec<Vec<u8>> = vec![];

        let mut it = parsed_response.into_iter_answer();
        while let Some(item) = it {
            if item.rr_class() != rr_class.into() || item.rr_type() != rr_type.into() {
                it = item.next();
                continue;
            }
            if let Ok(RawRRData::Data(data)) = item.rr_rd() {
                let mut txt = vec![];
                let mut it = data.iter();
                while let Some(&len) = it.next() {
                    for _ in 0..len {
                        txt.push(*it.next().ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidInput, "Invalid text record")
                        })?)
                    }
                }
                txts.push(txt);
            }
            it = item.next();
        }
        Ok(txts)
    }

    /// Reverse IP lookup.
    pub fn query_ptr(&self, ip: &IpAddr) -> Result<Vec<String>, io::Error> {
        let rr_class = Class::from_string("IN").unwrap();
        let rr_type = Type::from_string("PTR").unwrap();
        let rev_name = match ip {
            IpAddr::V4(ip) => {
                let mut octets = ip.octets();
                octets.reverse();
                format!(
                    "{}.{}.{}.{}.in-addr.arpa",
                    octets[0], octets[1], octets[2], octets[3]
                )
            }
            IpAddr::V6(ip) => {
                let mut octets = ip.octets();
                octets.reverse();
                let rev = octets
                    .iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<_>>()
                    .join(".");
                format!("{}.ip6.arpa", rev)
            }
        };
        let parsed_query = dnssector::gen::query(rev_name.as_bytes(), rr_type, rr_class)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let mut parsed_response = self.query_from_parsed_query(parsed_query)?;
        let mut names: Vec<String> = vec![];

        let mut it = parsed_response.into_iter_answer();
        while let Some(item) = it {
            if item.rr_class() != rr_class.into() || item.rr_type() != rr_type.into() {
                it = item.next();
                continue;
            }
            if let Ok(RawRRData::Data(data)) = item.rr_rd() {
                let mut name = vec![];
                let mut it = data.iter();
                while let Some(&len) = it.next() {
                    if len != 0 && !name.is_empty() {
                        name.push(b'.');
                    }
                    for _ in 0..len {
                        name.push(*it.next().ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidInput, "Invalid text record")
                        })?)
                    }
                }
                if name.is_empty() {
                    name.push(b'.');
                }
                if let Ok(name) = String::from_utf8(name) {
                    match ip {
                        IpAddr::V4(ip) => {
                            if self.query_a(&name)?.contains(ip) {
                                names.push(name)
                            }
                        }
                        IpAddr::V6(ip) => {
                            if self.query_aaaa(&name)?.contains(ip) {
                                names.push(name)
                            }
                        }
                    };
                }
            }
            it = item.next();
        }
        Ok(names)
    }

    /// Return the raw record data for the given query type.
    pub fn query_rrs_data(
        &self,
        name: &str,
        query_class: &str,
        query_type: &str,
    ) -> Result<Vec<Vec<u8>>, io::Error> {
        let rr_class = Class::from_string(query_class)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let rr_type = Type::from_string(query_type)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let parsed_query = dnssector::gen::query(name.as_bytes(), rr_type, rr_class)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let mut parsed_response = self.query_from_parsed_query(parsed_query)?;
        let mut raw_rrs = vec![];

        let mut it = parsed_response.into_iter_answer();
        while let Some(item) = it {
            if item.rr_class() != rr_class.into() || item.rr_type() != rr_type.into() {
                it = item.next();
                continue;
            }
            if let Ok(RawRRData::Data(data)) = item.rr_rd() {
                raw_rrs.push(data.to_vec());
            }
            it = item.next();
        }
        Ok(raw_rrs)
    }
}

#[test]
fn test_query_a() {
    use std::str::FromStr;

    let upstream_servers = crate::system::default_resolvers().unwrap_or_else(|_| {
        vec![
            UpstreamServer::new(SocketAddr::from_str("1.0.0.1:53").unwrap()),
            UpstreamServer::new(SocketAddr::from_str("1.1.1.1:53").unwrap()),
        ]
    });
    let dns_client = DNSClient::new(upstream_servers);
    let r = dns_client.query_a("one.one.one.one").unwrap();
    assert!(r.contains(&Ipv4Addr::new(1, 1, 1, 1)));
}

#[test]
fn test_query_ptr() {
    use std::str::FromStr;

    let upstream_servers = crate::system::default_resolvers().unwrap_or_else(|_| {
        vec![
            UpstreamServer::new(SocketAddr::from_str("1.0.0.1:53").unwrap()),
            UpstreamServer::new(SocketAddr::from_str("1.1.1.1:53").unwrap()),
        ]
    });
    let dns_client = DNSClient::new(upstream_servers);
    let r = dns_client
        .query_ptr(&IpAddr::from_str("1.1.1.1").unwrap())
        .unwrap();
    assert_eq!(r[0], "one.one.one.one");
}
