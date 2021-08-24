#[cfg(feature = "async")]
use crate::backend::async_std::AsyncBackend;

#[cfg(feature = "async-tokio")]
use crate::backend::async_tokio::AsyncBackend;

use crate::upstream_server::UpstreamServer;
use dnssector::constants::{Class, Type};
use dnssector::*;
use rand::Rng;
use std::io;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct DNSClient {
    backend: AsyncBackend,
    upstream_servers: Vec<UpstreamServer>,
    local_v4_addr: SocketAddr,
    local_v6_addr: SocketAddr,
}

impl DNSClient {
    pub fn new(upstream_servers: Vec<UpstreamServer>) -> Self {
        DNSClient {
            backend: AsyncBackend::new(Duration::new(6, 0)),
            upstream_servers,
            local_v4_addr: ([0; 4], 0).into(),
            local_v6_addr: ([0; 16], 0).into(),
        }
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
        let response = self
            .backend
            .dns_exchange_udp(local_addr, upstream_server, query)
            .await?;
        let mut parsed_response = DNSSector::new(response)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        if parsed_response.flags() & DNS_FLAG_TC == DNS_FLAG_TC {
            parsed_response = {
                let response = self
                    .backend
                    .dns_exchange_tcp(local_addr, upstream_server, query)
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

    /// Send a raw query to the DNS server and return the response.
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

    /// Return IPv4 addresses.
    pub async fn query_a(&self, name: &str) -> Result<Vec<Ipv4Addr>, io::Error> {
        let parsed_query = dnssector::gen::query(
            name.as_bytes(),
            Type::from_string("A").unwrap(),
            Class::from_string("IN").unwrap(),
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let mut parsed_response = self.query_from_parsed_query(parsed_query).await?;
        let mut ips = vec![];

        let mut it = parsed_response.into_iter_answer();
        while let Some(item) = it {
            if let Ok(IpAddr::V4(addr)) = item.rr_ip() {
                ips.push(addr);
            }
            it = item.next();
        }
        Ok(ips)
    }

    /// Return IPv6 addresses.
    pub async fn query_aaaa(&self, name: &str) -> Result<Vec<Ipv6Addr>, io::Error> {
        let parsed_query = dnssector::gen::query(
            name.as_bytes(),
            Type::from_string("AAAA").unwrap(),
            Class::from_string("IN").unwrap(),
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let mut parsed_response = self.query_from_parsed_query(parsed_query).await?;
        let mut ips = vec![];

        let mut it = parsed_response.into_iter_answer();
        while let Some(item) = it {
            if let Ok(IpAddr::V6(addr)) = item.rr_ip() {
                ips.push(addr);
            }
            it = item.next();
        }
        Ok(ips)
    }

    /// Return both IPv4 and IPv6 addresses, performing both queries simultaneously.
    pub async fn query_addrs(&self, name: &str) -> Result<Vec<IpAddr>, io::Error> {
        let futs = self
            .backend
            .join(self.query_a(name), self.query_aaaa(name))
            .await;
        let ipv4_ips = futs.0?;
        let ipv6_ips = futs.1?;
        let ips: Vec<_> = ipv4_ips
            .into_iter()
            .map(IpAddr::from)
            .chain(ipv6_ips.into_iter().map(IpAddr::from))
            .collect();
        Ok(ips)
    }

    /// Return TXT records.
    pub async fn query_txt(&self, name: &str) -> Result<Vec<Vec<u8>>, io::Error> {
        let parsed_query = dnssector::gen::query(
            name.as_bytes(),
            Type::from_string("TXT").unwrap(),
            Class::from_string("IN").unwrap(),
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let mut parsed_response = self.query_from_parsed_query(parsed_query).await?;
        let mut txts: Vec<Vec<u8>> = vec![];

        let mut it = parsed_response.into_iter_answer();
        while let Some(item) = it {
            if let Ok(raw) = item.rr_rd() {
                if let RawRRData::Data(data) = raw {
                    let mut txt = vec![];
                    let mut it = data.iter();
                    while let Some(len) = it.next() {
                        for _ in 0..*len {
                            txt.push(*it.next().ok_or_else(|| {
                                io::Error::new(io::ErrorKind::InvalidInput, "Invalid text record")
                            })?)
                        }
                    }
                    txts.push(txt);
                }
            }
            it = item.next();
        }
        Ok(txts)
    }

    /// Return the raw record data for the given query type.
    pub async fn query_rrs_data(
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
        let mut parsed_response = self.query_from_parsed_query(parsed_query).await?;
        let mut raw_rrs = vec![];

        let mut it = parsed_response.into_iter_answer();
        while let Some(item) = it {
            if let Ok(raw) = item.rr_rd() {
                if let RawRRData::Data(data) = raw {
                    raw_rrs.push(data.to_vec());
                }
            }
            it = item.next();
        }
        Ok(raw_rrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;

    #[cfg(feature = "async")]
    fn block_on<F: Future>(future: F) -> F::Output {
        use async_std::task;
        task::block_on(future)
    }

    #[cfg(feature = "async-tokio")]
    fn block_on<F: Future>(future: F) -> F::Output {
        use tokio::runtime;
        let rt = runtime::Builder::new_current_thread()
            .enable_time()
            .enable_io()
            .build()
            .unwrap();
        rt.block_on(future)
    }

    #[test]
    fn test_query_a() {
        use std::str::FromStr;

        let dns_client = DNSClient::new(vec![
            UpstreamServer::new(SocketAddr::from_str("1.0.0.1:53").unwrap()),
            UpstreamServer::new(SocketAddr::from_str("1.1.1.1:53").unwrap()),
        ]);
        block_on(async {
            let r = dns_client.query_a("one.one.one.one").await.unwrap();
            assert!(r.contains(&Ipv4Addr::new(1, 1, 1, 1)));
        })
    }

    #[test]
    fn test_query_addrs() {
        use std::str::FromStr;

        let dns_client = DNSClient::new(vec![
            UpstreamServer::new(SocketAddr::from_str("1.0.0.1:53").unwrap()),
            UpstreamServer::new(SocketAddr::from_str("1.1.1.1:53").unwrap()),
        ]);
        block_on(async {
            let r = dns_client.query_addrs("one.one.one.one").await.unwrap();
            assert!(r.contains(&IpAddr::from(Ipv4Addr::new(1, 1, 1, 1))));
        })
    }

    #[test]
    fn test_query_txt() {
        use std::str::FromStr;

        let dns_client = DNSClient::new(vec![
            UpstreamServer::new(SocketAddr::from_str("1.0.0.1:53").unwrap()),
            UpstreamServer::new(SocketAddr::from_str("1.1.1.1:53").unwrap()),
        ]);
        block_on(async {
            let r = dns_client.query_txt("fastly.com").await.unwrap();
            assert!(r.iter().any(|txt| {
                let txt = std::str::from_utf8(txt).unwrap();
                txt.starts_with("google-site")
            }))
        })
    }
}
