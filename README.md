A simple and secure DNS client for Rust
=======================================

[API documentation](https://docs.rs/dnsclient)

This is a DNS client crate. Some people may call that a stub resolver.

It can resolve IPv4 and IPv6 addresses. But unlike `std::net::ToSocketAddrs`, it directly contacts upstream servers, and doesn't depend on the system resolver. Which, in the worst case, could be systemd.

Instead, your application fully controls what upstream resolvers will be used.

It can also send raw queries, and return raw responses, retrying over multiple server candidates if necessary.

DNSClient carefully checks the consistency of every single packet it receives.

It will not let clients initiate zone transfers. It may prevent funky DNS implementations from crashing or being exploited when a malicious query or response is received.

It also transparently falls back to TCP when a truncated response is received.

Finally, its API couldn't be any simpler.

DNSClient comes with a synchronous interface (`sync::*`) as well as a `std::future`-based asynchronous interface (`async::*`).
