//! # Packet parsing for the Internet Protocol Suite
//!
//! ## Example usage
//! ```
//! use peel_ip::prelude::*;
//!
//! let mut peel = PeelIp::default();
//! let input = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0];
//! let result = peel.traverse(&input, vec![]).unwrap();
//! assert_eq!(result.len(), 1);
//! ```
#![deny(missing_docs)]

#[macro_use]
extern crate log;

#[macro_use]
extern crate nom;
extern crate peel;
extern crate path;

#[macro_use]
pub mod memcmp;

pub mod layer1;
pub mod layer2;
pub mod layer3;
pub mod layer4;

use prelude::*;

/// Provides sensible imports for packet parsers
pub mod prelude {
    pub use std::fmt;
    pub use std::error::Error;
    pub use std::str::{self, FromStr};
    pub use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    pub use nom::*;
    pub use log::LogLevel;
    pub use path::{Path, Connection, Data, Identifier};
    pub use path::error::ErrorType as PathErrorType;
    pub use peel::prelude::*;
    pub use super::NewPeelIp;

    /// A shorthand for the TCP/IP based `Peel`
    pub type PeelIp = Peel<PathIp>;

    /// A shorthand for the `IpProtocol` based `Path`
    pub type PathIp = Path<IpProtocol, ()>;

    /// Link
    pub use layer1::*;
    pub use layer1::ethernet::*;
    pub use layer1::arp::*;

    /// Internet
    pub use layer2::*;
    pub use layer2::ipv4::*;
    pub use layer2::ipv6::*;
    pub use layer2::icmp::*;
    pub use layer2::icmpv6::*;

    // Transport
    pub use layer3::*;
    pub use layer3::tcp::*;
    pub use layer3::tls::*;
    pub use layer3::udp::*;

    // Application
    pub use layer4::http::*;
    pub use layer4::ntp::*;
}

/// Trait for default parser tree generation
pub trait NewPeelIp {
    /// Get the default parser tree
    fn default() -> PeelIp {
        // Create a tree
        let mut p = Peel::new();

        // Create the parsers
        let eth = p.new_parser(EthernetParser);
        let arp = p.new_parser(ArpParser);
        let ipv4 = p.new_parser(Ipv4Parser);
        let ipv6 = p.new_parser(Ipv6Parser);
        let icmp = p.new_parser(IcmpParser);
        let icmpv6 = p.new_parser(Icmpv6Parser);
        let tcp = p.new_parser(TcpParser);
        let udp = p.new_parser(UdpParser);
        let tls = p.new_parser(TlsParser);
        let http = p.new_parser(HttpParser);
        let ntp = p.new_parser(NtpParser);

        // Link the parsers
        p.link_nodes(&[(eth, arp), (eth, ipv4), (eth, ipv6),
                       (ipv4, ipv4), (ipv4, ipv6), (ipv6, ipv6),
                       (ipv4, icmp), (ipv6, icmpv6), (ipv4, tcp),
                       (ipv6, tcp), (ipv4, udp), (ipv6, udp),
                       (tcp, tls), (tcp, http), (tls, http),
                       (udp, ntp)]);

        // Create a path instance
        p.data = Some(Path::new());

        p
    }
}

impl NewPeelIp for PeelIp {}
