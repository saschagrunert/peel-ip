//! # Packet parsing for the Internet Protocol Suite
//!
//! ## Example usage
//! ```
//! use peel_ip::PeelIp;
//!
//! let mut peel = PeelIp::new();
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
    pub use std::str::{self, FromStr};
    pub use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    pub use nom::*;
    pub use path::{Path, Data, Identifier};
    pub use peel::prelude::*;
    pub use super::{Layer, ParserVariant, PeelIp};

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

    // Transport
    pub use layer3::*;
    pub use layer3::tcp::*;
    pub use layer3::tls::*;
    pub use layer3::udp::*;

    // Application
    pub use layer4::http::*;
    pub use layer4::ntp::*;
}

#[derive(Debug)]
/// The return value for the variant retrieval of the Parser trait
pub enum ParserVariant {
    /// Ethernet parser
    Ethernet(EthernetParser),

    /// Address Resolution Protocol parser
    Arp(ArpParser),

    /// Internet Protocol version 4 parser
    Ipv4(Ipv4Parser),

    /// Internet Protocol version 6 parser
    Ipv6(Ipv6Parser),

    /// Transmission Control Protocol parser
    Tcp(TcpParser),

    /// Transport Layer Security parser
    Tls(TlsParser),

    /// Hypertext Transfer Protocol parser
    Http(HttpParser),

    /// User Datagram Protocol parser
    Udp(UdpParser),

    /// Network Time Protocol parser
    Ntp(NtpParser),
}

#[derive(Debug, Eq, PartialEq)]
/// Return values for the actual parsers
pub enum Layer {
    /// Ethernet protocol packet variant
    Ethernet(EthernetPacket),

    /// Address Resolution Protocol packet variant
    Arp(ArpPacket),

    /// Internet Protocol version 4 packet variant
    Ipv4(Ipv4Packet),

    /// Internet Protocol version 6 packet variant
    Ipv6(Ipv6Packet),

    /// Transmission Control Protocol packet variant
    Tcp(TcpPacket),

    /// Transport Layer Security packet variant
    Tls(TlsPacket),

    /// Hypertext Transfer Protocol packet variant
    Http(HttpPacket),

    /// User Datagram Protocol packet variant
    Udp(UdpPacket),

    /// Network Time Protocol packet variant
    Ntp(NtpPacket),
}

macro_rules! impl_fmt_display {
    ($name: ident) => {
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                match *self {
                    $name::Ethernet(_) => write!(f, "Ethernet"),
                    $name::Arp(_) => write!(f, "ARP"),
                    $name::Ipv4(_) => write!(f, "IPv4"),
                    $name::Ipv6(_) => write!(f, "IPv6"),
                    $name::Tcp(_) => write!(f, "TCP"),
                    $name::Tls(_) => write!(f, "TLS"),
                    $name::Http(_) => write!(f, "HTTP"),
                    $name::Udp(_) => write!(f, "UDP"),
                    $name::Ntp(_) => write!(f, "NTP"),
                }
            }
        }
    }
}

impl_fmt_display!(Layer);
impl_fmt_display!(ParserVariant);

/// Peel for TCP/IP packets
pub struct PeelIp;

impl PeelIp {
    /// Creates a new `Peel` structure for TCP/IP based packet parsing
    pub fn new() -> Peel<Layer, ParserVariant, PathIp> {
        // Create a tree
        let mut p = Peel::new();

        // Ethernet
        let eth = p.new_parser(EthernetParser);

        // ARP
        p.link_new_parser(eth, ArpParser);

        // IPv4/6
        let ipv4 = p.link_new_parser(eth, Ipv4Parser);
        let ipv6 = p.link_new_parser(eth, Ipv6Parser);
        p.link(ipv4, ipv6);
        p.link(ipv4, ipv4);
        p.link(ipv6, ipv6);

        // TCP
        let tcp = p.new_parser(TcpParser);
        p.link(ipv4, tcp);
        p.link(ipv6, tcp);

        // UDP
        let udp = p.new_parser(UdpParser);
        p.link(ipv4, udp);
        p.link(ipv6, udp);

        // TLS
        let tls = p.new_parser(TlsParser);
        p.link(tcp, tls);

        // HTTP
        let http = p.new_parser(HttpParser);
        p.link(tcp, http);
        p.link(tls, http);

        // NTP
        let ntp = p.new_parser(NtpParser);
        p.link(udp, ntp);

        // Create a path instance
        p.data = Some(Path::new());

        p
    }
}
