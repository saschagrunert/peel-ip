//! # Packet parsing for the Internet Protocol Suite
//!
//! ## Example usage
//! ```
//! use peel_ip::PeelIp;
//!
//! let mut peel = PeelIp::new();
//! let mut input = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00];
//! let result = peel.traverse(&input, vec![]).unwrap();
//! assert_eq!(result.len(), 1);
//! ```
#![deny(missing_docs)]

#[macro_use]
extern crate nom;
extern crate peel;

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
    pub use std::str::{FromStr, self};
    pub use std::net::{Ipv4Addr, Ipv6Addr};
    pub use nom::*;
    pub use peel::prelude::*;

    pub use super::{Layer, ParserVariant, PeelIp};

    /// A shorthand for the packet parsing node
    pub type PacketNode = ParserNode<Layer, ParserVariant>;

    /// A shorthand for the packet parsing arena
    pub type PacketArena = ParserArena<Layer, ParserVariant>;

    /// Link
    pub use layer1::*;
    pub use layer1::ethernet::*;

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
    /// Ethernet protocol parser
    Ethernet(EthernetParser),

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

impl fmt::Display for ParserVariant {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ParserVariant::Ethernet(_) => write!(f, "Ethernet"),
            ParserVariant::Ipv4(_) => write!(f, "IPv4"),
            ParserVariant::Ipv6(_) => write!(f, "IPv6"),
            ParserVariant::Tcp(_) => write!(f, "TCP"),
            ParserVariant::Tls(_) => write!(f, "TLS"),
            ParserVariant::Http(_) => write!(f, "HTTP"),
            ParserVariant::Udp(_) => write!(f, "UDP"),
            ParserVariant::Ntp(_) => write!(f, "NTP"),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
/// Return values for the actual parsers
pub enum Layer {
    /// Ethernet protocol for layer 1
    Ethernet(EthernetPacket),

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

impl fmt::Display for Layer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Layer::Ethernet(_) => write!(f, "Ethernet"),
            Layer::Ipv4(_) => write!(f, "IPv4"),
            Layer::Ipv6(_) => write!(f, "IPv6"),
            Layer::Tcp(_) => write!(f, "TCP"),
            Layer::Tls(_) => write!(f, "TLS"),
            Layer::Http(_) => write!(f, "HTTP"),
            Layer::Udp(_) => write!(f, "UDP"),
            Layer::Ntp(_) => write!(f, "NTP"),
        }
    }
}

/// Peel for TCP/IP packets
pub struct PeelIp;

impl PeelIp {
    /// Creates a new `Peel` structure for TCP/IP based packet parsing
    pub fn new() -> Peel<Layer, ParserVariant> {
        // Create a tree
        let mut p = Peel::new();

        // Ethernet
        let eth = p.new_parser(EthernetParser);

        // IPv4/6
        let ipv4 = p.link_new_parser(eth, Ipv4Parser);
        let ipv6 = p.link_new_parser(eth, Ipv6Parser);

        // TCP
        let tcp_ipv4 = p.link_new_parser(ipv4, TcpParser);
        let tcp_ipv6 = p.link_new_parser(ipv6, TcpParser);

        // UDP
        let udp_ipv4 = p.link_new_parser(ipv4, UdpParser);
        let udp_ipv6 = p.link_new_parser(ipv6, UdpParser);

        // TLS
        let tls_ipv4 = p.link_new_parser(tcp_ipv4, TlsParser);
        let tls_ipv6 = p.link_new_parser(tcp_ipv6, TlsParser);

        // HTTP
        p.link_new_parser(tcp_ipv4, HttpParser);
        p.link_new_parser(tcp_ipv6, HttpParser);
        p.link_new_parser(tls_ipv4, HttpParser);
        p.link_new_parser(tls_ipv6, HttpParser);

        // NTP
        p.link_new_parser(udp_ipv4, NtpParser);
        p.link_new_parser(udp_ipv6, NtpParser);

        p
    }
}
