//! Internet Protocol version 4 related packet processing
use prelude::*;

#[derive(Debug, Clone)]
/// The IPv4 parser
pub struct Ipv4Parser;

impl Parser<PathIp> for Ipv4Parser {
    type Result = Layer;
    type Variant = ParserVariant;

    /// Parse an `Ipv4Packet` from an `&[u8]`
    fn parse<'a>(&mut self,
                 input: &'a [u8],
                 result: Option<&Vec<Self::Result>>,
                 _: Option<&mut PathIp>)
                 -> IResult<&'a [u8], Self::Result> {
        do_parse!(input,
            // Check the type from the parent parser (Ethernet)
            expr_opt!(match result {
                Some(vector) => match vector.last() {
                    // Check the parent node for the correct EtherType
                    Some(&Layer::Ethernet(ref e)) if e.ethertype == EtherType::Ipv4 => Some(()),

                    // IPv4 in IPv4 encapsulation
                    Some(&Layer::Ipv4(ref e)) if e.protocol == IpProtocol::IpIp => Some(()),

                    // Previous result found, but not correct parent
                    _ => None,
                },
                // Parse also if no result is given, for testability
                None => Some(()),
            }) >>

            // Parse the actual packet
            ver_ihl: bits!(pair!(tag_bits!(u8, 4, 4),
                                 take_bits!(u8, 4))) >>
            tos: be_u8 >>
            length: be_u16 >>
            id: be_u16 >>
            flags_and_fragment_offset: bits!(pair!(take_bits!(u8, 3),
                                                   take_bits!(u16, 13))) >>
            ttl: be_u8 >>
            protocol: map_opt!(be_u8, IpProtocol::from_u8) >>
            checksum: be_u16 >>
            src: map!(be_u32, Ipv4Addr::from) >>
            dst: map!(be_u32, Ipv4Addr::from) >>

            // Return the parsing result
            (Layer::Ipv4(Ipv4Packet {
                version: ver_ihl.0,
                ihl: ver_ihl.1 << 2,
                tos: tos,
                length: length,
                id: id,
                flags: flags_and_fragment_offset.0,
                fragment_offset: flags_and_fragment_offset.1,
                ttl: ttl,
                protocol: protocol,
                checksum: checksum,
                src: src,
                dst: dst,
            }))
        )
    }

    fn variant(&self) -> Self::Variant {
        ParserVariant::Ipv4(self.clone())
    }
}

#[derive(Debug, Eq, PartialEq)]
/// Representation of an Internet Protocol version 4 packet
pub struct Ipv4Packet {
    /// Protocol version, should be '4'
    pub version: u8,

    /// IP header length
    pub ihl: u8,

    /// Type of Service
    pub tos: u8,

    /// Total packet length including header
    pub length: u16,

    /// Identification for the packet reassembly
    pub id: u16,

    /// IP header flags for fragmentation reassembly
    pub flags: u8,

    /// Current fragmentation offset
    pub fragment_offset: u16,

    /// Time to live of the packet
    pub ttl: u8,

    /// The transport protocol for the IP packet
    pub protocol: IpProtocol,

    /// Header checksum
    pub checksum: u16,

    /// Source address
    pub src: Ipv4Addr,

    /// Destination address
    pub dst: Ipv4Addr,
}

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
/// Current supported IPv4 protocols
pub enum IpProtocol {
    /// Internet Control Message Protocol
    Icmp,

    /// IP encapsulation within IP
    IpIp,

    /// Transmission Control Protocol
    Tcp,

    /// User Datagram Protocol
    Udp,

    /// IPv6 Encapsulation
    Ipv6,

    /// Internet Control Message Protocol version 6
    Icmpv6,
}

impl IpProtocol {
    /// Convert a u8 to an `IpProtocol`. Returns None if the type is not supported or generally
    /// invalid.
    pub fn from_u8(input: u8) -> Option<IpProtocol> {
        match input {
            1 => Some(IpProtocol::Icmp),
            4 => Some(IpProtocol::IpIp),
            6 => Some(IpProtocol::Tcp),
            17 => Some(IpProtocol::Udp),
            41 => Some(IpProtocol::Ipv6),
            58 => Some(IpProtocol::Icmpv6),
            _ => None,
        }
    }
}
