//! Ethernet related packet processing
use prelude::*;

#[derive(Debug, Clone)]
/// The Ethernet parser
pub struct EthernetParser;

impl Parser<PathIp> for EthernetParser {
    type Result = Layer;
    type Variant = ParserVariant;

    /// Parse an `EthernetPacket` from an `&[u8]`
    fn parse<'a>(&mut self,
                 input: &'a [u8],
                 _: Option<&Vec<Self::Result>>,
                 _: Option<&mut PathIp>)
                 -> IResult<&'a [u8], Self::Result> {
        do_parse!(input,
            d: take!(6) >>
            s: take!(6) >>
            e: map_opt!(be_u16, EtherType::from_u16) >>

            (Layer::Ethernet(EthernetPacket {
                dst: MacAddress(d[0], d[1], d[2], d[3], d[4], d[5]),
                src: MacAddress(s[0], s[1], s[2], s[3], s[4], s[5]),
                ethertype: e,
            }))
        )
    }

    fn variant(&self) -> Self::Variant {
        ParserVariant::Ethernet(self.clone())
    }
}

#[derive(Debug, Eq, PartialEq)]
/// Representation of the Ethernet structure
pub struct EthernetPacket {
    /// Destination mac address
    pub dst: MacAddress,

    /// Source mac address
    pub src: MacAddress,

    /// EtherType of the packet
    pub ethertype: EtherType,
}

#[derive(Debug, Default, Eq, PartialEq)]
/// Representation of a mac network address, usually in the format "ff:ff:ff:ff:ff:ff"
pub struct MacAddress(pub u8, pub u8, pub u8, pub u8, pub u8, pub u8);

#[derive(Debug, Eq, PartialEq)]
/// Supported `EtherType`
pub enum EtherType {
    /// Internet Protocol Version 4
    Ipv4,

    /// Address Resolution Protocol
    Arp,

    /// Internet Protocol Version 6
    Ipv6,
}

impl EtherType {
    /// Convert a u16 to an `EtherType`. Returns None if the type is not supported or generally
    /// invalid.
    pub fn from_u16(input: u16) -> Option<EtherType> {
        match input {
            0x0800 => Some(EtherType::Ipv4),
            0x0806 => Some(EtherType::Arp),
            0x86DD => Some(EtherType::Ipv6),
            _ => None,
        }
    }
}
