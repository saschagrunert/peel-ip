//! Internet Control Message Protocol version 6 related packet processing
use prelude::*;

#[derive(Debug, Clone)]
/// The ICMPv6 parser
pub struct Icmpv6Parser;

impl Parser<PathIp> for Icmpv6Parser {
    type Result = Layer;
    type Variant = ParserVariant;

    /// Parse an `Icmpv6Packet` from an `&[u8]`
    fn parse<'a>(&mut self,
                 input: &'a [u8],
                 result: Option<&Vec<Self::Result>>,
                 _: Option<&mut PathIp>)
                 -> IResult<&'a [u8], Self::Result> {
        do_parse!(input,
            expr_opt!(match result {
                Some(vector) => match vector.last() {
                    // ICMPv6 on top of IPv6
                    Some(&Layer::Ipv6(ref e)) if e.next_header == IpProtocol::Icmpv6 => Some(()),

                    // Previous result found, but not correct parent
                    _ => None,
                },
                // Parse also if no result is given, for testability
                None => Some(()),
            }) >>

            // Parse the actual packet
            message_type: map_opt!(be_u8, Icmpv6Type::from_u8) >>
            code: be_u8 >>
            checksum: be_u16 >>

            // ICMPv6 echo
            data: cond!((message_type == Icmpv6Type::EchoReply ||
                         message_type == Icmpv6Type::EchoRequest) &&
                        code == 0,
                        map!(IcmpEcho::parse, |x| Icmpv6Data::Echo(x))) >>

            // Return the parsing result
            (Layer::Icmpv6(Icmpv6Packet {
                message_type: message_type,
                code: code,
                checksum: checksum,
                data: data,
            }))
        )
    }

    fn variant(&self) -> Self::Variant {
        ParserVariant::Icmpv6(self.clone())
    }
}

#[derive(Debug, Eq, PartialEq)]
/// Representation of an Internet Control Message Protocol packet
pub struct Icmpv6Packet {
    /// The ICMPv6 type
    pub message_type: Icmpv6Type,

    /// The message subtype
    pub code: u8,

    /// Error checking data, calculated from the ICMPv6 header and data, with value 0 substituted for
    /// this field.
    pub checksum: u16,

    /// Contents vary based on the type and code.
    pub data: Option<Icmpv6Data>,
}

#[derive(Debug, Eq, PartialEq)]
/// Available ICMPv6 control messages
pub enum Icmpv6Type {
    /// Echo reply used to ping
    EchoReply,

    /// Echo request used to ping
    EchoRequest,
}

impl Icmpv6Type {
    /// Convert a u8 to an `Icmpv6Type`. Returns None if the type is not supported or generally
    /// invalid.
    pub fn from_u8(input: u8) -> Option<Icmpv6Type> {
        match input {
            128 => Some(Icmpv6Type::EchoRequest),
            129 => Some(Icmpv6Type::EchoReply),
            _ => None,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
/// Representation of a certain ICMPv6 message
pub enum Icmpv6Data {
    /// ICMPv6 ping request and reply
    Echo(IcmpEcho),
}
