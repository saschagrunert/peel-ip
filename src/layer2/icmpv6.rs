//! Internet Control Message Protocol version 6 related packet processing
use prelude::*;

/// The `ICMPv6` parser
pub struct Icmpv6Parser;

impl Parsable<PathIp> for Icmpv6Parser {
    /// Parse an `Icmpv6Packet` from an `&[u8]`
    fn parse<'a>(&mut self,
                 input: &'a [u8],
                 result: Option<&ParserResultVec>,
                 _: Option<&mut PathIp>)
                 -> IResult<&'a [u8], ParserResult> {
        do_parse!(input,
            expr_opt!(match result {
                Some(vector) => match vector.last() {
                    // ICMPv6 on top of IPv6
                    Some(ref any) => if let Some(ipv6) = any.downcast_ref::<Ipv6Packet>() {
                        if ipv6.next_header == IpProtocol::Icmpv6 {
                            Some(())
                        } else {
                            None
                        }
                    } else {
                        None
                    },

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
            (Box::new(Icmpv6Packet {
                message_type: message_type,
                code: code,
                checksum: checksum,
                data: data,
            }))
        )
    }
}

impl fmt::Display for Icmpv6Parser {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ICMPv6")
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
/// Available `ICMPv6` control messages
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
/// Representation of a certain `ICMPv6` message
pub enum Icmpv6Data {
    /// ICMPv6 ping request and reply
    Echo(IcmpEcho),
}
