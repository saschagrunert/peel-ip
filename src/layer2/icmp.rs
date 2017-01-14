//! Internet Control Message Protocol related packet processing
use prelude::*;

/// The ICMP parser
pub struct IcmpParser;

impl Parsable<PathIp> for IcmpParser {
    /// Parse an `IcmpPacket` from an `&[u8]`
    fn parse<'a>(&mut self,
                 input: &'a [u8],
                 result: Option<&ParserResultVec>,
                 _: Option<&mut PathIp>)
                 -> IResult<&'a [u8], ParserResult> {
        do_parse!(input,
            expr_opt!(match result {
                Some(vector) => match vector.last() {
                    // ICMP on top of IPv4
                    Some(ref any) => if let Some(ipv4) = any.downcast_ref::<Ipv4Packet>() {
                        if ipv4.protocol == IpProtocol::Icmp {
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
            message_type: map_opt!(be_u8, IcmpType::from_u8) >>
            code: be_u8 >>
            checksum: be_u16 >>

            // ICMP echo
            data: cond!((message_type == IcmpType::EchoReply ||
                         message_type == IcmpType::EchoRequest) &&
                        code == 0,
                        map!(IcmpEcho::parse, |x| IcmpData::Echo(x))) >>

            // Return the parsing result
            (Box::new(IcmpPacket {
                message_type: message_type,
                code: code,
                checksum: checksum,
                data: data,
            }))
        )
    }
}

impl fmt::Display for IcmpParser {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ICMP")
    }
}

#[derive(Debug, Eq, PartialEq)]
/// Representation of an Internet Control Message Protocol packet
pub struct IcmpPacket {
    /// The ICMP type
    pub message_type: IcmpType,

    /// The message subtype
    pub code: u8,

    /// Error checking data, calculated from the ICMP header and data, with value 0 substituted for
    /// this field.
    pub checksum: u16,

    /// Contents vary based on the type and code.
    pub data: Option<IcmpData>,
}

#[derive(Debug, Eq, PartialEq)]
/// Available ICMP control messages
pub enum IcmpType {
    /// Echo reply used to ping
    EchoReply,

    /// Echo request used to ping
    EchoRequest,
}

impl IcmpType {
    /// Convert a u8 to an `IcmpType`. Returns None if the type is not supported or generally
    /// invalid.
    pub fn from_u8(input: u8) -> Option<IcmpType> {
        match input {
            0 => Some(IcmpType::EchoReply),
            8 => Some(IcmpType::EchoRequest),
            _ => None,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
/// Representation of a certain ICMP message
pub enum IcmpData {
    /// ICMP ping request and reply
    Echo(IcmpEcho),
}

#[derive(Debug, Eq, PartialEq)]
/// ICMP echo request and replies
pub struct IcmpEcho {
    /// Identifier
    pub identifier: u16,

    /// Sequence Number
    pub sequence_number: u16,

    /// Optional payload
    pub payload: Option<Vec<u8>>,
}

impl IcmpEcho {
    named!(#[doc = "Parse an ICMP echo request or reply"],
           pub parse<&[u8], IcmpEcho>,
        do_parse!(
            identifier: be_u16 >>
            sequence_number: be_u16 >>
            payload: opt!(map!(rest, Vec::from)) >>

            (IcmpEcho {
                identifier: identifier,
                sequence_number: sequence_number,
                payload: payload,
            })
        )
    );
}
