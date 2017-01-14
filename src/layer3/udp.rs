//! User Datagram Protocol related packet processing
use prelude::*;

/// The UDP parser
pub struct UdpParser;

impl Parsable<PathIp> for UdpParser {
    /// Parse an `UdpPacket` from an `&[u8]`
    fn parse<'a>(&mut self,
                 input: &'a [u8],
                 result: Option<&ParserResultVec>,
                 path: Option<&mut PathIp>)
                 -> IResult<&'a [u8], ParserResult> {
        do_parse!(input,
            // Check the IP protocol from the parent parser (IPv4 or IPv6)
            expr_opt!(match result {
                Some(vector) => match vector.last() {
                    // Check the parent node for the correct IP protocol
                    Some(ref any) => match (any.downcast_ref::<Ipv4Packet>(),
                                            any.downcast_ref::<Ipv6Packet>()) {

                        // IPv4
                        (Some(ipv4), _) => if ipv4.protocol == IpProtocol::Udp {
                            Some(())
                        } else {
                            None
                        },

                        // IPv6
                        (_, Some(ipv6)) => if ipv6.next_header == IpProtocol::Udp {
                            Some(())
                        } else {
                            None
                        },

                        _ => None,
                    },

                    // Previous result found, but not correct parent
                    _ => None,
                },
                // Parse also if no result is given, for testability
                None => Some(()),
            }) >>

            // Parse the header
            src: be_u16 >>
            dst: be_u16 >>
            len: be_u16 >>
            checksum: be_u16 >>

            // Try to track the connection
            path_error: expr_opt!(match track_connection(path, result, src, dst) {
                Err(e) => Some(Some(e.code)),
                Ok(()) => Some(None),
            }) >>

            (Box::new(UdpPacket {
                header: UdpHeader {
                    source_port: src,
                    dest_port: dst,
                    length: len,
                    checksum: checksum,
                },
                path_error: path_error,
            }))
        )
    }
}

impl fmt::Display for UdpParser {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "UDP")
    }
}

#[derive(Debug, Eq, PartialEq)]
/// Representation of an User Datagram Protocol packet
pub struct UdpPacket {
    /// The header of the UDP packet
    pub header: UdpHeader,

    /// Set to some error code if the connection tracking failed
    pub path_error: Option<PathErrorType>,
}

#[derive(Debug, Eq, PartialEq)]
/// Representation of an User Datagram Protocol packet header
pub struct UdpHeader {
    /// This field identifies the sender's port when meaningful and should be assumed to be the
    /// port to reply to if needed. If not used, then it should be zero. If the source host is the
    /// client, the port number is likely to be an ephemeral port number. If the source host is the
    /// server, the port number is likely to be a well-known port number.
    pub source_port: u16,

    /// This field identifies the receiver's port and is required. Similar to source port number,
    /// if the client is the destination host then the port number will likely be an ephemeral port
    /// number and if the destination host is the server then the port number will likely be a
    /// well-known port number.
    pub dest_port: u16,

    /// A field that specifies the length in bytes of the UDP header and UDP data. The minimum
    /// length is 8 bytes because that is the length of the header. The field size sets a
    /// theoretical limit of 65,535 bytes (8 byte header + 65,527 bytes of data) for a UDP
    /// datagram. The practical limit for the data length which is imposed by the underlying IPv4
    /// protocol is 65,507 bytes (65,535 − 8 byte UDP header − 20 byte IP header).
    /// In IPv6 jumbograms it is possible to have UDP packets of size greater than 65,535 bytes.
    /// RFC 2675 specifies that the length field is set to zero if the length of the UDP header
    /// plus UDP data is greater than 65,535.
    pub length: u16,

    /// The checksum field may be used for error-checking of the header and data. This field is
    /// optional in IPv4, and mandatory in IPv6. The field carries all-zeros if unused.
    pub checksum: u16,
}
