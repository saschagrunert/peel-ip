//! Transmission Control Protocol related packet processing
use prelude::*;

#[derive(Debug, Clone)]
/// The TCP parser
pub struct TcpParser;

impl Parsable<PathIp> for TcpParser {
    /// Parse a `TcpPacket` from an `&[u8]`
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
                        (Some(ipv4), _) => if ipv4.protocol == IpProtocol::Tcp {
                            Some(())
                        } else {
                            None
                        },

                        // IPv6
                        (_, Some(ipv6)) => if ipv6.next_header == IpProtocol::Tcp {
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
            seq: be_u32 >>
            ack: be_u32 >>
            data_offset_res_flags : bits!(tuple!(take_bits!(u8, 4),
                                                 take_bits!(u8, 6),
                                                 take_bits!(u8, 6))) >>
            window : be_u16 >>
            checksum : be_u16 >>
            urgent_ptr : be_u16 >>
            options_check: expr_opt!((data_offset_res_flags.0 * 4).checked_sub(20)) >>
            options: take!(options_check) >>

            // Try to track the connection
            path_error: expr_opt!(match track_connection(path, result, src, dst) {
                Err(e) => Some(Some(e.code)),
                Ok(()) => Some(None),
            }) >>

            (Box::new(TcpPacket {
                header: TcpHeader {
                    source_port: src,
                    dest_port: dst,
                    sequence_no: seq,
                    ack_no: ack,
                    data_offset: data_offset_res_flags.0 * 4,
                    reserved: data_offset_res_flags.1,
                    flag_urg: data_offset_res_flags.2 & 0b100000 == 0b100000,
                    flag_ack: data_offset_res_flags.2 & 0b010000 == 0b010000,
                    flag_psh: data_offset_res_flags.2 & 0b001000 == 0b001000,
                    flag_rst: data_offset_res_flags.2 & 0b000100 == 0b000100,
                    flag_syn: data_offset_res_flags.2 & 0b000010 == 0b000010,
                    flag_fin: data_offset_res_flags.2 & 0b000001 == 0b000001,
                    window: window,
                    checksum: checksum,
                    urgent_pointer: urgent_ptr,
                    options: options.to_vec()
                },
                path_error: path_error,
            }))
        )
    }
}

impl fmt::Display for TcpParser {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TCP")
    }
}

#[derive(Debug, Eq, PartialEq)]
/// Representation of an User Datagram Protocol packet
pub struct TcpPacket {
    /// The header of the TCP packet
    pub header: TcpHeader,

    /// Set to some error code if the connection tracking failed
    pub path_error: Option<PathErrorType>,
}

#[derive(Debug, Eq, PartialEq)]
/// Representation of a Transmission Control Protocol packet header
pub struct TcpHeader {
    /// Identifies the sending port
    pub source_port: u16,

    /// Identifies the receiving port
    pub dest_port: u16,

    /// If the SYN flag is set (1), then this is the initial sequence number. The sequence number
    /// of the actual first data byte and the acknowledged number in the corresponding ACK are then
    /// this sequence number plus 1.
    /// If the SYN flag is clear (0), then this is the accumulated sequence number of the first
    /// data byte of this segment for the current session.
    pub sequence_no: u32,

    /// If the ACK flag is set then the value of this field is the next sequence number that the
    /// sender is expecting. This acknowledges receipt of all prior bytes (if any). The first ACK
    /// sent by each end acknowledges the other end's initial sequence number itself, but no data.
    pub ack_no: u32,

    /// Specifies the size of the TCP header in 32-bit words. The minimum size header is 5 words
    /// and the maximum is 15 words thus giving the minimum size of 20 bytes and maximum of 60
    /// bytes, allowing for up to 40 bytes of options in the header. This field gets its name from
    /// the fact that it is also the offset from the start of the TCP segment to the actual data.
    pub data_offset: u8,

    /// Kor future use and should be set to zero
    pub reserved: u8,

    /// Indicates that the Urgent pointer field is significant
    pub flag_urg: bool,

    /// Indicates that the Acknowledgment field is significant. All packets after the initial SYN
    /// packet sent by the client should have this flag set.
    pub flag_ack: bool,

    /// Push function. Asks to push the buffered data to the receiving application.
    pub flag_psh: bool,

    /// Reset the connection
    pub flag_rst: bool,

    /// Synchronize sequence numbers. Only the first packet sent from each end should have this
    /// flag set. Some other flags and fields change meaning based on this flag, and some are only
    /// valid for when it is set, and others when it is clear.
    pub flag_syn: bool,

    /// No more data from sender
    pub flag_fin: bool,

    /// The size of the receive window, which specifies the number of window size units (by
    /// default, bytes) (beyond the segment identified by the sequence number in the acknowledgment
    /// field) that the sender of this segment is currently willing to receive (see Flow control
    /// and Window Scaling)
    pub window: u16,

    /// The 16-bit checksum field is used for error-checking of the header and data
    pub checksum: u16,

    /// If the URG flag is set, then this 16-bit field is an offset from the sequence number
    /// indicating the last urgent data byte
    pub urgent_pointer: u16,

    /// The length of this field is determined by the data offset field.
    pub options: Vec<u8>,
}
