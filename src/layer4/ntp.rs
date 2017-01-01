//! Network Time Protocol related packet processing
use prelude::*;

#[derive(Debug, Clone)]
/// The UDP parser
pub struct NtpParser;

impl Parser<PathIp> for NtpParser {
    type Result = Layer;
    type Variant = ParserVariant;

    /// Parse a `NtpPacket` from an `&[u8]`
    fn parse<'a>(&mut self,
                 input: &'a [u8],
                 result: Option<&Vec<Self::Result>>,
                 _: Option<&mut PathIp>)
                 -> IResult<&'a [u8], Self::Result> {
        do_parse!(input,
            // Check the transport protocol from the parent parser (UDP)
            expr_opt!(match result {
                Some(vector) => {
                    match vector.last() {
                        // Check the parent node for the correct transport protocol
                        Some(&Layer::Udp(_)) => Some(()),

                        // Previous result found, but not correct parent
                        _ => None,
                    }
                },
                // Parse also if no result is given, for testability
                None => Some(()),
            }) >>

            b0: bits!(tuple!(take_bits!(u8, 2),
                             take_bits!(u8, 3),
                             take_bits!(u8, 3))) >>
            st: be_u8 >>
            pl: be_i8 >>
            pr: be_i8 >>
            rde: be_u32 >>
            rdi: be_u32 >>
            rid: be_u32 >>
            tsr: be_u64 >>
            tso: be_u64 >>
            tsv: be_u64 >>
            tsx: be_u64 >>
            auth: opt!(complete!(pair!(be_u32,
                                 map!(take!(16), Vec::from)))) >>

            (Layer::Ntp(NtpPacket {
                li: b0.0,
                version: b0.1,
                mode: b0.2,
                stratum: st,
                poll: pl,
                precision: pr,
                root_delay: rde,
                root_dispersion: rdi,
                ref_id: rid,
                ts_ref: tsr,
                ts_orig: tso,
                ts_recv: tsv,
                ts_xmit: tsx,
                auth: auth,
            }))
        )
    }

    fn variant(&self) -> Self::Variant {
        ParserVariant::Ntp(self.clone())
    }
}

#[derive(Debug, Eq, PartialEq)]
/// Representation of a Network Time Protocol packet
pub struct NtpPacket {
    /// Leap Indicator (2 Bit)
    /// This field is used to warn of an impending leap second
    pub li: u8,

    /// NTP version number (3 Bit)
    pub version: u8,

    /// Mode (3 Bit)
    pub mode: u8,

    /// Stratum level of the local clock
    pub stratum: u8,

    /// The maximum interval between messages in seconds to the nearest power of two
    pub poll: i8,

    /// Precision of the local clock in seconds to the nearest power of two
    pub precision: i8,

    /// The total round trip delay to the primary reference source, in seconds with the fraction
    /// point between bits 15 and 16. Positive and negative values are valid
    pub root_delay: u32,

    /// The maximum error relative to the primary reference source in seconds with the fraction
    /// point between bits 15 and 16. Only positive values greater than zero are valid
    pub root_dispersion: u32,

    /// Reference clock identifier. Used to identify the particular reference clock.
    pub ref_id: u32,

    /// Reference timestamp. The local time at which the local clock was last set or corrected.
    pub ts_ref: u64,

    /// Originate timestamp. The local time when the client sent the request.
    pub ts_orig: u64,

    /// Receive timestamp. The local time when the request was received by the server.
    pub ts_recv: u64,

    /// Transmit timestamp. The local time when the reply was sent from the server.
    pub ts_xmit: u64,

    /// Authenticator. (0 or 96 Bit) See section 7.5 of [RFC5905] and [RFC7822]
    pub auth: Option<(u32, Vec<u8>)>,
}
