//! Transport layer security related packet processing
use prelude::*;

#[derive(Debug, Clone)]
/// The TLS parser
pub struct TlsParser;

impl Parser for TlsParser {
    type Result = Layer;
    type Variant = ParserVariant;

    /// Parse a `TlsPacket` from an `&[u8]`
    fn parse<'a>(&self,
                 input: &'a [u8],
                 _: Option<&ParserNode>,
                 _: Option<&ProtocolGraph>,
                 result: Option<&Vec<Self::Result>>)
                 -> IResult<&'a [u8], Self::Result> {
        do_parse!(input,
            // Check the transport protocol from the parent parser (TCP)
            expr_opt!(match result {
                Some(vector) => match vector.last() {
                    // Check the parent node for the correct transport protocol
                    Some(&Layer::Tcp(_)) => Some(()),

                    // Previous result found, but not correct parent
                    _ => None,
                },
                // Parse also if no result is given, for testability
                None => Some(()),
            }) >>

            content_type: map_opt!(be_u8, TlsRecordContentType::from_u8) >>
            version: take!(2) >>
            length: be_u16 >>

            (Layer::Tls(TlsPacket {
                content_type: content_type,
                version: TlsRecordVersion {
                    major: version[0],
                    minor: version[1],
                },
                length: length,
            }))
        )
    }

    fn variant(&self) -> Self::Variant {
        ParserVariant::Tls(self.clone())
    }
}

#[derive(Debug, Eq, PartialEq)]
/// Representation of a Transport layer security packet
pub struct TlsPacket {
    /// Content type of the record
    pub content_type: TlsRecordContentType,

    /// TLS version of the record
    pub version: TlsRecordVersion,

    /// Record length
    pub length: u16,
}

#[derive(Debug, Eq, PartialEq)]
/// TLS record protocol content type
pub enum TlsRecordContentType {
    /// Change Cipher Spec
    ChangeCipherSpec,

    /// Alert
    Alert,

    /// Handshake
    Handshake,

    /// Application Data
    ApplicationData,

    /// Heartbeat
    Heartbeat,
}

impl TlsRecordContentType {
    /// Convert a u8 to an `TlsRecordContentType`. Returns None if the type is not supported or
    /// generally invalid.
    pub fn from_u8(input: u8) -> Option<TlsRecordContentType> {
        match input {
            20 => Some(TlsRecordContentType::ChangeCipherSpec),
            21 => Some(TlsRecordContentType::Alert),
            22 => Some(TlsRecordContentType::Handshake),
            23 => Some(TlsRecordContentType::ApplicationData),
            24 => Some(TlsRecordContentType::Heartbeat),
            _ => None,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
/// TLS record protocol version
pub struct TlsRecordVersion {
    /// Major part of the TLS version
    pub major: u8,

    /// Minor part of the TLS version
    pub minor: u8,
}
