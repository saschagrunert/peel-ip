//! Address Resolution Protocol related packet processing
use prelude::*;

#[derive(Debug, Clone)]
/// The ARP parser
pub struct ArpParser;

impl Parser<()> for ArpParser {
    type Result = Layer;
    type Variant = ParserVariant;

    /// Parse an `ArpPacket` from an `&[u8]`
    fn parse<'a>(&mut self,
                 input: &'a [u8],
                 result: Option<&Vec<Self::Result>>,
                 _: Option <&mut ()>)
                 -> IResult<&'a [u8], Self::Result> {
        do_parse!(input,
            // Check the type from the parent parser (Ethernet)
            expr_opt!(match result {
                Some(vector) => match vector.last() {
                    // Check the parent node for the correct EtherType
                    Some(&Layer::Ethernet(ref e)) if e.ethertype == EtherType::Arp => Some(()),

                    // Previous result found, but not correct parent
                    _ => None,
                },
                // Parse also if no result is given, for testability
                None => Some(()),
            }) >>

            hw_type: map_opt!(be_u16, ArpHardwareType::from_u16) >>
            p_type: map_opt!(be_u16, EtherType::from_u16) >>
            hw_len: be_u8 >>
            pr_len: be_u8 >>
            oper: map_opt!(be_u16, ArpOperation::from_u16) >>
            s: take!(6) >>
            ip_sender: map!(be_u32, Ipv4Addr::from) >>
            t: take!(6) >>
            ip_target: map!(be_u32, Ipv4Addr::from) >>

            (Layer::Arp(ArpPacket {
                hardware_type: hw_type,
                protocol_type: p_type,
                hardware_length: hw_len,
                protocol_length: pr_len,
                operation: oper,
                sender_hardware_address: MacAddress(s[0], s[1], s[2], s[3], s[4], s[5]),
                sender_protocol_address: ip_sender,
                target_hardware_address: MacAddress(t[0], t[1], t[2], t[3], t[4], t[5]),
                target_protocol_address: ip_target,
            }))
        )
    }

    fn variant(&self) -> Self::Variant {
        ParserVariant::Arp(self.clone())
    }
}

#[derive(Debug, Eq, PartialEq)]
/// Representation of the Arp structure
pub struct ArpPacket {
    /// This field specifies the network protocol type. Example: Ethernet is 1.
    pub hardware_type: ArpHardwareType,

    /// This field specifies the internetwork protocol for which the ARP request is
    /// intended. For IPv4, this has the value 0x0800. The permitted PTYPE values share a numbering
    /// space with those for EtherType.
    pub protocol_type: EtherType,

    /// Length (in octets) of a hardware address. Ethernet addresses size is 6.
    pub hardware_length: u8,

    /// Length (in octets) of addresses used in the upper layer protocol. (The
    /// upper layer protocol specified in PTYPE.) IPv4 address size is 4.
    pub protocol_length: u8,

    /// Specifies the operation that the sender is performing: 1 for request, 2 for reply.
    pub operation: ArpOperation,

    /// Media address of the sender.
    pub sender_hardware_address: MacAddress,

    /// Internetwork address of the sender.
    pub sender_protocol_address: Ipv4Addr,

    /// Media address of the intended receiver.
    pub target_hardware_address: MacAddress,

    /// Target protocol address: Internetwork address of the intended receiver.
    pub target_protocol_address: Ipv4Addr,
}


#[derive(Debug, Eq, PartialEq)]
/// Supported ARP Hardware Types
pub enum ArpHardwareType {
    /// Ethernet (10Mb)
    Ethernet,
}

impl ArpHardwareType {
    /// Convert a u16 to an `ArpHardwareType`. Returns None if the type is not supported or
    /// generally invalid.
    pub fn from_u16(input: u16) -> Option<ArpHardwareType> {
        match input {
            1 => Some(ArpHardwareType::Ethernet),
            _ => None,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
/// Supported ARP operations
pub enum ArpOperation {
    /// ARP requests
    Request,

    /// ARP responses
    Reply,

    /// Reverse ARP requests
    ReverseRequest,

    /// Reverse ARP responses
    ReverseReply,
}

impl ArpOperation {
    /// Convert a u16 to an `ArpOperation`. Returns None if the type is not supported or generally
    /// invalid.
    pub fn from_u16(input: u16) -> Option<ArpOperation> {
        match input {
            1 => Some(ArpOperation::Request),
            2 => Some(ArpOperation::Reply),
            3 => Some(ArpOperation::ReverseRequest),
            4 => Some(ArpOperation::ReverseReply),
            _ => None,
        }
    }
}
