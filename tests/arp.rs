extern crate nom;
extern crate peel_ip;
use peel_ip::prelude::*;

static ARP_REQUEST: &'static [u8] = &[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x00, 0x07, 0x0d, 0xaf, 0xf4,
                                      0x54, 0x18, 0xa6, 0xac, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0xa6,
                                      0xad, 0x9f];

static RARP_REQUEST: &'static [u8] = &[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x03, 0x00, 0x0c, 0x29, 0x34, 0x0b,
                                       0xde, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x29, 0x34, 0x0b, 0xde, 0x00, 0x00,
                                       0x00, 0x00];

#[test]
fn arp_parser_variant() {
    let parser = ArpParser;
    println!("{:?}", parser.variant());
}

#[test]
fn parse_arp_success() {
    let mut parser = ArpParser;
    let mut input = Vec::from(ARP_REQUEST);
    let res = parser.parse(&input, None, None).unwrap().1;
    println!("{}", res);
    assert_eq!(Layer::Arp(ArpPacket {
                   hardware_type: ArpHardwareType::Ethernet,
                   protocol_type: EtherType::Ipv4,
                   hardware_length: 6,
                   protocol_length: 4,
                   operation: ArpOperation::Request,
                   sender_hardware_address: MacAddress(0, 7, 13, 175, 244, 84),
                   sender_protocol_address: Ipv4Addr::new(24, 166, 172, 1),
                   target_hardware_address: MacAddress(0, 0, 0, 0, 0, 0),
                   target_protocol_address: Ipv4Addr::new(24, 166, 173, 159),
               }),
               res);
    input[7] = 2;
    parser.parse(&input, None, None).unwrap();
}

#[test]
fn parse_rarp_success() {
    let mut parser = ArpParser;
    let mut input = Vec::from(RARP_REQUEST);
    let res = parser.parse(&input, None, None).unwrap().1;
    println!("{}", res);
    assert_eq!(Layer::Arp(ArpPacket {
                   hardware_type: ArpHardwareType::Ethernet,
                   protocol_type: EtherType::Ipv4,
                   hardware_length: 6,
                   protocol_length: 4,
                   operation: ArpOperation::ReverseRequest,
                   sender_hardware_address: MacAddress(0, 12, 41, 52, 11, 222),
                   sender_protocol_address: Ipv4Addr::new(0, 0, 0, 0),
                   target_hardware_address: MacAddress(0, 12, 41, 52, 11, 222),
                   target_protocol_address: Ipv4Addr::new(0, 0, 0, 0),
               }),
               res);
    input[7] = 4;
    parser.parse(&input, None, None).unwrap();
}

#[test]
fn parse_arp_failure_too_small() {
    let mut parser = ArpParser;
    let mut input = Vec::from(ARP_REQUEST);
    input.pop();
    let res = parser.parse(&input, None, None);
    assert_eq!(res, IResult::Incomplete(Needed::Size(28)));
}

#[test]
fn parse_arp_failure_wrong_hardware_type() {
    let mut parser = ArpParser;
    let mut input = Vec::from(ARP_REQUEST);
    input[1] = 0;
    let res = parser.parse(&input, None, None);
    assert_eq!(res,
               IResult::Error(Err::Position(ErrorKind::MapOpt, &input[..])));
}

#[test]
fn parse_arp_failure_wrong_operation() {
    let mut parser = ArpParser;
    let mut input = Vec::from(ARP_REQUEST);
    input[7] = 0;
    let res = parser.parse(&input, None, None);
    assert_eq!(res,
               IResult::Error(Err::Position(ErrorKind::MapOpt, &input[6..])));
}
