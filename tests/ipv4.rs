extern crate nom;
extern crate peel_ip;
use peel_ip::prelude::*;

static IPV4_HEADER: &'static [u8] = &[0x45, 0x00, 0x01, 0xa5, 0xd6, 0x63, 0x40, 0x00, 0x3f, 0x06, 0x9b, 0xfc, 0xc0,
                                      0xa8, 0x01, 0x0a, 0xad, 0xfc, 0x58, 0x44];

#[test]
fn parse_ipv4_success() {
    let mut parser = Ipv4Parser;
    println!("{}", parser);
    let parsing_result = parser.parse(IPV4_HEADER, None, None).unwrap().1;
    let res = parsing_result.downcast_ref();
    assert_eq!(Some(&Ipv4Packet {
                   version: 4,
                   ihl: 20,
                   tos: 0,
                   length: 421,
                   id: 54883,
                   flags: 2,
                   fragment_offset: 0,
                   ttl: 63,
                   protocol: IpProtocol::Tcp,
                   checksum: 39932,
                   src: Ipv4Addr::new(192, 168, 1, 10),
                   dst: Ipv4Addr::new(173, 252, 88, 68),
               }),
               res);
}

#[test]
fn parse_ipv4_success_ipprotocols() {
    let mut parser = Ipv4Parser;
    // TCP
    let mut input = Vec::from(IPV4_HEADER);
    parser.parse(&input, None, None).unwrap();

    // UDP
    input[9] = 17;
    parser.parse(&input, None, None).unwrap();
}

#[test]
fn parse_ipv4_failure_wrong_version() {
    let mut parser = Ipv4Parser;
    let mut input = Vec::from(IPV4_HEADER);
    input[0] = 0x55;
    assert!(parser.parse(&input, None, None).to_full_result().is_err());
}

#[test]
fn parse_ipv4_failure_wrong_ipprotocol() {
    let mut parser = Ipv4Parser;
    let mut input = Vec::from(IPV4_HEADER);
    input[9] = 0xff;
    assert!(parser.parse(&input, None, None).to_full_result().is_err());
}

#[test]
fn parse_ipv4_failure_too_small() {
    let mut parser = Ipv4Parser;
    let mut input = Vec::from(IPV4_HEADER);
    input.pop();
    assert!(parser.parse(&input, None, None).to_full_result().is_err());
}
