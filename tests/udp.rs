extern crate nom;
extern crate peel_ip;
use peel_ip::prelude::*;

static UDP_HEADER: &'static [u8] = &[0x00, 0x35, 0xc7, 0xde, 0x00, 0x92, 0xad, 0x1b];

#[test]
fn parse_udp_success() {
    let mut parser = UdpParser;
    println!("{}", parser);
    let parsing_result = parser.parse(UDP_HEADER, None, None).unwrap().1;
    let res = parsing_result.downcast_ref();
    assert_eq!(Some(&UdpPacket {
                   header: UdpHeader {
                       source_port: 53,
                       dest_port: 51166,
                       length: 146,
                       checksum: 44315,
                   },
                   path_error: None,
               }),
               res);
}

#[test]
fn parse_udp_failure_too_small() {
    let mut parser = UdpParser;
    let mut input = Vec::from(UDP_HEADER);
    input.pop();
    assert!(parser.parse(&input, None, None).to_full_result().is_err());
}
