extern crate nom;
extern crate peel_ip;
use peel_ip::prelude::*;

static ETH_HEADER: &'static [u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 8, 0];

#[test]
fn parse_eth_success() {
    let mut parser = EthernetParser;
    println!("{}", parser);
    let parsing_result = parser.parse(ETH_HEADER, None, None).unwrap().1;
    let res = parsing_result.downcast_ref();
    assert_eq!(Some(&EthernetPacket {
                   dst: MacAddress(1, 2, 3, 4, 5, 6),
                   src: MacAddress(7, 8, 9, 10, 11, 12),
                   ethertype: EtherType::Ipv4,
               }),
               res);
}

#[test]
fn parse_eth_success_ethertypes() {
    let mut parser = EthernetParser;
    let mut input = Vec::from(ETH_HEADER); // IPv4
    parser.parse(&input, None, None).unwrap();

    input[13] = 0x06; // ARP
    parser.parse(&input, None, None).unwrap();

    input[12] = 0x86; // IPv6
    input[13] = 0xdd;
    parser.parse(&input, None, None).unwrap();
}

#[test]
fn parse_eth_failure_wrong_ethertype() {
    let mut parser = EthernetParser;
    let mut input = Vec::from(ETH_HEADER);
    input[13] = 0x55;
    assert!(parser.parse(&input, None, None).to_full_result().is_err());
}

#[test]
fn parse_eth_failure_too_small() {
    let mut parser = EthernetParser;
    let mut input = Vec::from(ETH_HEADER);
    input.pop();
    assert!(parser.parse(&input, None, None).to_full_result().is_err());
}
