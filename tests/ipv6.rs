extern crate nom;
extern crate peel_ip;
use peel_ip::prelude::*;

static IPV6_HEADER: &'static [u8] = &[0x60, 0x00, 0x00, 0x00, 0x00, 0x2f, 0x06, 0x40, 0x3f, 0xfe, 0x05, 0x07, 0x00,
                                      0x00, 0x00, 0x01, 0x02, 0x00, 0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0x3f, 0xfe,
                                      0x05, 0x01, 0x04, 0x10, 0x00, 0x00, 0x02, 0xc0, 0xdf, 0xff, 0xfe, 0x47, 0x03,
                                      0x3e];

#[test]
fn ipv6_parser_variant() {
    let parser = Ipv6Parser;
    println!("{:?}", parser.variant());
}

#[test]
fn parse_ipv6_success() {
    let parser = Ipv6Parser;
    let res = parser.parse(IPV6_HEADER, None, None, None).unwrap().1;
    println!("{}", res.0);
    assert_eq!(Layer::Ipv6(Ipv6Packet {
                   version: 6,
                   traffic_class: 0,
                   flow_label: 0,
                   payload_length: 47,
                   next_header: IpProtocol::Tcp,
                   hop_limit: 64,
                   src: Ipv6Addr::new(0x3ffe, 0x507, 0, 1, 0x200, 0x86ff, 0xfe05, 0x80da),
                   dst: Ipv6Addr::new(0x3ffe, 0x501, 0x410, 0, 0x2c0, 0xdfff, 0xfe47, 0x33e),
               }),
               res.0);
    assert_eq!(res.1, ParserState::ContinueWithFirstChild);
}

#[test]
fn parse_ipv6_success_ipprotocols() {
    let parser = Ipv6Parser;
    // TCP
    let mut input = Vec::from(IPV6_HEADER);
    parser.parse(&input, None, None, None).unwrap();

    // UDP
    input[6] = 17;
    parser.parse(&input, None, None, None).unwrap();
}

#[test]
fn parse_ipv6_failure_wrong_version() {
    let parser = Ipv6Parser;
    let mut input = Vec::from(IPV6_HEADER);
    input[0] = 0x55;
    let res = parser.parse(&input, None, None, None);
    assert_eq!(res,
               IResult::Error(Err::Position(ErrorKind::TagBits, &input[..])));
}

#[test]
fn parse_ipv6_failure_wrong_ipprotocol() {
    let parser = Ipv6Parser;
    let mut input = Vec::from(IPV6_HEADER);
    input[6] = 0xff;
    let res = parser.parse(&input, None, None, None);
    assert_eq!(res,
               IResult::Error(Err::Position(ErrorKind::MapOpt, &input[6..])));
}

#[test]
fn parse_ipv6_failure_too_small() {
    let parser = Ipv6Parser;
    let mut input = Vec::from(IPV6_HEADER);
    input.pop();
    let res = parser.parse(&input, None, None, None);
    assert_eq!(res, IResult::Incomplete(Needed::Size(40)));
}
