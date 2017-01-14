extern crate nom;
extern crate peel_ip;
use peel_ip::prelude::*;

static ICMPV6_REQUEST: &'static [u8] = &[0x80, 0x00, 0x41, 0x5c, 0x02, 0x00, 0x0a, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65,
                                         0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72,
                                         0x73, 0x74, 0x75, 0x76, 0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
                                         0x69];

#[test]
fn parse_icmpv6_request_success() {
    let mut parser = Icmpv6Parser;
    println!("{}", parser);
    let parsing_result = parser.parse(ICMPV6_REQUEST, None, None).unwrap().1;
    let res = parsing_result.downcast_ref();
    assert_eq!(Some(&Icmpv6Packet {
                   message_type: Icmpv6Type::EchoRequest,
                   code: 0,
                   checksum: 16732,
                   data: Some(Icmpv6Data::Echo(IcmpEcho {
                       identifier: 512,
                       sequence_number: 2560,
                       payload: Some(b"abcdefghijklmnopqrstuvwabcdefghi".to_vec()),
                   })),
               }),
               res);
}

#[test]
fn parse_icmpv6_reply_success() {
    let mut parser = Icmpv6Parser;
    let mut input = Vec::from(ICMPV6_REQUEST);
    input[0] = 129;
    let parsing_result = parser.parse(&input, None, None).unwrap().1;
    let res = parsing_result.downcast_ref();
    assert_eq!(Some(&Icmpv6Packet {
                   message_type: Icmpv6Type::EchoReply,
                   code: 0,
                   checksum: 16732,
                   data: Some(Icmpv6Data::Echo(IcmpEcho {
                       identifier: 512,
                       sequence_number: 2560,
                       payload: Some(b"abcdefghijklmnopqrstuvwabcdefghi".to_vec()),
                   })),
               }),
               res);
}

#[test]
fn parse_icmpv6_failure_wrong_icmpv6_type() {
    let mut parser = Icmpv6Parser;
    let mut input = Vec::from(ICMPV6_REQUEST);
    input[0] = 1;
    assert!(parser.parse(&input, None, None).to_full_result().is_err());
}

#[test]
fn parse_icmpv6_failure_too_small() {
    let mut parser = Icmpv6Parser;
    assert!(parser.parse(&ICMPV6_REQUEST[..7], None, None).to_full_result().is_err());
}
