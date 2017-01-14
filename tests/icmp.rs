extern crate nom;
extern crate peel_ip;
use peel_ip::prelude::*;

static ICMP_REQUEST: &'static [u8] = &[0x08, 0x00, 0x41, 0x5c, 0x02, 0x00, 0x0a, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65,
                                       0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72,
                                       0x73, 0x74, 0x75, 0x76, 0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
                                       0x69];

#[test]
fn parse_icmp_request_success() {
    let mut parser = IcmpParser;
    println!("{}", parser);
    let parsing_result = parser.parse(ICMP_REQUEST, None, None).unwrap().1;
    let res = parsing_result.downcast_ref();
    assert_eq!(Some(&IcmpPacket {
                   message_type: IcmpType::EchoRequest,
                   code: 0,
                   checksum: 16732,
                   data: Some(IcmpData::Echo(IcmpEcho {
                       identifier: 512,
                       sequence_number: 2560,
                       payload: Some(b"abcdefghijklmnopqrstuvwabcdefghi".to_vec()),
                   })),
               }),
               res);
}

#[test]
fn parse_icmp_reply_success() {
    let mut parser = IcmpParser;
    let mut input = Vec::from(ICMP_REQUEST);
    input[0] = 0;
    let parsing_result = parser.parse(&input, None, None).unwrap().1;
    let res = parsing_result.downcast_ref();
    assert_eq!(Some(&IcmpPacket {
                   message_type: IcmpType::EchoReply,
                   code: 0,
                   checksum: 16732,
                   data: Some(IcmpData::Echo(IcmpEcho {
                       identifier: 512,
                       sequence_number: 2560,
                       payload: Some(b"abcdefghijklmnopqrstuvwabcdefghi".to_vec()),
                   })),
               }),
               res);
}

#[test]
fn parse_icmp_failure_wrong_icmp_type() {
    let mut parser = IcmpParser;
    let mut input = Vec::from(ICMP_REQUEST);
    input[0] = 1;
    assert!(parser.parse(&input, None, None).to_full_result().is_err());
}

#[test]
fn parse_icmp_failure_too_small() {
    let mut parser = IcmpParser;
    assert!(parser.parse(&ICMP_REQUEST[..7], None, None).to_full_result().is_err());
}
