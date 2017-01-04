extern crate nom;
extern crate peel_ip;
use peel_ip::prelude::*;

static TCP_HEADER: &'static [u8] = &[0xca, 0x45, 0x01, 0xbb, 0x98, 0x66, 0x5f, 0x0a, 0x44, 0x9d, 0x7f, 0x05, 0x80,
                                     0x18, 0x20, 0x00, 0x0f, 0x1c, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x00, 0x02,
                                     0x2c, 0x2e, 0x63, 0x93, 0xf1, 0x5b];

#[test]
fn tcp_parser_variant() {
    let parser = TcpParser;
    println!("{:?}", parser.variant());
}

#[test]
fn parse_tcp_success() {
    let mut parser = TcpParser;
    let res = parser.parse(TCP_HEADER, None, None).unwrap().1;
    println!("{}", res);
    assert_eq!(Layer::Tcp(TcpPacket {
                   header: TcpHeader {
                       source_port: 51781,
                       dest_port: 443,
                       sequence_no: 2556845834,
                       ack_no: 1151172357,
                       data_offset: 32,
                       reserved: 0,
                       flag_urg: false,
                       flag_ack: true,
                       flag_psh: true,
                       flag_rst: false,
                       flag_syn: false,
                       flag_fin: false,
                       window: 8192,
                       checksum: 3868,
                       urgent_pointer: 0,
                       options: TCP_HEADER[20..].to_vec(),
                   },
                   path_error: None,
               }),
               res);
}

#[test]
fn parse_tcp_failure_too_small() {
    let mut parser = TcpParser;
    let mut input = Vec::from(TCP_HEADER);
    input.pop();
    let res = parser.parse(&input, None, None);
    assert_eq!(res, IResult::Incomplete(Needed::Size(32)));
}

#[test]
fn parse_tcp_failure_wrong_result() {
    let mut parser = TcpParser;
    let res = parser.parse(TCP_HEADER, Some(&vec![]), None);
    assert_eq!(res,
               IResult::Error(Err::Position(ErrorKind::ExprOpt, &TCP_HEADER[..])));
}
