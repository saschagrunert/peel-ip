extern crate nom;
extern crate peel_ip;
use peel_ip::prelude::*;

static NTP_HEADER: &'static [u8] =
    &[0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0xcc, 0x25, 0xcc, 0x13, 0x2b, 0x02, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x52, 0x80,
      0x0c, 0x2b, 0x59, 0x00, 0x64, 0x66, 0x84, 0xf4, 0x4c, 0xa4, 0xee, 0xce, 0x12, 0xb8];

#[test]
fn parse_ntp_success() {
    let parser = NtpParser;
    let res = parser.parse(NTP_HEADER, None, None, None).unwrap().1;
    println!("{}", res);
    assert_eq!(Layer::Ntp(NtpPacket {
                   li: 0,
                   version: 4,
                   mode: 3,
                   stratum: 0,
                   poll: 0,
                   precision: 0,
                   root_delay: 12,
                   root_dispersion: 0,
                   ref_id: 0,
                   ts_ref: 0,
                   ts_orig: 0,
                   ts_recv: 0,
                   ts_xmit: 14710388140573593600,
                   auth: Some((1, NTP_HEADER[52..].to_vec())),
               }),
               res);
}

#[test]
fn parse_ntp_failure_too_small() {
    let parser = NtpParser;
    let res = parser.parse(&NTP_HEADER[..47], None, None, None);
    assert_eq!(res, IResult::Incomplete(Needed::Size(48)));
}
