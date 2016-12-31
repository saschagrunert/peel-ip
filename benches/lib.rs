#![feature(test)]
extern crate peel_ip;
extern crate test;

use test::Bencher;
use peel_ip::prelude::*;

#[bench]
fn tree_generation(bencher: &mut Bencher) {
    bencher.iter(|| {
        PeelIp::new();
    });
}

static PACKET_ETH_IPV4_TCP_TLS: &'static [u8] =
    &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x34,
      0x73, 0x22, 0x40, 0x00, 0x3f, 0x06, 0x3a, 0x09, 0x0a, 0x00, 0x00, 0x65, 0x42, 0xc4, 0x41, 0x70, 0xca, 0x45,
      0x01, 0xbb, 0x98, 0x66, 0x5f, 0x0a, 0x44, 0x9d, 0x7f, 0x05, 0x80, 0x10, 0x20, 0x00, 0xbf, 0xf2, 0x00, 0x00,
      0x01, 0x01, 0x08, 0x0a, 0x00, 0x02, 0x2c, 0x2c, 0x63, 0x93, 0xf1, 0x5b, 0x16, 0x03, 0x01, 0x00, 0xf4, 0x01,
      0x00, 0x00, 0xf0, 0x03, 0x03, 0x14, 0x5b, 0x92, 0xc3, 0xcd, 0x27, 0xe0, 0xa7, 0x09, 0x1d, 0x3a, 0x14, 0xda,
      0x13, 0x8f, 0x19, 0x92, 0x9b, 0x5f, 0xd9, 0x75, 0x34, 0xe7, 0x45, 0xd8, 0x2d, 0x1c, 0xa9, 0xb0, 0x89, 0x3c,
      0xac, 0x20, 0x58, 0x44, 0x00, 0x00, 0x68, 0x46, 0xcb, 0x02, 0xee, 0xfd, 0x82, 0x22, 0x32, 0x12, 0x89, 0x20,
      0x73, 0xbe, 0x5d, 0x4b, 0xdb, 0x0b, 0xe5, 0x2f, 0x2c, 0xf6, 0x41, 0x1f, 0x27, 0xcb, 0xf1, 0x21, 0x00, 0x20,
      0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9e, 0xcc, 0x14, 0xcc, 0x13, 0xcc, 0x15, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39,
      0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x87,
      0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00, 0x14, 0x00, 0x00, 0x11, 0x61, 0x73, 0x65, 0x63,
      0x75, 0x72, 0x69, 0x74, 0x79, 0x73, 0x69, 0x74, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x17, 0x00, 0x00, 0x00,
      0x23, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x16, 0x00, 0x14, 0x06, 0x01, 0x06, 0x03, 0x05, 0x01, 0x05, 0x03, 0x04,
      0x01, 0x04, 0x03, 0x03, 0x01, 0x03, 0x03, 0x02, 0x01, 0x02, 0x03, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00,
      0x00, 0x00, 0x33, 0x74, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x10, 0x00, 0x1d, 0x00, 0x1b, 0x08, 0x68,
      0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x08, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x33, 0x2e, 0x31, 0x05, 0x68,
      0x32, 0x2d, 0x31, 0x34, 0x02, 0x68, 0x32, 0x75, 0x50, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00,
      0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x18];

#[bench]
fn tree_parsing(bencher: &mut Bencher) {
    let mut peel = PeelIp::new();
    bencher.iter(|| {
        assert!(peel.traverse(PACKET_ETH_IPV4_TCP_TLS, vec![]).is_ok());
    });
    bencher.bytes = PACKET_ETH_IPV4_TCP_TLS.len() as u64;
}
