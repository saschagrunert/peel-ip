#![feature(test)]
extern crate peel_ip;
extern crate test;

use test::Bencher;
use peel_ip::prelude::*;

static PACKET: &'static [u8] = &[0xca, 0x45, 0x01, 0xbb, 0x98, 0x66, 0x5f, 0x0a, 0x44, 0x9d, 0x7f, 0x05, 0x80, 0x18,
                                 0x20, 0x00, 0x0f, 0x1c, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x00, 0x02, 0x2c, 0x2e,
                                 0x63, 0x93, 0xf1, 0x5b];

#[bench]
fn tcp_small_packet(bencher: &mut Bencher) {
    let parser = TcpParser;
    bencher.iter(|| {
        parser.parse(PACKET, None, None, None).unwrap();
    });
    bencher.bytes = PACKET.len() as u64;
}

#[bench]
fn tcp_big_packet(bencher: &mut Bencher) {
    let parser = TcpParser;
    let mut input = Vec::from(PACKET);
    input.extend_from_slice(&[0xff; 1450]);
    bencher.iter(|| {
        parser.parse(&input, None, None, None).unwrap();
    });
    bencher.bytes = input.len() as u64;
}
