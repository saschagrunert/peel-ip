#![feature(test)]
extern crate peel_ip;
extern crate test;

use test::Bencher;
use peel_ip::prelude::*;

static PACKET: &'static [u8] = &[0x60, 0x00, 0x00, 0x00, 0x00, 0x2f, 0x06, 0x40, 0x3f, 0xfe, 0x05, 0x07, 0x00, 0x00,
                                 0x00, 0x01, 0x02, 0x00, 0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0x3f, 0xfe, 0x05, 0x01,
                                 0x04, 0x10, 0x00, 0x00, 0x02, 0xc0, 0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e];

#[bench]
fn ipv6_small_packet(bencher: &mut Bencher) {
    let mut parser = Ipv6Parser;
    bencher.iter(|| {
        parser.parse(PACKET, None).unwrap();
    });
    bencher.bytes = PACKET.len() as u64;
}

#[bench]
fn ipv6_big_packet(bencher: &mut Bencher) {
    let mut parser = Ipv6Parser;
    let mut input = Vec::from(PACKET);
    input.extend_from_slice(&[0xff; 1450]);
    bencher.iter(|| {
        parser.parse(&input, None).unwrap();
    });
    bencher.bytes = input.len() as u64;
}
