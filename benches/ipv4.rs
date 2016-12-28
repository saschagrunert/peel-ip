#![feature(test)]
extern crate peel_ip;
extern crate test;

use test::Bencher;
use peel_ip::prelude::*;

static PACKET: &'static [u8] = &[0x45, 0x00, 0x01, 0xa5, 0xd6, 0x63, 0x40, 0x00, 0x3f, 0x06, 0x9b, 0xfc, 0xc0, 0xa8,
                                 0x01, 0x0a, 0xad, 0xfc, 0x58, 0x44];

#[bench]
fn ipv4_small_packet(bencher: &mut Bencher) {
    let parser = Ipv4Parser;
    bencher.iter(|| {
        parser.parse(PACKET, None, None, None).unwrap();
    });
    bencher.bytes = PACKET.len() as u64;
}

#[bench]
fn ipv4_big_packet(bencher: &mut Bencher) {
    let parser = Ipv4Parser;
    let mut input = Vec::from(PACKET);
    input.extend_from_slice(&[0xff; 1450]);
    bencher.iter(|| {
        parser.parse(&input, None, None, None).unwrap();
    });
    bencher.bytes = input.len() as u64;
}
