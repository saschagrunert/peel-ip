#![feature(test)]
extern crate peel_ip;
extern crate test;

use test::Bencher;
use peel_ip::prelude::*;

static PACKET: &'static [u8] = &[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x00, 0x07, 0x0d, 0xaf, 0xf4, 0x54,
                                 0x18, 0xa6, 0xac, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0xa6, 0xad, 0x9f];

#[bench]
fn arp_small_packet(bencher: &mut Bencher) {
    let mut parser = ArpParser;
    bencher.iter(|| {
        parser.parse(PACKET, None).unwrap();
    });
    bencher.bytes = PACKET.len() as u64;
}

#[bench]
fn arp_big_packet(bencher: &mut Bencher) {
    let mut parser = ArpParser;
    let mut input = Vec::from(PACKET);
    input.extend_from_slice(&[0xff; 1450]);
    bencher.iter(|| {
        parser.parse(&input, None).unwrap();
    });
    bencher.bytes = input.len() as u64;
}
