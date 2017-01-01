#![feature(test)]
extern crate peel_ip;
extern crate test;

use test::Bencher;
use peel_ip::prelude::*;

static PACKET: &'static [u8] = &[0x80, 0x00, 0x41, 0x5c, 0x02, 0x00, 0x0a, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
                                 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74,
                                 0x75, 0x76, 0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69];

#[bench]
fn icmpv6_small_packet(bencher: &mut Bencher) {
    let mut parser = Icmpv6Parser;
    bencher.iter(|| {
        parser.parse(PACKET, None, None).unwrap();
    });
    bencher.bytes = PACKET.len() as u64;
}

#[bench]
fn icmpv6_big_packet(bencher: &mut Bencher) {
    let mut parser = Icmpv6Parser;
    let mut input = Vec::from(PACKET);
    input.extend_from_slice(&[0xff; 1450]);
    bencher.iter(|| {
        parser.parse(&input, None, None).unwrap();
    });
    bencher.bytes = input.len() as u64;
}
