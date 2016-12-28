#![feature(test)]
extern crate peel_ip;
extern crate test;

use test::Bencher;
use peel_ip::prelude::*;

static PACKET: &'static [u8] = &[0x00, 0x35, 0xc7, 0xde, 0x00, 0x92, 0xad, 0x1b];

#[bench]
fn udp_small_packet(bencher: &mut Bencher) {
    let parser = UdpParser;
    bencher.iter(|| {
        parser.parse(PACKET, None, None, None).unwrap();
    });
    bencher.bytes = PACKET.len() as u64;
}

#[bench]
fn udp_big_packet(bencher: &mut Bencher) {
    let parser = UdpParser;
    let mut input = Vec::from(PACKET);
    input.extend_from_slice(&[0xff; 1450]);
    bencher.iter(|| {
        parser.parse(&input, None, None, None).unwrap();
    });
    bencher.bytes = input.len() as u64;
}
