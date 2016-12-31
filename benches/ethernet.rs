#![feature(test)]
extern crate peel_ip;
extern crate test;

use test::Bencher;
use peel_ip::prelude::*;

static PACKET: &'static [u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 8, 0];

#[bench]
fn ethernet_small_packet(bencher: &mut Bencher) {
    let mut parser = EthernetParser;
    bencher.iter(|| {
        parser.parse(PACKET, None).unwrap();
    });
    bencher.bytes = PACKET.len() as u64;
}

#[bench]
fn ethernet_big_packet(bencher: &mut Bencher) {
    let mut parser = EthernetParser;
    let mut input = Vec::from(PACKET);
    input.extend_from_slice(&[0xff; 1450]);
    bencher.iter(|| {
        parser.parse(&input, None).unwrap();
    });
    bencher.bytes = input.len() as u64;
}
