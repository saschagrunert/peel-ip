#[macro_use]
extern crate peel_ip;
use peel_ip::memcmp::Memcmp;

#[macro_use]
extern crate nom;
use nom::{IResult, ErrorKind, Needed, Err};

#[test]
fn memcmp_success_1_to_20() {
    let mut vec = vec![];
    for i in 1..20 {
        vec.push(i);
        assert!(vec.memcmp(&vec));
    }
}

#[test]
fn memcmp_failure_1_to_20() {
    let mut vec_1 = vec![];
    let mut vec_2 = vec![];
    for i in 1..20 {
        vec_1.push(i);
        vec_2.push(0);
        assert!(!vec_1.memcmp(&vec_2));
    }
}

#[test]
fn memcmp_success_nom() {
    named!(parse<&[u8]>,
        do_parse!(
            tag: tag_fast!("TEST") >>
            (tag)
        )
    );

    parse(b"TEST TEST TEST").unwrap();
    let input = b"FAILURE";
    assert_eq!(parse(input), IResult::Error(Err::Position(ErrorKind::Tag, &input[..])));
    assert_eq!(parse(b"T"), IResult::Incomplete(Needed::Size(4)));
}
