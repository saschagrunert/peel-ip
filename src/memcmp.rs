//! Custom memcmp and related nom macro
use nom::CompareResult;

/// Memory compare trait
pub trait Memcmp {
    /// Compares an `&[u8]` to another one
    fn memcmp(self: &Self, b: &Self) -> bool;

    /// Compare with the nom `CompareResult`
    fn nom_compare(&self, t: &[u8]) -> CompareResult;
}

impl Memcmp for [u8] {
    #[cfg_attr(feature = "cargo-clippy", allow(inline_always))]
    #[inline(always)]
    fn memcmp(&self, b: &[u8]) -> bool {
        extern "C" {
            fn memcmp(s1: *const i8, s2: *const i8, n: usize) -> i32;
        }
        let len = b.len();
        self.len() == len &&
        unsafe {
            let pa = b.as_ptr() as *const i8;
            let pb = self.as_ptr() as *const i8;
            match len {
                1 => *(pa as *const u8) == *(pb as *const u8),
                2 => *(pa as *const u16) == *(pb as *const u16),
                3 => {
                    *(pa as *const u16) == *(pb as *const u16) &&
                    *(pa.offset(2) as *const u8) == *(pb.offset(2) as *const u8)
                }
                4 => *(pa as *const u32) == *(pb as *const u32),
                5 => {
                    *(pa as *const u32) == *(pb as *const u32) &&
                    *(pa.offset(4) as *const u8) == *(pb.offset(4) as *const u8)
                }
                6 => {
                    *(pa as *const u32) == *(pb as *const u32) &&
                    *(pa.offset(4) as *const u16) == *(pb.offset(4) as *const u16)
                }
                7 => {
                    *(pa as *const u32) == *(pb as *const u32) &&
                    *(pa.offset(4) as *const u16) == *(pb.offset(4) as *const u16) &&
                    *(pa.offset(6) as *const u8) == *(pb.offset(6) as *const u8)
                }
                8 => *(pa as *const u64) == *(pb as *const u64),
                9 => {
                    *(pa as *const u64) == *(pb as *const u64) &&
                    *(pa.offset(8) as *const u8) == *(pb.offset(8) as *const u8)
                }
                10 => {
                    *(pa as *const u64) == *(pb as *const u64) &&
                    *(pa.offset(8) as *const u16) == *(pb.offset(8) as *const u16)
                }
                11 => {
                    *(pa as *const u64) == *(pb as *const u64) &&
                    *(pa.offset(8) as *const u16) == *(pb.offset(8) as *const u16) &&
                    *(pa.offset(10) as *const u8) == *(pb.offset(10) as *const u8)
                }
                12 => {
                    *(pa as *const u64) == *(pb as *const u64) &&
                    *(pa.offset(8) as *const u32) == *(pb.offset(8) as *const u32)
                }
                13 => {
                    *(pa as *const u64) == *(pb as *const u64) &&
                    *(pa.offset(8) as *const u32) == *(pb.offset(8) as *const u32) &&
                    *(pa.offset(12) as *const u8) == *(pb.offset(12) as *const u8)
                }
                14 => {
                    *(pa as *const u64) == *(pb as *const u64) &&
                    *(pa.offset(8) as *const u32) == *(pb.offset(8) as *const u32) &&
                    *(pa.offset(12) as *const u16) == *(pb.offset(12) as *const u16)
                }
                15 => {
                    *(pa as *const u64) == *(pb as *const u64) &&
                    *(pa.offset(8) as *const u32) == *(pb.offset(8) as *const u32) &&
                    *(pa.offset(12) as *const u16) == *(pb.offset(12) as *const u16) &&
                    *(pa.offset(14) as *const u8) == *(pb.offset(14) as *const u8)
                }
                16 => {
                    *(pa as *const u64) == *(pb as *const u64) &&
                    *(pa.offset(8) as *const u64) == *(pb.offset(8) as *const u64)
                }
                _ => memcmp(pa, pb, len) == 0,
            }
        }
    }

    fn nom_compare(&self, t: &[u8]) -> CompareResult {
        let len = self.len();
        let blen = t.len();
        let m = if len < blen { len } else { blen };
        let reduced = &self[..m];
        let b = &t[..m];

        if !reduced.memcmp(b) {
            CompareResult::Error
        } else if m < blen {
            CompareResult::Incomplete
        } else {
            CompareResult::Ok
        }
    }
}

#[macro_export]
macro_rules! tag_fast (
    ($i:expr, $tag: expr) => ({
        use nom::{CompareResult, InputLength, Slice, IResult, Needed, ErrorKind};
        use $crate::memcmp::Memcmp;
        let res: IResult<_,_> = match ($i).nom_compare($tag.as_bytes()) {
            CompareResult::Ok => {
                let blen = $tag.input_len();
                IResult::Done($i.slice(blen..), $i.slice(..blen))
            },
            CompareResult::Incomplete => {
                IResult::Incomplete(Needed::Size($tag.input_len()))
            },
            CompareResult::Error => {
                IResult::Error(error_position!(ErrorKind::Tag, $i))
            }
        };
        res
    });
);
