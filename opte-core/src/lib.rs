#![no_std]
#![feature(alloc_prelude)]
#![feature(btree_retain)]
#![feature(extern_types)]
#![feature(str_split_once)]
#![feature(vec_into_raw_parts)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#[cfg(any(feature = "std", test))]
#[macro_use]
extern crate std;

#[cfg(all(not(feature = "std"), not(test)))]
extern crate core as std;

#[cfg(all(not(feature = "std"), not(test)))]
#[macro_use]
extern crate alloc;
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::prelude::v1::*;

use std::fmt::{self, Display};
use std::num::ParseIntError;
use std::prelude::v1::*;
use std::str::FromStr;

#[cfg(all(not(feature = "std"), not(test)))]
extern crate illumos_ddi_dki;
#[cfg(all(not(feature = "std"), not(test)))]
use illumos_ddi_dki as ddi;
#[cfg(all(not(feature = "std"), not(test)))]
use illumos_ddi_dki::CE_NOTE;

// TODO Not sure reexporting makes sense, but felt like trying it on
// for size.
pub use cstr_core::CStr;
pub use cstr_core::CString;

use serde::{Deserialize, Serialize};

pub mod arp;
pub mod ether;
pub mod firewallng;
pub mod flow_table;
pub mod headers;
pub mod icmp;
pub mod ioctl;
pub mod ip4;
pub mod ip6;
pub mod layer;
pub mod nat;
pub mod packet;
pub mod port;
pub mod rule;
pub mod sync;
pub mod tcp;
pub mod tcp_state;
pub mod udp;
pub mod vpc;

#[cfg(test)]
mod int_test;

use ip4::IpError;

// TODO For std env we don't have to redefine these, we can pull them
// from some path in std I'm forgetting at the moment.
pub type c_int = i32;
pub type c_schar = i8;
pub type c_uchar = u8;
#[cfg(not(target_arch = "aarch64"))]
pub type c_char = c_schar;
// Note: This is here only to allow running `cargo test` on an
// ARM-based mac.
#[cfg(target_arch = "aarch64")]
pub type c_char = u8;
pub type uintptr_t = usize;

#[cfg(all(not(feature = "std"), not(test)))]
#[no_mangle]
pub static mut opte_debug: i32 = 0;

#[cfg(all(not(feature = "std"), not(test)))]
pub fn dbg<S: AsRef<str>>(msg: S)
where
    Vec<u8>: From<S>,
{
    unsafe {
        if opte_debug != 0 {
            let cstr = CString::new(msg).unwrap();
            ddi::cmn_err(CE_NOTE, cstr.as_ptr());
        }
    }
}

#[cfg(any(feature = "std", test))]
fn dbg<S: AsRef<str> + Display>(msg: S) {
    println!("{}", msg);
}

/// Return value with `bit` set.
///
/// TODO Make generic and take any unsigned integer.
pub const fn bit_on(bit: u8) -> u8 {
    // TODO Uncomment when `const_panic` feature is stable.
    // assert!(bit < 16);
    0x1 << bit
}

// TODO Currently I'm using this for parsing many different things. It
// might be wise to have different parse error types. E.g., one for
// parsing ioctl strings, another for parsing IPv4 strings, for IPv6,
// etc.
//
// TODO This probably doesn't belong in this module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseErr {
    BadAction,
    BadAddrError,
    BadDirectionError,
    BadProtoError,
    BadToken(String),
    InvalidPort,
    IpError(IpError),
    Malformed,
    MalformedInt,
    MalformedPort,
    MissingField,
    UnknownToken(String),
    ValTooLong(String, usize),
}

pub type ParseResult<T> = core::result::Result<T, ParseErr>;

impl From<IpError> for ParseErr {
    fn from(err: IpError) -> Self {
        ParseErr::IpError(err)
    }
}

impl From<ParseIntError> for ParseErr {
    fn from(_err: ParseIntError) -> Self {
        ParseErr::MalformedInt
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Direction {
    In,
    Out,
}

impl FromStr for Direction {
    type Err = ParseErr;

    fn from_str(s: &str) -> ParseResult<Self> {
        match s.to_ascii_lowercase().as_str() {
            "in" => Ok(Direction::In),
            "out" => Ok(Direction::Out),
            _ => Err(ParseErr::BadDirectionError),
        }
    }
}

impl From<Direction> for uintptr_t {
    fn from(dir: Direction) -> Self {
        match dir {
            Direction::In => 0,
            Direction::Out => 1,
        }
    }
}

impl Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let dirstr = match self {
            Direction::In => "IN",
            Direction::Out => "OUT",
        };

        write!(f, "{}", dirstr)
    }
}
