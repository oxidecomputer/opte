#![no_std]
// TODO I think Patrick's recent change nullifies this requirement?
#![feature(asm)]
#![cfg_attr(target_os = "macos", feature(asm_sym))]
#![feature(extern_types)]
#![feature(vec_into_raw_parts)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![deny(unreachable_patterns)]
#![deny(unused_must_use)]

#[cfg(any(feature = "std", test))]
#[macro_use]
extern crate std;

#[cfg(all(not(feature = "std"), not(test)))]
#[macro_use]
extern crate alloc;

use core::fmt::{self, Display};
use core::num::ParseIntError;
use core::str::FromStr;

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::boxed::Box;
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::string::{String, ToString};
#[cfg(all(not(feature = "std"), not(test)))]
use alloc::vec::Vec;
#[cfg(any(feature = "std", test))]
use std::boxed::Box;
#[cfg(any(feature = "std", test))]
use std::string::String;

#[cfg(all(not(feature = "std"), not(test)))]
use illumos_ddi_dki as ddi;

// TODO Not sure reexporting makes sense, but felt like trying it on
// for size.
pub use cstr_core::CStr;
pub use cstr_core::CString;

use serde::{Deserialize, Serialize};

pub mod arp;
pub mod checksum;
pub mod dhcp;
#[macro_use]
pub mod ether;
pub mod flow_table;
pub mod geneve;
#[macro_use]
pub mod headers;
pub mod icmp;
pub mod ioctl;
#[macro_use]
pub mod ip4;
#[macro_use]
pub mod ip6;
pub mod layer;
pub mod nat;
pub mod oxide_net;
#[macro_use]
pub mod packet;
pub mod port;
pub mod rule;
pub mod sync;
#[macro_use]
pub mod tcp;
pub mod tcp_state;
#[macro_use]
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
    use ddi::CE_NOTE;

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

#[cfg(all(not(feature = "std"), not(test)))]
pub fn err<S: AsRef<str>>(msg: S)
where
    Vec<u8>: From<S>,
{
    use ddi::CE_WARN;

    unsafe {
        let cstr = CString::new(msg).unwrap();
        ddi::cmn_err(CE_WARN, cstr.as_ptr());
    }
}

#[cfg(any(feature = "std", test))]
pub fn err<S: AsRef<str> + Display>(msg: S) {
    println!("ERROR: {}", msg);
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

impl fmt::Display for ParseErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
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

// ================================================================
// DTrace USDT Provider
//
// Allowing us to use USDT to trace the opte-core SDT probes when
// running in std/test.
// ================================================================
#[usdt::provider]
mod opte_provider {
    use crate::Direction;

    fn port_process_entry(dir: Direction, name: &str) {}
    fn layer_process_return(
        dir: Direction,
        name: &str,
        id: &crate::layer::InnerFlowId,
        res: &str
    ) {}
}

// ================================================================
// Providers
//
// Providers allow opte-core to work in different contexts (in theory)
// by allowing various implementations of core services to be plugged
// into the engine. For example, logging and stats can both be done as
// providers; providing implementations fit for in-kernel execution
// versus unit testing execution. Ideally we could get to a point
// where OPTE could also easily be stood up in userland (not that it
// is explicitly a goal, but only that the flexibility gives us better
// options for testing or unique production situations). However, this
// is the type of abstraction that can quickly grow out of control. If
// it doesn't serve an obvious purpose with at least two obvious
// implmentations, then it probably doesn't need to be a provider.
//
// XXX For now we stash providers here. This should probably move to
// dedicated module.
// ================================================================

/// A logging provider provides the means to log messages to some
/// destination based on the context in which OPTE is running. For
/// example, in a unit test this could map to `println!`. In the
/// illumos kernel it would map to `cmn_err(9F)`.
///
/// Logging levels are provided by [`LogLevel`]. These levels will map
/// to the underlying provider with varying degrees of success.
pub trait LogProvider {
    /// Log a message at the specified level.
    fn log(&self, level: LogLevel, msg: &str);
}

#[derive(Clone, Copy, Debug)]
pub enum LogLevel {
    Note,
    Warn,
    Error,
}

impl Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let level_s = match self {
            Self::Note => "[NOTE]",
            Self::Warn => "[WARN]",
            Self::Error => "[ERROR]",
        };
        write!(f, "{}", level_s)
    }
}

#[cfg(any(feature = "std", test))]
#[derive(Clone, Copy)]
pub struct PrintlnLog {}

#[cfg(any(feature = "std", test))]
impl LogProvider for PrintlnLog {
    fn log(&self, level: LogLevel, msg: &str) {
        println!("{} {}", level, msg);
    }
}

#[cfg(all(not(feature = "std"), not(test)))]
pub struct KernelLog {}

#[cfg(all(not(feature = "std"), not(test)))]
impl LogProvider for KernelLog {
    fn log(&self, level: LogLevel, msg: &str) {
        let cmn_level = match level {
            LogLevel::Note => ddi::CE_NOTE,
            LogLevel::Warn => ddi::CE_WARN,
            LogLevel::Error => ddi::CE_WARN,
        };

        unsafe {
            ddi::cmn_err(
                cmn_level,
                CString::new(msg.to_string()).unwrap().as_ptr(),
            )
        }
    }
}

pub struct ExecCtx {
    pub log: Box<dyn LogProvider>,
}
