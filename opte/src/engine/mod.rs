// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! The engine in OPTE.
//!
//! All code under this namespace is guarded by the `engine` feature flag.
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
#[macro_use]
pub mod packet;
pub mod port;
pub mod rule;
pub mod snat;
pub mod sync;
#[macro_use]
pub mod tcp;
pub mod tcp_state;
pub mod time;
#[macro_use]
pub mod udp;

pub use crate::api::Direction;
use core::fmt::{self, Display};
use ip4::IpError;

impl Direction {
    pub fn cstr_raw(&self) -> *const illumos_sys_hdrs::c_char {
        match self {
            Self::In => b"in\0".as_ptr() as *const illumos_sys_hdrs::c_char,
            Self::Out => b"out\0".as_ptr() as *const illumos_sys_hdrs::c_char,
        }
    }
}

impl From<Direction> for illumos_sys_hdrs::uintptr_t {
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

use core::num::ParseIntError;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::string::String;
    } else {
        use std::string::String;
    }
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
    Other(String),
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

impl From<String> for ParseErr {
    fn from(err: String) -> Self {
        ParseErr::Other(err)
    }
}

/// When set to 1 we will panic in some situations instead of just
/// flagging in error. This can be useful for debugging certain
/// scenarios in development.
#[no_mangle]
pub static mut opte_panic_debug: i32 = 0;

cfg_if! {
    if #[cfg(not(feature = "std"))] {
        use alloc::vec::Vec;
        use illumos_ddi_dki as ddi;

        /// When set to 1 enables debug messages.
        #[no_mangle]
        pub static mut opte_debug: i32 = 0;

        pub fn dbg<S: AsRef<str>>(msg: S)
        where
            Vec<u8>: From<S>,
        {
            use ddi::CE_NOTE;

            unsafe {
                if opte_debug != 0 {
                    let cstr = cstr_core::CString::new(msg).unwrap();
                    ddi::cmn_err(CE_NOTE, cstr.as_ptr());
                }
            }
        }

        pub fn err<S: AsRef<str>>(msg: S)
        where
            Vec<u8>: From<S>,
        {
            use ddi::CE_WARN;

            unsafe {
                let cstr = cstr_core::CString::new(msg).unwrap();
                ddi::cmn_err(CE_WARN, cstr.as_ptr());
            }
        }

    } else {
        fn dbg<S: AsRef<str> + Display>(msg: S) {
            println!("{}", msg);
        }

        pub fn err<S: AsRef<str> + Display>(msg: S) {
            println!("ERROR: {}", msg);
        }
    }
}
