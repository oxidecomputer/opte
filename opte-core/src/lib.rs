#![no_std]
// XXX This allows me to run `cargo +nightly test` on a macOS system.
// I'd prefer to run everything with
// `--target=x86_64-unknown-illumos`, but the usdt crate doesn't
// compile when I do that thanks to `asm!` shenanigans -- I don't have
// time for that yak at this moment.
#![cfg_attr(target_os = "macos", feature(asm_sym))]
#![feature(extern_types)]
#![feature(vec_into_raw_parts)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![deny(unreachable_patterns)]
#![deny(unused_must_use)]

use core::fmt::{self, Display};

// NOTE: Things get weird if you move the extern crate into cfg_if!.
#[cfg(any(feature = "std", test))]
#[macro_use]
extern crate std;

#[cfg(all(not(feature = "std"), not(test)))]
#[macro_use]
extern crate alloc;

#[macro_use]
extern crate cfg_if;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::boxed::Box;
        use alloc::string::ToString;
    } else {
        use std::boxed::Box;
    }
}

// TODO Not sure reexporting makes sense, but felt like trying it on
// for size.
pub use cstr_core::CStr;
pub use cstr_core::CString;

use serde::{Deserialize, Serialize};

cfg_if! {
    if #[cfg(any(feature = "engine", test))] {
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
        pub mod time;
        #[macro_use]
        pub mod udp;
        pub mod vpc;
    }
}

#[cfg(test)]
mod int_test;

#[cfg(any(feature = "api", test))]
pub mod api;

#[cfg(any(feature = "engine", test))]
use ip4::IpError;

cfg_if! {
    if #[cfg(all(not(feature = "std"), feature = "engine"))] {
        use alloc::vec::Vec;
        use illumos_ddi_dki as ddi;

        #[no_mangle]
        pub static mut opte_debug: i32 = 0;

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

    } else {
        fn dbg<S: AsRef<str> + Display>(msg: S) {
            println!("{}", msg);
        }

        pub fn err<S: AsRef<str> + Display>(msg: S) {
            println!("ERROR: {}", msg);
        }
    }
}

/// Return value with `bit` set.
///
/// TODO Make generic and take any unsigned integer.
pub const fn bit_on(bit: u8) -> u8 {
    // TODO Uncomment when `const_panic` feature is stable.
    // assert!(bit < 16);
    0x1 << bit
}

cfg_if! {
    if #[cfg(any(feature = "engine", test))] {

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
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Direction {
    In,
    Out,
}

#[cfg(feature = "engine")]
impl Direction {
    pub fn cstr_raw(&self) -> *const illumos_sys_hdrs::c_char {
        match self {
            Self::In => b"in\0".as_ptr() as *const illumos_sys_hdrs::c_char,
            Self::Out => b"out\0".as_ptr() as *const illumos_sys_hdrs::c_char,
        }
    }
}

#[cfg(any(feature = "engine", test))]
impl core::str::FromStr for Direction {
    type Err = ParseErr;

    fn from_str(s: &str) -> ParseResult<Self> {
        match s.to_ascii_lowercase().as_str() {
            "in" => Ok(Direction::In),
            "out" => Ok(Direction::Out),
            _ => Err(ParseErr::BadDirectionError),
        }
    }
}

#[cfg(feature = "engine")]
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

// ================================================================
// DTrace USDT Provider
//
// Allowing us to use USDT to trace the opte-core SDT probes when
// running in std/test.
// ================================================================
#[cfg(feature = "usdt")]
#[usdt::provider]
mod opte_provider {
    use crate::Direction;

    fn flow__expired(port: &str, ft_name: &str, flow: &str) {}
    fn gen__desc__fail(
        port: &str,
        layer: &str,
        dir: Direction,
        flow: &str,
        err: &str,
    ) {
    }
    fn gen__ht__fail(
        port: &str,
        layer: &str,
        dir: Direction,
        flow: &str,
        err: &str,
    ) {
    }
    fn ht__run(
        port: &str,
        loc: &str,
        dir: Direction,
        before: &str,
        after: &str,
    ) {
    }
    fn layer__process__entry(
        dir: Direction,
        port: &str,
        name: &str,
        flow: &str,
    ) {
    }
    fn layer__process__return(
        dir: Direction,
        port: &str,
        name: &str,
        flow: &str,
        res: &str,
    ) {
    }
    fn port__process__entry(
        dir: Direction,
        name: &str,
        ifid: &str,
        pkt: &illumos_sys_hdrs::uintptr_t,
    ) {
    }
    pub fn port__process__return(
        dir: Direction,
        name: &str,
        ifid: &str,
        pkt: &illumos_sys_hdrs::uintptr_t,
        res: &str,
    ) {
    }
    fn rule__deny(port: &str, layer: &str, dir: Direction, flow: &str) {}
    fn rule__match(
        port: &str,
        layer: &str,
        dir: Direction,
        flow: &str,
        action: &str,
    ) {
    }
    fn rule__no__match(port: &str, layer: &str, dir: Direction, flow: &str) {}
    fn tcp__flow__state(
        port: &str,
        flow: &str,
        curr_state: &str,
        new_state: &str,
    ) {
    }
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

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::io::Write;

    use pcap_parser::pcap::LegacyPcapBlock;
    use pcap_parser::{Linktype, PcapHeader, ToVec};

    use crate::packet::{Packet, PacketRead, PacketReader, Parsed};

    pub struct PcapBuilder {
        file: File,
    }

    impl PcapBuilder {
        pub fn new(path: &str) -> Self {
            let mut file = File::create(path).unwrap();

            let mut hdr = PcapHeader {
                magic_number: 0xa1b2c3d4,
                version_major: 2,
                version_minor: 4,
                thiszone: 0,
                sigfigs: 0,
                snaplen: 1500,
                network: Linktype::ETHERNET,
            };

            file.write_all(&hdr.to_vec().unwrap()).unwrap();

            Self { file }
        }

        pub fn add_pkt(&mut self, pkt: &Packet<Parsed>) {
            let pkt_bytes = PacketReader::new(&pkt, ()).copy_remaining();
            let mut block = LegacyPcapBlock {
                ts_sec: 7777,
                ts_usec: 7777,
                caplen: pkt_bytes.len() as u32,
                origlen: pkt_bytes.len() as u32,
                data: &pkt_bytes,
            };

            self.file.write_all(&block.to_vec().unwrap()).unwrap();
        }
    }
}
