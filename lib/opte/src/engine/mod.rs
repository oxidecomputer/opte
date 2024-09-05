// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! The engine in OPTE.
//!
//! All code under this namespace is guarded by the `engine` feature flag.
pub mod arp;
pub mod checksum;
pub mod dhcp;
pub mod dhcpv6;
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
pub mod predicate;
#[cfg(any(feature = "std", test))]
pub mod print;
pub mod rule;
pub mod snat;
#[macro_use]
pub mod tcp;
pub mod tcp_state;
#[macro_use]
pub mod udp;

pub mod ingot_packet;

use alloc::string::String;
use core::fmt;
use core::num::ParseIntError;
use ingot::types::Parsed as IngotParsed;
use ingot::types::Read;
use ingot_packet::MsgBlk;
use ingot_packet::NoEncap;
use ingot_packet::OpteMeta;
use ingot_packet::OpteParsed;
use ingot_packet::Packet2;
use ingot_packet::PacketHeaders;
use ingot_packet::Parsed2;
use ingot_packet::ParsedMblk;
use ip4::IpError;
pub use opte_api::Direction;

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
    if #[cfg(feature = "std")] {
        #[macro_export]
        macro_rules! dbg_macro {
            ($s:tt) => {
                println!($s);
            };
            ($s:tt, $($arg:tt)*) => {
                println!($s, $($arg)*);
            };
        }

        #[macro_export]
        macro_rules! err_macro {
            ($s:tt) => {
                println!(concat!("ERROR: ", $s));
            };
            ($s:tt, $($arg:tt)*) => {
                println!(concat!("ERROR: ", $s), $($arg)*);
            };
        }
    } else if #[cfg(feature = "kernel")] {
        /// When set to 1 enables debug messages.
        #[no_mangle]
        pub static mut opte_debug: i32 = 0;

        #[macro_export]
        macro_rules! dbg_macro {
            ($s:tt) => {
                unsafe {
                    if ::opte::engine::opte_debug != 0 {
                        let out_str = format!(concat!($s, "\0"));
                        // Unwrap safety: we just concat'd a NUL.
                        let cstr = ::core::ffi::CStr::from_bytes_with_nul(out_str.as_bytes()).unwrap();
                        ::illumos_sys_hdrs::cmn_err(::illumos_sys_hdrs::CE_NOTE, cstr.as_ptr());
                    }
                }
            };
            ($s:tt, $($arg:tt)*) => {
                unsafe {
                    if ::opte::engine::opte_debug != 0 {
                        let out_str = format!(concat!($s, "\0"), $($arg)*);
                        // Unwrap safety: we just concat'd a NUL.
                        let cstr = ::core::ffi::CStr::from_bytes_with_nul(out_str.as_bytes()).unwrap();
                        ::illumos_sys_hdrs::cmn_err(::illumos_sys_hdrs::CE_NOTE, cstr.as_ptr());
                    }
                }
            };
        }

        #[macro_export]
        macro_rules! err_macro {
            ($s:tt) => {
                unsafe {
                    let out_str = format!(concat!($s, "\0"));
                    // Unwrap safety: we just concat'd a NUL.
                    let cstr = ::core::ffi::CStr::from_bytes_with_nul(out_str.as_bytes()).unwrap();
                    ::illumos_sys_hdrs::cmn_err(::illumos_sys_hdrs::CE_WARN, cstr.as_ptr());
                }
            };
            ($s:tt, $($arg:tt)*) => {
                unsafe {
                    let out_str = format!(concat!($s, "\0"), $($arg)*);
                    // Unwrap safety: we just concat'd a NUL.
                    let cstr = ::core::ffi::CStr::from_bytes_with_nul(out_str.as_bytes()).unwrap();
                    ::illumos_sys_hdrs::cmn_err(::illumos_sys_hdrs::CE_WARN, cstr.as_ptr());
                }
            };
        }
    }
}

pub use dbg_macro as dbg;
pub use err_macro as err;

use crate::engine::flow_table::FlowTable;
use crate::engine::packet::Initialized;
use crate::engine::packet::InnerFlowId;
use crate::engine::packet::Packet;
use crate::engine::packet::ParseError;
use crate::engine::port::UftEntry;

/// The action to take for a single packet, based on the processing of
/// the [`NetworkImpl::handle_pkt()`] callback.
pub enum HdlPktAction {
    /// Allow the packet to pass through the port.
    ///
    /// The handler may have modified the packet.
    Allow,

    /// Deny the packet from passing through the port.
    Deny,

    /// Deliver a response packet in the opposite direction of the
    /// input packet.
    ///
    /// The input packet is dropped.
    Hairpin(MsgBlk),
}

/// Some type of problem occurred during [`NetworkImpl::handle_pkt()`]
/// processing.
pub struct HdlPktError(pub &'static str);

/// An implementation of a particular type of network.
///
/// OPTE is a generalized engine for processing and transforming
/// packets in a flow-based manner. It does not dictate the specific
/// details of the expected types of packets, that is left to the
/// network implementation built atop of OPTE. The network
/// implementation does this is two ways.
///
/// 1. It provides its own unique stack of [`layer::Layer`]
/// definitions; each made up of its unique set of [`rule::Rule`] &
/// [`rule::Action`] pairings. Furthermore, the actions themselves may
/// be built atop generic OPTE actions or may be provided in whole by
/// the network implementation.
///
/// 2. It uses this trait to provide hooks into the parsing of packets
/// as well as single packet processing (non-flow processing).
///
/// OPTE itself provides a general structure for parsing; limiting the
/// possible parse graph to that of a typical L2 + L3 + L4 packet,
/// with optional encapsulation. The network implementation provides a
/// specific parser to fill out this general template, as only the
/// implementation knows the shape of the traffic it expects to see.
///
/// The network implementation may also provide additional
/// single-packet processing. This allows a rule to specify the
/// handling of the packet at an individual level, instead of
/// treating it as a flow. This is useful for packets that do not
/// easily map to the flow model.
pub trait NetworkImpl {
    /// The packet parser for this network implementation.
    type Parser: NetworkParser;

    /// Handle an individual packet on its own, separate from the flow
    /// processing. This callback is a general mechanism for handling
    /// packets which don't fit neatly into flow processing, and do
    /// not require maximal performance. For this reason, it allows
    /// deeper packet inspection and is not bound to the more limited
    /// predicate matching system.
    ///
    /// This is called as part of rule processing when a matched rule
    /// has an action of [`rule::Action::HandlePacket`]. Upon entering
    /// this callback, there is no return to rule processing. It's the
    /// sole discretion of this callback to determine the response to
    /// take in regards to the input packet. That response is dictated
    /// by the [`HdlPktAction`] value.
    ///
    /// This callback is given access to both the inbound and outbound
    /// UFT tables. This can be useful for handling certain types of
    /// traffic, such as ICMP DU, where you may want to match parts of
    /// the packet body with flow state.
    ///
    /// # Errors
    ///
    /// As this is a general mechanism, the handler may fail for a
    /// myriad of reasons. The error returned is for informational
    /// purposes, rather than having any obvious direct action to take
    /// in response.
    fn handle_pkt<T: Read>(
        &self,
        dir: Direction,
        pkt: &mut Packet2<Parsed2<T>>,
        uft_in: &FlowTable<UftEntry<InnerFlowId>>,
        uft_out: &FlowTable<UftEntry<InnerFlowId>>,
    ) -> Result<HdlPktAction, HdlPktError>
    where
        T: Read;

    /// Return the parser for this network implementation.
    fn parser(&self) -> Self::Parser;
}

/// A packet parser for the network implementation.
///
/// This provides parsing for inbound/outbound packets for a given
/// [`NetworkImpl`].
pub trait NetworkParser {
    /// Parse an outbound packet.
    ///
    /// An outbound packet is one travelling from the [`port::Port`]
    /// client to the network.
    fn parse_outbound<T: Read>(
        &self,
        rdr: T,
    ) -> Result<OpteParsed<T>, ParseError>;

    /// Parse an inbound packet.
    ///
    /// An inbound packet is one traveling from the network to the
    /// [`port::Port`] client.
    fn parse_inbound<T: Read>(
        &self,
        rdr: T,
    ) -> Result<OpteParsed<T>, ParseError>;
}

/// A generic ULP parser, useful for testing inside of the opte crate
/// itself.
pub struct GenericUlp {}

impl GenericUlp {
    /// Parse a generic L2 + L3 + L4 packet, storing the headers in
    /// the inner position.
    fn parse_ulp<T: Read>(&self, rdr: T) -> Result<OpteParsed<T>, ParseError> {
        let v = NoEncap::parse_read(rdr)?;
        Ok(OpteMeta::convert_ingot(v))
    }
}

impl NetworkParser for GenericUlp {
    fn parse_inbound<T: Read>(
        &self,
        rdr: T,
    ) -> Result<OpteParsed<T>, ParseError> {
        self.parse_ulp(rdr)
    }

    fn parse_outbound<T: Read>(
        &self,
        rdr: T,
    ) -> Result<OpteParsed<T>, ParseError> {
        self.parse_ulp(rdr)
    }
}
