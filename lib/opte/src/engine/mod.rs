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
pub mod ip;
pub mod layer;
pub mod nat;
#[macro_use]
pub mod packet;
pub mod parse;
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

use crate::ddi::mblk::MsgBlk;
use checksum::Checksum;
use ingot::tcp::TcpRef;
use ingot::types::IntoBufPointer;
use ingot::types::Parsed as IngotParsed;
use ingot::types::Read;
pub use opte_api::Direction;
use packet::FullParsed;
use packet::OpteMeta;
use packet::Packet;
use packet::Pullup;
use parse::ValidNoEncap;
use rule::CompiledTransform;
use zerocopy::ByteSlice;
use zerocopy::ByteSliceMut;

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
                {
                let out_str = format!(concat!($s, "\0"));
                unsafe {
                    // Unwrap safety: we just concat'd a NUL.
                    let cstr = ::core::ffi::CStr::from_bytes_with_nul(out_str.as_bytes()).unwrap();
                    ::illumos_sys_hdrs::cmn_err(::illumos_sys_hdrs::CE_WARN, cstr.as_ptr());
                }
                }
            };
            ($s:tt, $($arg:tt)*) => {
                {
                let out_str = format!(concat!($s, "\0"), $($arg)*);
                unsafe {
                    // Unwrap safety: we just concat'd a NUL.
                    let cstr = ::core::ffi::CStr::from_bytes_with_nul(out_str.as_bytes()).unwrap();
                    ::illumos_sys_hdrs::cmn_err(::illumos_sys_hdrs::CE_WARN, cstr.as_ptr());
                }
                }
            };
        }
    }
}

pub use dbg_macro as dbg;
pub use err_macro as err;

use crate::engine::flow_table::FlowTable;
use crate::engine::packet::InnerFlowId;
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
///    definitions; each made up of its unique set of [`rule::Rule`] &
///    [`rule::Action`] pairings. Furthermore, the actions themselves may
///    be built atop generic OPTE actions or may be provided in whole by
///    the network implementation.
///
/// 2. It uses this trait to provide hooks into the parsing of packets
///    as well as single packet processing (non-flow processing).
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
    fn handle_pkt<'a, T: Read + Pullup + 'a>(
        &self,
        dir: Direction,
        pkt: &mut Packet<FullParsed<T>>,
        uft_in: &FlowTable<UftEntry<InnerFlowId>>,
        uft_out: &FlowTable<UftEntry<InnerFlowId>>,
    ) -> Result<HdlPktAction, HdlPktError>
    where
        T::Chunk: ByteSliceMut + IntoBufPointer<'a>;

    /// Return the parser for this network implementation.
    fn parser(&self) -> Self::Parser;
}

/// A packet parser for the network implementation.
///
/// This provides parsing for inbound/outbound packets for a given
/// [`NetworkImpl`].
pub trait NetworkParser {
    type InMeta<T: ByteSliceMut>: LightweightMeta<T>;
    type OutMeta<T: ByteSliceMut>: LightweightMeta<T>;

    /// Parse an outbound packet.
    ///
    /// An outbound packet is one travelling from the [`port::Port`]
    /// client to the network.
    fn parse_outbound<'a, T: Read + 'a>(
        &self,
        rdr: T,
    ) -> Result<IngotParsed<Self::OutMeta<T::Chunk>, T>, ParseError>
    where
        T::Chunk: IntoBufPointer<'a> + ByteSliceMut;

    /// Parse an inbound packet.
    ///
    /// An inbound packet is one traveling from the network to the
    /// [`port::Port`] client.
    fn parse_inbound<'a, T: Read + 'a>(
        &self,
        rdr: T,
    ) -> Result<IngotParsed<Self::InMeta<T::Chunk>, T>, ParseError>
    where
        T::Chunk: IntoBufPointer<'a> + ByteSliceMut;
}

/// Header formats which allow a flow ID to be read out, and which can be converted
/// into the shared `OpteMeta` format.
pub trait LightweightMeta<T: ByteSlice>: Into<OpteMeta<T>> {
    /// Runs a compiled fastpath action against the target metadata.
    fn run_compiled_transform(&mut self, transform: &CompiledTransform)
    where
        T: ByteSliceMut;

    /// Derive the checksum for the packet body from inner headers.
    fn compute_body_csum(&self) -> Option<Checksum>;

    // This is a dedicated fn since `where for<'a> &'a Self: Into<InnerFlowId>`
    // had *awful* ergonomics around that bound's propagation.
    /// Return the flow ID (5-tuple, or other composite key) which
    /// identifies this packet's parent flow.
    fn flow(&self) -> InnerFlowId;

    /// Returns the number of bytes occupied by the packet's outer encapsulation.
    fn encap_len(&self) -> u16;

    /// Recalculate checksums within inner headers, derived from a pre-computed `body_csum`.
    fn update_inner_checksums(&mut self, body_csum: Checksum);

    /// Provide a view of internal TCP state.
    fn inner_tcp(&self) -> Option<&impl TcpRef<T>>;

    /// Determines whether headers have consistent lengths/mandatory fields set.
    fn validate(&self, pkt_len: usize) -> Result<(), ParseError>;
}

/// A generic ULP parser, useful for testing inside of the opte crate
/// itself.
pub struct GenericUlp {}

impl NetworkParser for GenericUlp {
    type InMeta<T: ByteSliceMut> = ValidNoEncap<T>;
    type OutMeta<T: ByteSliceMut> = ValidNoEncap<T>;

    fn parse_inbound<'a, T: Read + 'a>(
        &self,
        rdr: T,
    ) -> Result<IngotParsed<Self::InMeta<T::Chunk>, T>, ParseError>
    where
        T::Chunk: IntoBufPointer<'a> + ByteSliceMut,
    {
        Ok(ValidNoEncap::parse_read(rdr)?)
    }

    fn parse_outbound<'a, T: Read + 'a>(
        &self,
        rdr: T,
    ) -> Result<IngotParsed<Self::OutMeta<T::Chunk>, T>, ParseError>
    where
        T::Chunk: IntoBufPointer<'a> + ByteSliceMut,
    {
        Ok(ValidNoEncap::parse_read(rdr)?)
    }
}
