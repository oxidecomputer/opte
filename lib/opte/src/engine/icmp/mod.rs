// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Internet Control Message Protocol (ICMP) shared data structures.

pub mod v4;
pub mod v6;

use super::checksum::Checksum as OpteCsum;
use super::checksum::HeaderChecksum;
use super::headers::HeaderActionError;
use super::packet::PacketReadMut;
use super::packet::ReadErr;
use crate::d_error::DError;
use crate::engine::headers::HeaderActionModify;
use crate::engine::headers::UlpMetaModify;
use crate::engine::predicate::DataPredicate;
use crate::engine::predicate::EtherAddrMatch;
use crate::engine::predicate::IpProtoMatch;
use crate::engine::predicate::Predicate;
use crate::engine::rule::AllowOrDeny;
use crate::engine::rule::GenErr;
use crate::engine::rule::GenPacketResult;
use crate::engine::rule::HairpinAction;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::Display;
use ingot::types::primitives::u16be;
use ingot::Ingot;
pub use opte_api::ip::Protocol;
use serde::Deserialize;
use serde::Serialize;
use smoltcp::phy::Checksum;
use smoltcp::phy::ChecksumCapabilities as Csum;
use zerocopy::ByteSlice;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;
use zerocopy::Ref;
use zerocopy::Unaligned;

/// Shared methods for handling ICMPv4/v6 Echo fields.
pub trait QueryEcho {
    /// Extract an ID from the body of an ICMP(v6) packet.
    ///
    /// This method should return `None` for any non-echo packets.
    fn echo_id(&self) -> Option<u16>;
}

/// Internal structure of an ICMP(v6) Echo(Reply)'s rest_of_header.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Ingot)]
#[ingot(impl_default)]
pub struct IcmpEcho {
    pub id: u16be,
    pub sequence: u16be,
}
