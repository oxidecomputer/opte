// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Core implementation of DHCPv6 protocol.
//!
//! RFC 8415 is the main RFC describing the protocol and its options. Other
//! useful RFCs are 3646, which describes how DNS servers are transmitted in
//! DHCPv6, and 4075, which covers SNTP servers.
//!
//! DHCPv6 is conceptually simple: clients request some configuration data from
//! servers. The devil is in the details though, and there are a lot of them for
//! DHCPv6.
//!
//! Transport
//! ---------
//!
//! DHCPv6 runs over UDP. Servers listen on well-known multicast addresses,
//! `ff02::1:2` and `ff05::1:3`, at port 547. Clients send messages from port
//! 546.
//!
//! Message types
//! -------------
//!
//! There are a lot of message types in DHCPv6, which can be used to request
//! configuration data, renew that data, inform clients of changes, and a lot
//! more. These are described in detail in RFC 8415 section 7.3, with the full
//! list available
//! [here](https://www.iana.org/assignments/dhcpv6-parameters/dhcpv6-parameters.xhtml#dhcpv6-parameters-1).
//!
//! The most important options for us are:
//!
//! - Solicit: Used by clients to discover servers.
//! - Advertise: Used by servers to announce themselves to clients.
//! - Request: Request specific kinds of data from servers.
//! - Reply: Send specific kinds of data to clients.
//! - Renew: Sent by clients to renew leases for addresses.
//!
//! Options
//! -------
//!
//! Most important data in DHCPv6 is sent in Options. These are just type- and
//! length-delimited bytes, where the type determines the interpretation of
//! those bytes. There are a huge number of these, but as with message types,
//! we're mostly concerned with a small subset:
//!
//! - Client ID: A unique identifier for a client.
//! - Server ID: A unique identifier for a server.
//! - Non-Temporary Address: A permanent set of one or more IPv6 addresses.
//! - Temporary Address: A temporary set of one or more IPv6 addresses.
//! - IA Address: A single IPv6 address, with its lifetimes.
//! - Option Request: A list of Option codes for requested options.
//! - Elapsed Time: The duration a client has been trying to talk to the server.
//! - Rapid Commit: An option that tells the server to commit data to a client,
//! without waiting for a second ACK sequence of messages.
//! - DNS Servers: A list of IPv6 addresses for DNS servers the client can use.
//! - SNTP Servers: A list of IPv6 addresses for SNTP servers the client can
//! use.
//!
//! See the `options` module for more details on the encoding of these in a
//! message.
//!
//! DHCPv6 Unique Identifiers (DUID)
//! --------------------------------
//!
//! These are unique, opaque byte arrays that identify peers, both clients and
//! servers. They are formed from information such as MAC addresses, timestamps,
//! or UUIDs, though they're really just used for comparison, to uniquely ID a
//! peer. This is the content of a Client ID or Server ID option.

pub mod options;
pub mod protocol;
pub use protocol::MessageType;

use alloc::borrow::Cow;
use alloc::vec::Vec;
use core::convert::AsRef;
use core::fmt;
use core::fmt::Display;
use core::ops::Deref;
pub use opte_api::dhcpv6::AddressInfo;
pub use opte_api::dhcpv6::LeasedAddress;
use opte_api::DhcpCfg;
use opte_api::Ipv6Addr;
use opte_api::MacAddr;

/// The All-DHCP-Relay-Agents-And-Servers IPv6 address.
pub const ALL_RELAYS_AND_SERVERS: Ipv6Addr =
    Ipv6Addr::from_const([0xff02, 0, 0, 0, 0, 0, 1, 2]);

/// The All-DHCP-Servers IPv6 address.
pub const ALL_SERVERS: Ipv6Addr =
    Ipv6Addr::from_const([0xff05, 0, 0, 0, 0, 0, 1, 3]);

/// The UDP port on which DHCPv6 servers listen.
pub const SERVER_PORT: u16 = 547;

/// The UDP port from which clients transmit.
pub const CLIENT_PORT: u16 = 546;

/// An identifier for a single transaction, a request-reply pair in the DHCPv6
/// protocol.
///
/// See [RFC 8415 §8] for details, but this is just an opaque 3-octet ID.
///
/// [RFC 8415 §8]: https://www.rfc-editor.org/rfc/rfc8415.html#section-8
#[derive(Clone, Debug, PartialEq)]
pub struct TransactionId<'a>(pub Cow<'a, [u8]>);

impl<'a> TransactionId<'a> {
    pub const SIZE: usize = 3;
}

impl<'a> Deref for TransactionId<'a> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> AsRef<[u8]> for TransactionId<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> From<&'a [u8; 3]> for TransactionId<'a> {
    fn from(buf: &'a [u8; 3]) -> Self {
        Self(Cow::from(buf.as_slice()))
    }
}

/// An action for acting as a DHCPv6 server, leasing IPv6 addresses.
#[derive(Clone)]
pub struct Dhcpv6Action {
    /// Expected MAC address of the client.
    pub client_mac: MacAddr,

    /// MAC address we advertise as the DHCP server.
    pub server_mac: MacAddr,

    /// IPv6 addresses leased to the client.
    pub addrs: AddressInfo,

    /// SNTP servers the client should use.
    pub sntp_servers: Vec<Ipv6Addr>,

    /// Runtime-reconfigurable DHCP options (DNS, search lists, etc.).
    pub dhcp_cfg: DhcpCfg,
}

impl Dhcpv6Action {
    /// Return an iterator over the actual leased IPv6 addresses.
    pub fn addresses(&self) -> impl Iterator<Item = Ipv6Addr> + '_ {
        self.addrs.addrs.iter().map(|lease| lease.addr)
    }
}

impl Display for Dhcpv6Action {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let addr_list = self
            .addresses()
            .map(|addr| format!("{}", addr))
            .collect::<Vec<_>>()
            .join(",");
        write!(f, "DHCPv6 IA Addrs: [{}]", addr_list)
    }
}

/// A lifetime describes the duration over which data such as addresses are
/// valid. These are encoded in messages as a u32.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Lifetime(pub u32);

impl Lifetime {
    const INFINITE: Self = Self(u32::MAX);

    pub fn infinite() -> Self {
        Self::INFINITE
    }

    pub fn is_infinite(&self) -> bool {
        self == &Self::INFINITE
    }
}

impl Default for Lifetime {
    fn default() -> Self {
        Self::infinite()
    }
}

/// An error during DHCPv6 operations.
#[derive(Clone, Debug)]
pub enum Error {
    /// Not enough bytes to parse the desired type.
    Truncated,
    /// Unsupported parameter or value.
    Unsupported,
    /// Invalid data, e.g., non-UTF8 status code messages.
    InvalidData,
}

/// A DHCPv6 Unique Identifier (DUID).
///
/// DUIDs are used to identify peers in an exchange, both clients and servers.
/// There are a number of formats, but in general peers are supposed to treat
/// them as opaque byte arrays. We support copying any DUID format from a client
/// message, however we only _generate_ DUIDs in the Link-Layer Address format,
/// i.e., just from a MAC address.
#[derive(Clone, Debug, PartialEq)]
pub struct Duid<'a>(pub Cow<'a, [u8]>);

impl<'a> Duid<'a> {
    const TYPE_LL: u8 = 3;
    const HW_TYPE_ETHER: u8 = 1;
    // Length of Ethernet addr, plus two u16 words for the DUID type and the
    // hardware type.
    const LL_LEN: usize =
        crate::engine::ether::ETHER_ADDR_LEN + 2 * core::mem::size_of::<u16>();

    fn buffer_len(&self) -> usize {
        self.0.len()
    }

    fn copy_into<'b>(&'a self, buf: &'b mut [u8]) -> Result<(), Error>
    where
        'b: 'a,
    {
        if buf.len() < self.buffer_len() {
            return Err(Error::Truncated);
        }
        buf[0..self.buffer_len()].copy_from_slice(&self.0);
        Ok(())
    }

    /// Return `true` if the provided DUID matches the Link-Layer Address DUID
    /// we construct for a server, based on its MAC address.
    pub fn is_duid_ll_mac(&self, mac: &MacAddr) -> bool {
        let data = &self.0;
        if data.len() < Self::LL_LEN {
            return false;
        }
        if data[0] != 0 || data[1] != Self::TYPE_LL {
            return false;
        }
        if data[2] != 0 || data[3] != Self::HW_TYPE_ETHER {
            return false;
        }
        &data[4..] == mac.as_ref()
    }
}

impl<'a> From<&'a MacAddr> for Duid<'a> {
    fn from(mac: &'a MacAddr) -> Self {
        let mut buf = vec![0; Self::LL_LEN];
        buf[1] = Self::TYPE_LL;
        buf[3] = Self::HW_TYPE_ETHER;
        buf[4..].copy_from_slice(mac.as_ref());
        Self(Cow::from(buf))
    }
}

#[cfg(test)]
pub mod test_data {
    // A packet snooped from a Linux DHCPv6 client, sending a well-formed
    // Solicit message with no Rapid Commit option.
    //
    // This is an Ethernet frame, IPv6 header with no extension headers, UDP
    // header, and a Solicit message contained.
    pub const TEST_SOLICIT_PACKET: &[u8] =
        b"\x33\x33\x00\x01\x00\x02\xa8\x40\x25\xfa\xdd\x0b\x86\xdd\x60\x0a\
        \xea\xa7\x00\x40\x11\x01\xfe\x80\x00\x00\x00\x00\x00\x00\xaa\x40\
        \x25\xff\xfe\xfa\xdd\x0b\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\
        \x00\x00\x00\x01\x00\x02\x02\x22\x02\x23\x00\x40\x80\x86\x01\xb3\
        \xe0\x09\x00\x01\x00\x0e\x00\x01\x00\x01\x2a\xc9\xf2\x2d\xa8\x40\
        \x25\xfa\xdd\x0b\x00\x06\x00\x08\x00\x17\x00\x18\x00\x27\x00\x1f\
        \x00\x08\x00\x02\x00\x00\x00\x03\x00\x0c\x25\xfa\xdd\x0b\x00\x00\
        \x0e\x10\x00\x00\x15\x18";

    pub fn test_solicit_packet_solicit_message() -> &'static [u8] {
        &TEST_SOLICIT_PACKET[62..]
    }

    pub fn test_solicit_packet_xid() -> &'static [u8] {
        &TEST_SOLICIT_PACKET[63..66]
    }

    pub fn test_solicit_packet_client_id() -> &'static [u8] {
        &TEST_SOLICIT_PACKET[66..84]
    }

    pub fn test_solicit_packet_client_duid() -> &'static [u8] {
        &TEST_SOLICIT_PACKET[70..84]
    }

    pub fn test_solicit_packet_iana() -> &'static [u8] {
        &TEST_SOLICIT_PACKET[102..]
    }

    pub fn test_solicit_packet_option_request() -> &'static [u8] {
        &TEST_SOLICIT_PACKET[84..96]
    }
}

#[cfg(test)]
mod test {
    use super::Cow;
    use super::Duid;
    use super::MacAddr;
    use std::vec::Vec;

    #[test]
    fn test_duid_from_mac() {
        let mac: MacAddr = [0xa8, 0x40, 0x25, 0x01, 0x02, 0x03].into();
        let duid = Duid::from(&mac);

        let data = &duid.0;
        assert_eq!(data[1], Duid::TYPE_LL);
        assert_eq!(data[3], Duid::HW_TYPE_ETHER);
        assert_eq!(&data[4..], mac.as_ref());

        // Sanity check that comparison works.
        let buf = Cow::from(Vec::from(&data[..]));
        assert_eq!(duid, Duid(buf));
    }
}
