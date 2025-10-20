// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

use super::mac::MacAddr;
use crate::DomainName;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::Debug;
use core::fmt::Display;
use core::ops::Deref;
use core::result;
use core::str::FromStr;
use ingot::types::NetworkRepr;
use serde::Deserialize;
use serde::Serialize;

/// Generate an ICMPv6 Echo Reply message.
///
/// This maps an ICMPv6 Echo Request message from `src` to `dst` into an ICMPv6
/// Echo Reply message from `dst` to `src`.
#[derive(Debug, Clone, Copy)]
pub struct Icmpv6EchoReply {
    /// The MAC address of the Echo Request source.
    pub src_mac: MacAddr,

    /// The IP address of the Echo Request source.
    pub src_ip: Ipv6Addr,

    /// The MAC address of the Echo Request destination.
    pub dst_mac: MacAddr,

    /// The IP address of the Echo Request destination.
    pub dst_ip: Ipv6Addr,
}

impl Display for Icmpv6EchoReply {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ICMPv6 Echo Reply ({},{}) => ({},{})",
            self.dst_mac, self.dst_ip, self.src_mac, self.src_ip,
        )
    }
}

/// Generate an ICMPv4 Echo Reply message.
///
/// Map an ICMPv4 Echo Message (Type=8, Code=0) from `src` to `dst`
/// into an ICMPv4 Echo Reply Message (Type=0, Code=0) from `dst` to
/// `src`.
#[derive(Clone, Debug)]
pub struct IcmpEchoReply {
    /// The MAC address of the sender of the Echo message. The
    /// destination MAC address of the Echo Reply.
    pub echo_src_mac: MacAddr,

    /// The IP address of the sender of the Echo message. The
    /// destination IP address of the Echo Reply.
    pub echo_src_ip: Ipv4Addr,

    /// The MAC address of the destination of the Echo message. The
    /// source MAC address of the Echo Reply.
    pub echo_dst_mac: MacAddr,

    /// The IP address of the destination of the Echo message. The
    /// source IP address of the Echo Reply.
    pub echo_dst_ip: Ipv4Addr,
}

impl Display for IcmpEchoReply {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ICMPv4 Echo Reply ({},{}) => ({},{})",
            self.echo_dst_mac,
            self.echo_dst_ip,
            self.echo_src_mac,
            self.echo_src_ip,
        )
    }
}

/// Per-guest DHCP options.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DhcpCfg {
    /// Hostname to assign connected guest over DHCP.
    pub hostname: Option<DomainName>,

    /// Local domain of connected guest over DHCP.
    pub host_domain: Option<DomainName>,

    /// A list of domain names used during DNS resolution.
    ///
    /// Resolvers will use the provided list when resolving relative domain
    /// names.
    pub domain_search_list: Vec<DomainName>,

    /// IPv4 external DNS servers provided to a guest.
    pub dns4_servers: Vec<Ipv4Addr>,

    /// IPv6 external DNS servers provided to a guest.
    pub dns6_servers: Vec<Ipv6Addr>,
}

impl DhcpCfg {
    /// Combine `hostname` and `host_domain` into a single FQDN
    /// in a target buffer.
    pub fn push_fqdn(&self, buf: &mut Vec<u8>) {
        let Some(hostname) = &self.hostname else {
            return;
        };
        buf.extend_from_slice(hostname.encode());
        if let Some(domain_name) = &self.host_domain {
            // Need to overwrite trailing terminator of hostname.
            // Saturate is not strictly necessary: DomainNames can
            // only be parsed rather than constructed, but safer
            // to be conservative here.
            buf.truncate(buf.len().saturating_sub(1));
            buf.extend_from_slice(domain_name.encode());
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum DhcpReplyType {
    Offer,
    Ack,
}

impl Display for DhcpReplyType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Offer => write!(f, "OFFER"),
            Self::Ack => write!(f, "ACK"),
        }
    }
}

/// Map a subnet to its next-hop.
#[derive(Clone, Copy, Debug)]
pub struct SubnetRouterPair {
    pub subnet: Ipv4Cidr,
    pub router: Ipv4Addr,
}

impl SubnetRouterPair {
    pub fn encode_len(&self) -> u8 {
        // One byte for the subnet mask width.
        let mut entry_size = 1u8;

        // Variable length for the subnet number. Only significant
        // bytes are included.
        entry_size += self.subnet_encode_len();

        // Four bytes for the router's address.
        entry_size += 4;
        entry_size
    }

    pub fn encode(&self, bytes: &mut [u8]) {
        let mut pos = 0;
        bytes[pos] = self.subnet.prefix_len();
        pos += 1;
        let n = self.subnet_encode_len();
        let subnet_bytes = &self.subnet.ip();
        for i in 0..n {
            bytes[pos] = subnet_bytes[i as usize];
            pos += 1;
        }

        for b in self.router.bytes() {
            bytes[pos] = b;
            pos += 1;
        }
    }

    pub fn new(subnet: Ipv4Cidr, router: Ipv4Addr) -> Self {
        Self { subnet, router }
    }

    fn subnet_encode_len(&self) -> u8 {
        let prefix = self.subnet.prefix_len();

        if prefix == 0 {
            0
        } else {
            let round = u8::from(!prefix.is_multiple_of(8));
            (prefix / 8) + round
        }
    }
}

/// An IP protocol value.
#[repr(u8)]
#[derive(
    Clone,
    Copy,
    Debug,
    Deserialize,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
pub enum Protocol {
    ICMP,
    IGMP,
    TCP,
    UDP,
    ICMPv6,
    Unknown(u8),
}

pub const PROTO_ICMP: u8 = 0x1;
pub const PROTO_IGMP: u8 = 0x2;
pub const PROTO_TCP: u8 = 0x6;
pub const PROTO_UDP: u8 = 0x11;
pub const PROTO_ICMPV6: u8 = 0x3A;

impl Default for Protocol {
    fn default() -> Self {
        Self::Unknown(255)
    }
}

impl Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::ICMP => write!(f, "ICMP"),
            Self::IGMP => write!(f, "IGMP"),
            Self::TCP => write!(f, "TCP"),
            Self::UDP => write!(f, "UDP"),
            Self::ICMPv6 => write!(f, "ICMPv6"),
            Self::Unknown(_) => write!(f, "Unknown"),
        }
    }
}

impl From<u8> for Protocol {
    fn from(proto: u8) -> Self {
        match proto {
            PROTO_ICMP => Self::ICMP,
            PROTO_IGMP => Self::IGMP,
            PROTO_TCP => Self::TCP,
            PROTO_UDP => Self::UDP,
            PROTO_ICMPV6 => Self::ICMPv6,
            _ => Self::Unknown(proto),
        }
    }
}

impl From<Protocol> for u8 {
    fn from(proto: Protocol) -> u8 {
        match proto {
            Protocol::ICMP => PROTO_ICMP,
            Protocol::IGMP => PROTO_IGMP,
            Protocol::TCP => PROTO_TCP,
            Protocol::UDP => PROTO_UDP,
            Protocol::ICMPv6 => PROTO_ICMPV6,
            Protocol::Unknown(v) => v,
        }
    }
}

impl From<smoltcp::wire::IpProtocol> for Protocol {
    fn from(proto: smoltcp::wire::IpProtocol) -> Self {
        Self::from(u8::from(proto))
    }
}

impl From<Protocol> for smoltcp::wire::IpProtocol {
    fn from(proto: Protocol) -> smoltcp::wire::IpProtocol {
        use smoltcp::wire::IpProtocol::*;
        match proto {
            Protocol::ICMP => Icmp,
            Protocol::IGMP => Igmp,
            Protocol::TCP => Tcp,
            Protocol::UDP => Udp,
            Protocol::ICMPv6 => Icmpv6,
            Protocol::Unknown(proto) => Unknown(proto),
        }
    }
}

/// An IPv4 or IPv6 address.
#[derive(
    Clone,
    Copy,
    Debug,
    Deserialize,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
pub enum IpAddr {
    Ip4(Ipv4Addr),
    Ip6(Ipv6Addr),
}

impl IpAddr {
    pub const fn is_multicast(&self) -> bool {
        match self {
            IpAddr::Ip4(v4) => v4.is_multicast(),
            IpAddr::Ip6(v6) => v6.is_multicast(),
        }
    }
}

impl From<Ipv4Addr> for IpAddr {
    fn from(ipv4: Ipv4Addr) -> Self {
        IpAddr::Ip4(ipv4)
    }
}

impl From<Ipv6Addr> for IpAddr {
    fn from(ipv6: Ipv6Addr) -> Self {
        IpAddr::Ip6(ipv6)
    }
}

#[cfg(any(feature = "std", test))]
impl From<std::net::IpAddr> for IpAddr {
    fn from(ip: std::net::IpAddr) -> Self {
        match ip {
            std::net::IpAddr::V4(ipv4) => Self::Ip4(ipv4.into()),
            std::net::IpAddr::V6(ipv6) => Self::Ip6(ipv6.into()),
        }
    }
}

#[cfg(any(feature = "std", test))]
impl From<IpAddr> for std::net::IpAddr {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::Ip4(ipv4) => Self::V4(ipv4.into()),
            IpAddr::Ip6(ipv6) => Self::V6(ipv6.into()),
        }
    }
}

impl Default for IpAddr {
    fn default() -> Self {
        IpAddr::Ip4(Default::default())
    }
}

impl fmt::Display for IpAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IpAddr::Ip4(ip4) => write!(f, "{ip4}"),
            IpAddr::Ip6(ip6) => write!(f, "{ip6}"),
        }
    }
}

impl FromStr for IpAddr {
    type Err = String;
    fn from_str(val: &str) -> result::Result<Self, Self::Err> {
        if let Ok(ipv4) = val.parse::<Ipv4Addr>() {
            Ok(ipv4.into())
        } else {
            val.parse::<Ipv6Addr>()
                .map(IpAddr::Ip6)
                .map_err(|_| String::from("Invalid IP address"))
        }
    }
}

/// An IPv4 address.
#[derive(
    Clone,
    Copy,
    Default,
    Deserialize,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[repr(C)]
pub struct Ipv4Addr {
    inner: [u8; 4],
}

impl Ipv4Addr {
    pub const ANY_ADDR: Self = Self { inner: [0; 4] };
    pub const LOCAL_BCAST: Self = Self { inner: [255; 4] };

    /// Return the bytes of the address.
    #[inline]
    pub fn bytes(&self) -> [u8; 4] {
        self.inner
    }

    pub const fn from_const(bytes: [u8; 4]) -> Self {
        Self { inner: bytes }
    }

    /// Return the address after applying the network mask.
    pub fn mask(mut self, mask: u8) -> Result<Self, String> {
        if mask > 32 {
            return Err(format!("bad mask: {mask}"));
        }

        if mask == 0 {
            return Ok(Ipv4Addr::ANY_ADDR);
        }

        let mut n = u32::from_be_bytes(self.inner);

        let mut bits = i32::MIN;
        bits >>= mask - 1;
        n &= bits as u32;
        self.inner = n.to_be_bytes();
        Ok(self)
    }

    pub fn safe_mask(self, prefix_len: Ipv4PrefixLen) -> Self {
        self.mask(prefix_len.0).unwrap()
    }

    /// Produce a `u32` which itself is stored in memory in network
    /// order. This is needed for passing this type up to DTrace so
    /// its inet_ntoa() subroutine works.
    pub fn to_be(self) -> u32 {
        // First we create a native-endian u32 from the network-order
        // bytes, then we convert that to an in-memory network-order
        // u32.
        u32::from_be_bytes(self.bytes()).to_be()
    }

    pub const fn is_multicast(&self) -> bool {
        matches!(self.inner[0], 224..240)
    }
}

impl From<core::net::Ipv4Addr> for Ipv4Addr {
    fn from(ip4: core::net::Ipv4Addr) -> Self {
        Self { inner: ip4.octets() }
    }
}

impl From<Ipv4Addr> for core::net::Ipv4Addr {
    fn from(ip4: Ipv4Addr) -> Self {
        Self::from(ip4.inner)
    }
}

impl From<smoltcp::wire::Ipv4Address> for Ipv4Addr {
    fn from(smolip4: smoltcp::wire::Ipv4Address) -> Self {
        let bytes = smolip4.as_bytes();
        Self::from([bytes[0], bytes[1], bytes[2], bytes[3]])
    }
}

impl From<Ipv4Addr> for smoltcp::wire::Ipv4Address {
    fn from(ip: Ipv4Addr) -> Self {
        Self::from_bytes(&ip)
    }
}

impl From<Ipv4Addr> for u32 {
    fn from(ip: Ipv4Addr) -> u32 {
        u32::from_be_bytes(ip.bytes())
    }
}

impl From<u32> for Ipv4Addr {
    fn from(val: u32) -> Self {
        Self { inner: val.to_be_bytes() }
    }
}

impl From<[u8; 4]> for Ipv4Addr {
    fn from(bytes: [u8; 4]) -> Self {
        Self { inner: bytes }
    }
}

impl FromStr for Ipv4Addr {
    type Err = String;

    fn from_str(val: &str) -> result::Result<Self, Self::Err> {
        let octets: Vec<u8> = val
            .split('.')
            .map(|s| s.parse().map_err(|e| format!("{e}")))
            .collect::<result::Result<Vec<u8>, _>>()?;

        if octets.len() != 4 {
            return Err(format!("malformed ip: {val}"));
        }

        // At the time of writing there is no TryFrom impl for Vec to
        // array in the alloc create. Honestly this looks a bit
        // cleaner anyways.
        Ok(Self { inner: [octets[0], octets[1], octets[2], octets[3]] })
    }
}

impl Display for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.inner[0], self.inner[1], self.inner[2], self.inner[3],
        )
    }
}

// There's no reason to view an Ipv4Addr as its raw array, so just
// present it in a human-friendly manner.
impl Debug for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Ipv4Addr {{ inner: {self} }}")
    }
}

impl AsRef<[u8]> for Ipv4Addr {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl AsRef<[u8; 4]> for Ipv4Addr {
    fn as_ref(&self) -> &[u8; 4] {
        &self.inner
    }
}

impl From<Ipv4Addr> for [u8; 4] {
    fn from(ip: Ipv4Addr) -> [u8; 4] {
        ip.inner
    }
}

impl Deref for Ipv4Addr {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// An IPv6 address.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
    Deserialize,
)]
#[repr(C)]
pub struct Ipv6Addr {
    inner: [u8; 16],
}

impl Ipv6Addr {
    /// The unspecified IPv6 address, i.e., `::` or all zeros.
    pub const ANY_ADDR: Self = Self { inner: [0; 16] };

    /// The All-Routers multicast address, used in the Neighbor Discovery
    /// Protocol.
    pub const ALL_ROUTERS: Self =
        Self::from_const([0xff02, 0, 0, 0, 0, 0, 0, 2]);

    /// The All-Nodes multicast address, used in the Neighbor Discovery
    /// Protocol.
    pub const ALL_NODES: Self = Self::from_const([0xff02, 0, 0, 0, 0, 0, 0, 1]);

    /// Generate an IPv6 address via an EUI-64 transform, from a MAC address.
    /// The generated address has link-local scope.
    ///
    /// See [RFC 4291] for details of the transformation applied.
    ///
    /// [RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291#page-20
    pub fn from_eui64(mac: &MacAddr) -> Self {
        let mac = mac.bytes();
        // Invert the locally-administered bit in the first octet of the MAC
        let mac0 = mac[0] ^ 0b10;
        let bytes: [u8; 16] = [
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, mac0, mac[1],
            mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5],
        ];
        Self::from(bytes)
    }

    /// Return the multicast MAC address associated with this multicast IPv6
    /// address. If the IPv6 address is not multicast, None will be returned.
    ///
    /// See [RFC 2464 §7] for details.
    ///
    /// [RFC 2464 §7]: https://www.rfc-editor.org/rfc/rfc2464
    pub const fn multicast_mac(&self) -> Option<MacAddr> {
        if self.is_multicast() {
            Some(self.unchecked_multicast_mac())
        } else {
            None
        }
    }

    /// Return the multicast MAC address associated with this multicast IPv6
    /// address, without checking if this IP address is a multicast address.
    ///
    /// See [RFC 2464 §7] for details.
    ///
    /// [RFC 2464 §7]: https://www.rfc-editor.org/rfc/rfc2464
    pub const fn unchecked_multicast_mac(&self) -> MacAddr {
        let bytes = &self.inner;
        MacAddr::from_const([
            0x33, 0x33, bytes[12], bytes[13], bytes[14], bytes[15],
        ])
    }

    /// Return the solicited-node multicast IPv6 address corresponding to
    /// `self`.
    ///
    /// See [RFC 4291 §2.7.1] for details.
    ///
    /// [RFC 4291 §2.7.1]: https://www.rfc-editor.org/rfc/rfc4291#section-2.7.1
    pub const fn solicited_node_multicast(&self) -> Ipv6Addr {
        let bytes = &self.inner;
        let w0 = u16::from_be_bytes([0xff, bytes[13]]);
        let w1 = u16::from_be_bytes([bytes[14], bytes[15]]);
        Self::from_const([0xff02, 0, 0, 0, 0, 1, w0, w1])
    }

    /// Return `true` if this is a solicited node multicast address.
    pub fn is_solicited_node_multicast(&self) -> bool {
        const EXPECTED: &[u8] =
            &[0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xff];
        &self.inner[..EXPECTED.len()] == EXPECTED
    }

    /// Return `true` if this is a multicast IPv6 address, and `false` otherwise
    pub const fn is_multicast(&self) -> bool {
        self.inner[0] == 0xFF
    }

    /// Return `true` if this is a multicast IPv6 address with administrative scope
    /// (admin-local, site-local, or organization-local) as defined in RFC 4291 and RFC 7346.
    ///
    /// The three administrative scopes are:
    /// - `0x4`: admin-local scope
    /// - `0x5`: site-local scope
    /// - `0x8`: organization-local scope
    pub const fn is_admin_scoped_multicast(&self) -> bool {
        if !self.is_multicast() {
            return false;
        }

        // Extract the scope field from the lower 4 bits of the second byte
        // (first byte is 0xFF for all multicast, second byte contains flags and scope)
        let scope = self.inner[1] & 0x0F;
        matches!(scope, 0x4 | 0x5 | 0x8)
    }

    /// Return the bytes of the address.
    pub fn bytes(&self) -> [u8; 16] {
        self.inner
    }

    /// Return the address after applying the network mask.
    pub fn mask(mut self, mask: u8) -> Result<Self, String> {
        if mask > 128 {
            return Err(format!("bad mask: {mask}"));
        }

        if mask == 128 {
            return Ok(self);
        }

        if mask == 0 {
            self.inner.fill(0);
            return Ok(self);
        }

        // The mask is in bits and we want to determine which byte (of
        // the 16 that make up the address) to start with. A byte is 8
        // bits, if 8 goes into `mask` N times, then the first N bytes
        // stay as-is. However, byte N may need partial masking, and
        // bytes N+1..16 must be set to zero.
        let mut byte_idx = usize::from(mask / 8);
        let partial = mask % 8;

        if partial > 0 {
            let bits = i8::MIN >> (partial - 1);
            self.inner[byte_idx] &= bits as u8;
            byte_idx += 1;
        }
        self.inner[byte_idx..].fill(0);

        Ok(self)
    }

    pub fn safe_mask(self, mask: Ipv6PrefixLen) -> Self {
        self.mask(mask.val()).unwrap()
    }

    pub const fn from_const(words: [u16; 8]) -> Self {
        let w0 = words[0].to_be_bytes();
        let w1 = words[1].to_be_bytes();
        let w2 = words[2].to_be_bytes();
        let w3 = words[3].to_be_bytes();
        let w4 = words[4].to_be_bytes();
        let w5 = words[5].to_be_bytes();
        let w6 = words[6].to_be_bytes();
        let w7 = words[7].to_be_bytes();
        Self {
            inner: [
                w0[0], w0[1], w1[0], w1[1], w2[0], w2[1], w3[0], w3[1], w4[0],
                w4[1], w5[0], w5[1], w6[0], w6[1], w7[0], w7[1],
            ],
        }
    }

    pub fn has_prefix(&self, prefix: u128, len: u8) -> bool {
        let mask = ((1u128 << len) - 1) << (128 - len);
        (mask & u128::from_be_bytes(self.inner)) == prefix
    }
}

impl fmt::Display for Ipv6Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let sip6 = smoltcp::wire::Ipv6Address(self.bytes());
        write!(f, "{sip6}")
    }
}

impl From<core::net::Ipv6Addr> for Ipv6Addr {
    fn from(ip6: core::net::Ipv6Addr) -> Self {
        Self { inner: ip6.octets() }
    }
}

impl From<Ipv6Addr> for core::net::Ipv6Addr {
    fn from(ip6: Ipv6Addr) -> Self {
        Self::from(ip6.inner)
    }
}

impl From<smoltcp::wire::Ipv6Address> for Ipv6Addr {
    fn from(ip: smoltcp::wire::Ipv6Address) -> Self {
        // Safety: We assume the `smoltcp` type is well-formed, with at least 16
        // octets in the correct order.
        let bytes: [u8; 16] = ip.as_bytes().try_into().unwrap();
        Self::from(bytes)
    }
}

impl From<Ipv6Addr> for smoltcp::wire::Ipv6Address {
    fn from(ip: Ipv6Addr) -> Self {
        // Safety: This panics, but we know bytes is exactly 16 octets.
        Self::from_bytes(&ip)
    }
}

impl From<&[u8; 16]> for Ipv6Addr {
    fn from(bytes: &[u8; 16]) -> Ipv6Addr {
        Ipv6Addr { inner: *bytes }
    }
}

impl From<Ipv6Addr> for u128 {
    fn from(ip: Ipv6Addr) -> u128 {
        u128::from_be_bytes(ip.bytes())
    }
}

impl From<[u8; 16]> for Ipv6Addr {
    fn from(bytes: [u8; 16]) -> Ipv6Addr {
        Ipv6Addr { inner: bytes }
    }
}

impl From<[u16; 8]> for Ipv6Addr {
    fn from(bytes: [u16; 8]) -> Ipv6Addr {
        let tmp = bytes.map(u16::to_be_bytes);
        let mut addr = [0; 16];
        for (i, pair) in tmp.iter().enumerate() {
            addr[i * 2] = pair[0];
            addr[(i * 2) + 1] = pair[1];
        }

        Ipv6Addr { inner: addr }
    }
}

impl From<u128> for Ipv6Addr {
    fn from(i: u128) -> Ipv6Addr {
        Self::from(i.to_be_bytes())
    }
}

impl FromStr for Ipv6Addr {
    type Err = String;

    fn from_str(val: &str) -> result::Result<Self, Self::Err> {
        let ip = val
            .parse::<smoltcp::wire::Ipv6Address>()
            .map_err(|_| String::from("Invalid IPv6 address"))?;
        Ok(ip.into())
    }
}

impl AsRef<[u8]> for Ipv6Addr {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl Deref for Ipv6Addr {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// An IPv4 or IPv6 CIDR.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum IpCidr {
    Ip4(Ipv4Cidr),
    Ip6(Ipv6Cidr),
}

impl From<Ipv4Cidr> for IpCidr {
    fn from(cidr: Ipv4Cidr) -> Self {
        IpCidr::Ip4(cidr)
    }
}

impl From<Ipv6Cidr> for IpCidr {
    fn from(cidr: Ipv6Cidr) -> Self {
        IpCidr::Ip6(cidr)
    }
}

impl IpCidr {
    pub fn is_default(&self) -> bool {
        match self {
            Self::Ip4(ip4) => ip4.is_default(),
            Self::Ip6(ip6) => ip6.is_default(),
        }
    }

    pub fn ip(&self) -> IpAddr {
        match self {
            Self::Ip4(ip4) => IpAddr::Ip4(ip4.ip()),
            Self::Ip6(ip6) => IpAddr::Ip6(ip6.ip()),
        }
    }

    pub fn prefix_len(&self) -> u8 {
        match self {
            Self::Ip4(ip4) => ip4.prefix_len(),
            Self::Ip6(ip6) => ip6.prefix_len(),
        }
    }

    pub fn max_prefix_len(&self) -> u8 {
        match self {
            Self::Ip4(_) => Ipv4PrefixLen::NETMASK_ALL.val(),
            Self::Ip6(_) => Ipv6PrefixLen::NETMASK_ALL.val(),
        }
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Ip4(ip4) => write!(f, "{ip4}"),
            Self::Ip6(ip6) => write!(f, "{ip6}"),
        }
    }
}

impl FromStr for IpCidr {
    type Err = String;

    /// Convert a string like "192.168.2.0/24" into an `IpCidr`.
    fn from_str(val: &str) -> result::Result<Self, Self::Err> {
        match val.parse::<Ipv4Cidr>() {
            Ok(ip4) => Ok(IpCidr::Ip4(ip4)),
            Err(_) => val
                .parse::<Ipv6Cidr>()
                .map(IpCidr::Ip6)
                .map_err(|_| String::from("Invalid IP CIDR")),
        }
    }
}

#[cfg(feature = "ipnetwork")]
impl From<ipnetwork::IpNetwork> for IpCidr {
    fn from(ip: ipnetwork::IpNetwork) -> Self {
        match ip {
            ipnetwork::IpNetwork::V4(ip4) => Self::Ip4(ip4.into()),
            ipnetwork::IpNetwork::V6(ip6) => Self::Ip6(ip6.into()),
        }
    }
}

#[cfg(feature = "ipnetwork")]
impl From<IpCidr> for ipnetwork::IpNetwork {
    fn from(ip: IpCidr) -> Self {
        match ip {
            IpCidr::Ip4(ip4) => Self::V4(ip4.into()),
            IpCidr::Ip6(ip6) => Self::V6(ip6.into()),
        }
    }
}

/// A valid IPv4 prefix legnth.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, Ord, PartialOrd,
)]
pub struct Ipv4PrefixLen(u8);

impl TryFrom<u8> for Ipv4PrefixLen {
    type Error = String;

    fn try_from(p: u8) -> Result<Self, Self::Error> {
        Self::new(p)
    }
}

impl Ipv4PrefixLen {
    pub const NETMASK_NONE: Self = Self(0);
    pub const NETMASK_ALL: Self = Self(32);

    pub fn new(prefix_len: u8) -> Result<Self, String> {
        if prefix_len > 32 {
            return Err(format!("bad IPv4 prefix length: {prefix_len}"));
        }

        Ok(Self(prefix_len))
    }

    /// Convert the prefix length into a subnet mask.
    pub fn to_netmask(self) -> Ipv4Addr {
        let mut bits = i32::MIN;
        bits >>= self.0 - 1;
        Ipv4Addr::from(bits.to_be_bytes())
    }

    pub fn val(&self) -> u8 {
        self.0
    }
}

/// An IPv4 CIDR.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Ipv4Cidr {
    ip: Ipv4Addr,
    prefix_len: Ipv4PrefixLen,
}

impl core::cmp::Ord for Ipv4Cidr {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        if self.ip != other.ip {
            self.ip.cmp(&other.ip)
        } else {
            self.prefix_len.cmp(&other.prefix_len)
        }
    }
}

impl core::cmp::PartialOrd for Ipv4Cidr {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl FromStr for Ipv4Cidr {
    type Err = String;

    /// Convert a string like "192.168.2.0/24" into an `Ipv4Cidr`.
    fn from_str(val: &str) -> result::Result<Self, Self::Err> {
        let (ip_s, prefix_s) = match val.split_once('/') {
            Some(v) => v,
            None => return Err("no '/' found".to_string()),
        };

        let ip = match ip_s.parse() {
            Ok(v) => v,
            Err(e) => return Err(format!("bad IP: {e}")),
        };

        let raw = match prefix_s.parse::<u8>() {
            Ok(v) => v,
            Err(e) => {
                return Err(format!("bad prefix length: {e}"));
            }
        };

        let prefix_len = Ipv4PrefixLen::new(raw)?;
        Ok(Ipv4Cidr::new(ip, prefix_len))
    }
}

impl Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.ip, self.prefix_len.val())
    }
}

impl Ipv4Cidr {
    /// IPv4 multicast address range, `224.0.0.0/4`.
    pub const MCAST: Self = Self {
        ip: Ipv4Addr::from_const([224, 0, 0, 0]),
        prefix_len: Ipv4PrefixLen(4),
    };

    pub fn ip(&self) -> Ipv4Addr {
        self.parts().0
    }

    /// Does this CIDR represent the default route subnet?
    pub fn is_default(&self) -> bool {
        let (ip, prefix_len) = self.parts();
        ip == Ipv4Addr::ANY_ADDR && prefix_len.val() == 0
    }

    /// Is this `ip` a member of the CIDR?
    pub fn is_member(&self, ip: Ipv4Addr) -> bool {
        ip.safe_mask(self.parts().1) == self.ip()
    }

    pub fn new(ip: Ipv4Addr, prefix_len: Ipv4PrefixLen) -> Self {
        let ip = ip.safe_mask(prefix_len);
        Ipv4Cidr { ip, prefix_len }
    }

    pub fn new_checked(ip: Ipv4Addr, prefix_len: u8) -> Result<Self, String> {
        let pl = Ipv4PrefixLen::new(prefix_len)?;
        let ip = ip.safe_mask(pl);
        Ok(Ipv4Cidr { ip, prefix_len: pl })
    }

    pub fn parts(&self) -> (Ipv4Addr, Ipv4PrefixLen) {
        (self.ip, self.prefix_len)
    }

    pub fn prefix_len(self) -> u8 {
        self.parts().1.val()
    }

    /// Convert the CIDR prefix length into a subnet mask.
    pub fn to_mask(self) -> Ipv4Addr {
        let mut bits = i32::MIN;
        bits >>= self.prefix_len() - 1;
        Ipv4Addr::from(bits.to_be_bytes())
    }
}

#[cfg(feature = "ipnetwork")]
impl From<ipnetwork::Ipv4Network> for Ipv4Cidr {
    fn from(n: ipnetwork::Ipv4Network) -> Self {
        let ip = n.ip().into();
        // A valid `Ipv4Network` necessarily has a valid prefix so fine to unwrap.
        let prefix = Ipv4PrefixLen::new(n.prefix()).unwrap();
        Ipv4Cidr::new(ip, prefix)
    }
}

#[cfg(feature = "ipnetwork")]
impl From<Ipv4Cidr> for ipnetwork::Ipv4Network {
    fn from(c: Ipv4Cidr) -> Self {
        let (ip, prefix) = c.parts();
        // A valid `Ipv4Cidr` necessarily has a valid prefix so fine to unwrap.
        ipnetwork::Ipv4Network::new(ip.into(), prefix.val()).unwrap()
    }
}

/// An IPv6 CIDR.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Ipv6Cidr {
    ip: Ipv6Addr,
    prefix_len: Ipv6PrefixLen,
}

impl core::cmp::Ord for Ipv6Cidr {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        if self.ip != other.ip {
            self.ip.cmp(&other.ip)
        } else {
            self.prefix_len.cmp(&other.prefix_len)
        }
    }
}

impl core::cmp::PartialOrd for Ipv6Cidr {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Ipv6Cidr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let (ip, prefix_len) = self.parts();
        write!(f, "{ip}/{}", prefix_len.val())
    }
}

impl FromStr for Ipv6Cidr {
    type Err = String;

    /// Convert a string like "fd00:dead:beef:cafe::/64" into an [`Ipv6Cidr`].
    fn from_str(val: &str) -> result::Result<Self, Self::Err> {
        let (ip_s, prefix_s) = match val.split_once('/') {
            Some(v) => v,
            None => return Err("no '/' found".to_string()),
        };

        let ip = match ip_s.parse::<smoltcp::wire::Ipv6Address>() {
            Ok(v) => v.into(),
            Err(_) => {
                return Err(format!("Bad IP address component: '{ip_s}'"));
            }
        };

        let prefix_len = match prefix_s.parse::<u8>() {
            Ok(v) => v,
            Err(e) => {
                return Err(format!("bad prefix length: {e}"));
            }
        };

        Ipv6Cidr::new_checked(ip, prefix_len)
    }
}

/// A valid IPv6 prefix length.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, Ord, PartialOrd,
)]
pub struct Ipv6PrefixLen(u8);

impl TryFrom<u8> for Ipv6PrefixLen {
    type Error = String;

    fn try_from(p: u8) -> Result<Self, Self::Error> {
        Self::new(p)
    }
}

impl Ipv6PrefixLen {
    pub const NETMASK_NONE: Self = Self(0);
    pub const NETMASK_ALL: Self = Self(128);

    pub fn new(prefix_len: u8) -> result::Result<Self, String> {
        if prefix_len > 128 {
            return Err(format!("bad IPv6 prefix length: {prefix_len}"));
        }

        Ok(Self(prefix_len))
    }

    pub fn val(&self) -> u8 {
        self.0
    }
}

impl Ipv6Cidr {
    /// The IPv6 link-local prefix, `fe80::/64`.
    pub const LINK_LOCAL: Self = Self {
        ip: Ipv6Addr::from_const([0xfe80, 0, 0, 0, 0, 0, 0, 0]),
        prefix_len: Ipv6PrefixLen(64),
    };

    /// IPv6 admin-local multicast scope prefix, `ff04::/16`.
    pub const MCAST_ADMIN_LOCAL: Self = Self {
        ip: Ipv6Addr::from_const([0xff04, 0, 0, 0, 0, 0, 0, 0]),
        prefix_len: Ipv6PrefixLen(16),
    };

    /// IPv6 site-local multicast scope prefix, `ff05::/16`.
    pub const MCAST_SITE_LOCAL: Self = Self {
        ip: Ipv6Addr::from_const([0xff05, 0, 0, 0, 0, 0, 0, 0]),
        prefix_len: Ipv6PrefixLen(16),
    };

    /// IPv6 organization-local multicast scope prefix, `ff08::/16`.
    pub const MCAST_ORG_LOCAL: Self = Self {
        ip: Ipv6Addr::from_const([0xff08, 0, 0, 0, 0, 0, 0, 0]),
        prefix_len: Ipv6PrefixLen(16),
    };

    pub fn new(ip: Ipv6Addr, prefix_len: Ipv6PrefixLen) -> Self {
        let ip = ip.safe_mask(prefix_len);
        Ipv6Cidr { ip, prefix_len }
    }

    pub fn new_checked(
        ip: Ipv6Addr,
        prefix_len: u8,
    ) -> result::Result<Self, String> {
        let pl = Ipv6PrefixLen::new(prefix_len)?;
        let ip = ip.safe_mask(pl);
        Ok(Ipv6Cidr { ip, prefix_len: pl })
    }

    pub fn parts(&self) -> (Ipv6Addr, Ipv6PrefixLen) {
        (self.ip, self.prefix_len)
    }

    /// Return `true` if this is the default route subnet
    pub fn is_default(&self) -> bool {
        let (ip, prefix_len) = self.parts();
        ip == Ipv6Addr::ANY_ADDR && prefix_len.val() == 0
    }

    /// Return the prefix length (netmask).
    pub fn prefix_len(self) -> u8 {
        self.prefix_len.0
    }

    /// Return the network address of this CIDR.
    pub fn ip(&self) -> Ipv6Addr {
        self.ip
    }

    /// Is this `ip` a member of the CIDR?
    pub fn is_member(&self, ip: Ipv6Addr) -> bool {
        ip.safe_mask(self.prefix_len) == self.ip
    }
}

#[cfg(feature = "ipnetwork")]
impl From<ipnetwork::Ipv6Network> for Ipv6Cidr {
    fn from(n: ipnetwork::Ipv6Network) -> Self {
        let ip = n.ip().into();
        // A valid `Ipv6Network` necessarily has a valid prefix so fine to unwrap.
        let prefix = Ipv6PrefixLen::new(n.prefix()).unwrap();
        Ipv6Cidr::new(ip, prefix)
    }
}

#[cfg(feature = "ipnetwork")]
impl From<Ipv6Cidr> for ipnetwork::Ipv6Network {
    fn from(c: Ipv6Cidr) -> Self {
        let (ip, prefix) = c.parts();
        // A valid `Ipv6Cidr` necessarily has a valid prefix so fine to unwrap.
        ipnetwork::Ipv6Network::new(ip.into(), prefix.val()).unwrap()
    }
}

impl NetworkRepr<[u8; 4]> for Ipv4Addr {
    fn to_network(self) -> [u8; 4] {
        self.inner
    }

    fn from_network(val: [u8; 4]) -> Self {
        Self { inner: val }
    }
}

impl NetworkRepr<[u8; 16]> for Ipv6Addr {
    fn to_network(self) -> [u8; 16] {
        self.inner
    }

    fn from_network(val: [u8; 16]) -> Self {
        Self { inner: val }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::string::ToString;

    #[test]
    fn bad_prefix_len() {
        let msg = "bad IPv4 prefix length: 33".to_string();
        assert_eq!(Ipv4PrefixLen::new(33), Err(msg));
    }

    #[test]
    fn bad_cidr() {
        let mut msg = "bad IPv4 prefix length: 33".to_string();
        assert_eq!("192.168.2.9/33".parse::<Ipv4Cidr>(), Err(msg.clone()));

        msg = "bad IPv6 prefix length: 129".to_string();
        let ip6 = "fd01:dead:beef::1".parse().unwrap();
        assert_eq!(Ipv6Cidr::new_checked(ip6, 129), Err(msg.clone()));

        assert_eq!("fd01:dead:beef::1/129".parse::<Ipv6Cidr>(), Err(msg))
    }

    #[test]
    fn good_cidr() {
        let pl = Ipv4PrefixLen::new(24).unwrap();
        let ip = "192.168.2.0".parse().unwrap();
        assert_eq!(
            Ipv4Cidr::new(ip, pl),
            Ipv4Cidr {
                ip: Ipv4Addr { inner: [192, 168, 2, 0] },
                prefix_len: pl,
            }
        );

        assert_eq!(
            "192.168.2.0/24".parse(),
            Ok(Ipv4Cidr {
                ip: Ipv4Addr { inner: [192, 168, 2, 0] },
                prefix_len: pl,
            })
        );

        assert_eq!(
            "192.168.2.9/24".parse(),
            Ok(Ipv4Cidr {
                ip: Ipv4Addr { inner: [192, 168, 2, 0] },
                prefix_len: pl,
            })
        );

        assert_eq!(
            "192.168.2.9/24".parse::<Ipv4Cidr>().unwrap().to_string(),
            "192.168.2.0/24".to_string()
        );

        let mut ip6_cidr = "fd01:dead:beef::1/64".parse::<Ipv6Cidr>().unwrap();
        let mut ip6_prefix = "fd01:dead:beef::".parse().unwrap();
        assert_eq!(
            ip6_cidr.parts(),
            (ip6_prefix, Ipv6PrefixLen::new(64).unwrap())
        );

        ip6_cidr = "fe80::8:20ff:fe35:f794/10".parse::<Ipv6Cidr>().unwrap();
        ip6_prefix = "fe80::".parse().unwrap();
        assert_eq!(
            ip6_cidr.parts(),
            (ip6_prefix, Ipv6PrefixLen::new(10).unwrap())
        );

        ip6_cidr = "fe80::8:20ff:fe35:f794/128".parse::<Ipv6Cidr>().unwrap();
        ip6_prefix = "fe80::8:20ff:fe35:f794".parse().unwrap();
        assert_eq!(
            ip6_cidr.parts(),
            (ip6_prefix, Ipv6PrefixLen::new(128).unwrap())
        );

        ip6_cidr = "fd00:1122:3344:0201::/56".parse::<Ipv6Cidr>().unwrap();
        ip6_prefix = "fd00:1122:3344:0200::".parse().unwrap();
        assert_eq!(
            ip6_cidr.parts(),
            (ip6_prefix, Ipv6PrefixLen::new(56).unwrap())
        );
    }

    #[test]
    fn ipv4_addr_bad() {
        assert!("192.168.33.1O".parse::<Ipv4Addr>().is_err());
        assert!("192.168.33.256".parse::<Ipv4Addr>().is_err());
    }

    #[test]
    fn ipv4_addr_good() {
        assert_eq!(
            "192.168.33.10".parse(),
            Ok(Ipv4Addr::from([192, 168, 33, 10]))
        );
    }

    #[test]
    fn ipv4_mask() {
        let ip = "192.168.2.77".parse::<Ipv4Addr>().unwrap();
        assert_eq!(ip.mask(24).unwrap(), "192.168.2.0".parse().unwrap());
        assert_eq!(ip.mask(0).unwrap(), "0.0.0.0".parse().unwrap());
        assert!(ip.mask(33).is_err());
    }

    #[test]
    fn ipv6_mask() {
        let mut ip6: Ipv6Addr = "fd01:dead:beef::1".parse().unwrap();
        let mut ip6_prefix = "fd01:dead:beef::".parse().unwrap();
        assert_eq!(ip6.mask(64).unwrap(), ip6_prefix);

        ip6 = "fe80::8:20ff:fe35:f794".parse().unwrap();
        ip6_prefix = "fe80::".parse().unwrap();
        assert_eq!(ip6.mask(10).unwrap(), ip6_prefix);

        ip6 = "fe80::8:20ff:fe35:f794".parse().unwrap();
        assert_eq!(ip6.mask(128).unwrap(), ip6);

        ip6 = "fd00:1122:3344:0201::".parse().unwrap();
        ip6_prefix = "fd00:1122:3344:0200::".parse().unwrap();
        assert_eq!(ip6.mask(56).unwrap(), ip6_prefix);

        let ip6 = Ipv6Addr::from([1; 16]);
        assert_eq!(ip6.mask(0).unwrap(), Ipv6Addr::ANY_ADDR);
    }

    #[test]
    fn ipv6_is_default() {
        let cidr = Ipv6Cidr::new_checked(Ipv6Addr::from([1; 16]), 1).unwrap();
        assert!(!cidr.is_default());
        let cidr = Ipv6Cidr::new_checked(Ipv6Addr::from([0; 16]), 1).unwrap();
        assert!(!cidr.is_default());

        let cidr = Ipv6Cidr::new_checked(Ipv6Addr::from([1; 16]), 0).unwrap();
        assert!(cidr.is_default());
        let cidr = Ipv6Cidr::new_checked(Ipv6Addr::from([0; 16]), 0).unwrap();
        assert!(cidr.is_default());
    }

    #[test]
    fn ipv6_prefix_len() {
        for i in 0u8..=128 {
            let len = Ipv6Cidr::new_checked(Ipv6Addr::from([1; 16]), i)
                .unwrap()
                .prefix_len();
            assert_eq!(i, len);
        }
        assert!(Ipv6Cidr::new_checked(Ipv6Addr::from([1; 16]), 129).is_err());
    }

    #[test]
    fn ipv6_cidr_is_member() {
        let cidr: Ipv6Cidr = "fd00:1::1/16".parse().unwrap();
        assert!(cidr.is_member("fd00:1::1".parse().unwrap()));
        assert!(cidr.is_member("fd00:1::10".parse().unwrap()));
        assert!(cidr.is_member("fd00:2::1".parse().unwrap()));

        assert!(!cidr.is_member("fd01:1::1".parse().unwrap()));
        assert!(!cidr.is_member("fd01:1::10".parse().unwrap()));
        assert!(!cidr.is_member("fd01:2::1".parse().unwrap()));
    }

    #[test]
    fn test_ip_addr_from_str() {
        assert_eq!(
            IpAddr::Ip4(Ipv4Addr::from([172, 30, 0, 1])),
            "172.30.0.1".parse().unwrap()
        );
        let bytes = [0xfd00, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(
            IpAddr::Ip6(Ipv6Addr::from(bytes)),
            "fd00::1".parse().unwrap()
        );
    }

    #[test]
    fn test_ip_cidr_from_str() {
        assert_eq!(
            IpCidr::Ip4(
                Ipv4Cidr::new_checked(Ipv4Addr::from([10, 0, 0, 0]), 24)
                    .unwrap()
            ),
            "10.0.0.0/24".parse().unwrap(),
        );
        assert_eq!(
            IpCidr::Ip6(
                Ipv6Cidr::new_checked(
                    Ipv6Addr::from([0xfd00, 0, 0, 0, 0, 0, 0, 1]),
                    64
                )
                .unwrap()
            ),
            "fd00::1/64".parse().unwrap(),
        );
    }

    #[test]
    fn test_ipv6_from_eui64() {
        let mac = MacAddr::from_const([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        let actual = Ipv6Addr::from_eui64(&mac);
        // The locally-administered bit should be set, but otherwise the MAC is
        // just transcribed.
        assert_eq!(actual, "fe80::0302:03ff:fe04:0506".parse().unwrap());
    }

    #[test]
    fn test_ipv6_from_const() {
        assert_eq!(
            Ipv6Addr {
                inner: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            },
            Ipv6Addr::from_const([0xfe80, 0, 0, 0, 0, 0, 0, 0]),
        );
    }

    fn to_ipv6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    #[test]
    fn test_ipv6_is_multicast() {
        assert!(!to_ipv6("fd00::1").is_multicast());
        assert!(to_ipv6("ff00::1").is_multicast());
    }

    #[test]
    fn test_ipv6_multicast_mac() {
        assert!(to_ipv6("fd00::1").multicast_mac().is_none());
        assert_eq!(
            to_ipv6("ff00::0001:0203").multicast_mac().unwrap(),
            MacAddr::from([0x33, 0x33, 0, 1, 2, 3]),
        );
    }

    #[test]
    fn test_ipv6_solicited_node_multicast() {
        let addr = to_ipv6("fd00:abcd:abcd:abcd:abcd:abcd:abcd:abcd");
        let expected = to_ipv6("ff02::1:ffcd:abcd");
        assert_eq!(addr.solicited_node_multicast(), expected);
    }

    #[test]
    fn test_ipv6_admin_scoped_multicast() {
        // Test the three valid administrative scopes
        assert!(to_ipv6("ff04::1").is_admin_scoped_multicast()); // admin-local (0x4)
        assert!(to_ipv6("ff05::1").is_admin_scoped_multicast()); // site-local (0x5)
        assert!(to_ipv6("ff08::1").is_admin_scoped_multicast()); // organization-local (0x8)

        // Test non-admin scoped multicast addresses
        assert!(!to_ipv6("ff01::1").is_admin_scoped_multicast()); // interface-local
        assert!(!to_ipv6("ff02::1").is_admin_scoped_multicast()); // link-local
        assert!(!to_ipv6("ff0e::1").is_admin_scoped_multicast()); // global

        // Test non-multicast addresses
        assert!(!to_ipv6("fd00::1").is_admin_scoped_multicast()); // ULA
        assert!(!to_ipv6("fe80::1").is_admin_scoped_multicast()); // link-local unicast
        assert!(!to_ipv6("2001:db8::1").is_admin_scoped_multicast()); // global unicast
    }

    #[test]
    fn dhcp_fqdn() {
        let no_host = DhcpCfg { hostname: None, ..Default::default() };
        let only_host =
            DhcpCfg { hostname: "mybox".parse().ok(), ..Default::default() };
        let with_domain = DhcpCfg {
            host_domain: "oxide.computer".parse().ok(),
            ..only_host.clone()
        };
        let domain_no_host = DhcpCfg {
            host_domain: "oxide.computer".parse().ok(),
            ..no_host.clone()
        };

        let mut space = vec![];

        no_host.push_fqdn(&mut space);
        assert!(space.is_empty());

        only_host.push_fqdn(&mut space);
        assert_eq!(&space, "\x05mybox\x00".as_bytes());

        space.clear();
        with_domain.push_fqdn(&mut space);
        assert_eq!(&space, "\x05mybox\x05oxide\x08computer\x00".as_bytes());

        space.clear();
        domain_no_host.push_fqdn(&mut space);
        assert!(space.is_empty());
    }
}
