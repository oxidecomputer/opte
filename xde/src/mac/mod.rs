// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! The mac client abstractions now live in `illumos::mac`; they are
//! re-exported here alongside xde's own offload policy.

pub use illumos::mac::*;

#[derive(Copy, Clone, Debug)]
pub struct OffloadInfo {
    pub cso_state: mac_capab_cso_t,
    pub lso_state: mac_capab_lso_t,
    pub mtu: u32,
}

impl OffloadInfo {
    /// Forwards the underlay's tunnel checksum offload capabilities into
    /// standard capabilities.
    pub fn upstream_csum(&self) -> mac_capab_cso_t {
        let base_capabs = self.cso_state.cso_flags;
        let mut out = mac_capab_cso_t::default();

        if base_capabs.contains(ChecksumOffloadCapabs::TUNNEL_VALID)
            && self.cso_state.cso_tunnel.ct_types.contains(TunnelType::GENEVE)
        {
            let tsco_flags = self.cso_state.cso_tunnel.ct_flags;
            if tsco_flags.contains(TunnelCsoFlags::INNER_IPHDR) {
                out.cso_flags |= ChecksumOffloadCapabs::INET_HDRCKSUM;
            }
            if tsco_flags.contains(
                TunnelCsoFlags::INNER_TCP_PARTIAL
                    | TunnelCsoFlags::INNER_UDP_PARTIAL,
            ) {
                out.cso_flags |= ChecksumOffloadCapabs::INET_PARTIAL;
            }
            if tsco_flags.contains(
                TunnelCsoFlags::INNER_TCP_FULL | TunnelCsoFlags::INNER_UDP_FULL,
            ) {
                out.cso_flags |= ChecksumOffloadCapabs::INET_FULL_V4
                    | ChecksumOffloadCapabs::INET_FULL_V6;
            }
        }

        out
    }

    /// Forwards the underlay's tunnel TCP LSO capabilities into
    /// standard LSO capabilities.
    pub fn upstream_lso(&self) -> mac_capab_lso_t {
        let mut out = mac_capab_lso_t::default();

        if self.lso_state.lso_flags.contains(TcpLsoFlags::TUNNEL_TCP)
            && self
                .lso_state
                .lso_tunnel_tcp
                .tun_types
                .contains(TunnelType::GENEVE)
        {
            out.lso_flags |= TcpLsoFlags::BASIC_IPV4 | TcpLsoFlags::BASIC_IPV6;
            out.lso_basic_tcp_ipv4 = lso_basic_tcp_ipv4_t {
                lso_max: self.lso_state.lso_tunnel_tcp.tun_pay_max,
            };
            out.lso_basic_tcp_ipv6 = lso_basic_tcp_ipv6_t {
                lso_max: self.lso_state.lso_tunnel_tcp.tun_pay_max,
            };
        }

        out
    }

    /// Return the set of capabilities and MTUs compatible across one or more
    /// underlay devices.
    pub fn mutual_capabs(&self, other: &Self) -> Self {
        Self {
            cso_state: mac_capab_cso_t {
                cso_flags: self.cso_state.cso_flags & other.cso_state.cso_flags,
                cso_tunnel: cso_tunnel_t {
                    ct_flags: self.cso_state.cso_tunnel.ct_flags
                        & other.cso_state.cso_tunnel.ct_flags,
                    ct_encap_max: self
                        .cso_state
                        .cso_tunnel
                        .ct_encap_max
                        .min(other.cso_state.cso_tunnel.ct_encap_max),
                    ct_types: self.cso_state.cso_tunnel.ct_types
                        & other.cso_state.cso_tunnel.ct_types,
                },
            },
            lso_state: mac_capab_lso_t {
                lso_flags: self.lso_state.lso_flags & other.lso_state.lso_flags,
                lso_basic_tcp_ipv4: lso_basic_tcp_ipv4_t {
                    lso_max: self
                        .lso_state
                        .lso_basic_tcp_ipv4
                        .lso_max
                        .min(other.lso_state.lso_basic_tcp_ipv4.lso_max),
                },
                lso_basic_tcp_ipv6: lso_basic_tcp_ipv6_t {
                    lso_max: self
                        .lso_state
                        .lso_basic_tcp_ipv6
                        .lso_max
                        .min(other.lso_state.lso_basic_tcp_ipv6.lso_max),
                },
                lso_tunnel_tcp: lso_tunnel_tcp_t {
                    tun_pay_max: self
                        .lso_state
                        .lso_tunnel_tcp
                        .tun_pay_max
                        .min(other.lso_state.lso_tunnel_tcp.tun_pay_max),
                    tun_encap_max: self
                        .lso_state
                        .lso_tunnel_tcp
                        .tun_encap_max
                        .min(other.lso_state.lso_tunnel_tcp.tun_encap_max),
                    tun_flags: self.lso_state.lso_tunnel_tcp.tun_flags
                        & other.lso_state.lso_tunnel_tcp.tun_flags,
                    tun_types: self.lso_state.lso_tunnel_tcp.tun_types
                        & other.lso_state.lso_tunnel_tcp.tun_types,
                    tun_pad: [0; 2],
                },
            },
            mtu: self.mtu.min(other.mtu),
        }
    }
}
