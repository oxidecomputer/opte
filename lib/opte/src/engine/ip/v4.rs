// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! IPv4 headers.

use crate::engine::checksum::Checksum;
use crate::engine::packet::MismatchError;
use crate::engine::packet::ParseError;
use crate::engine::predicate::MatchExact;
use crate::engine::predicate::MatchExactVal;
use crate::engine::predicate::MatchPrefix;
use crate::engine::predicate::MatchPrefixVal;
use crate::engine::predicate::MatchRangeVal;
use ingot::ip::Ecn;
use ingot::ip::IpProtocol;
use ingot::ip::Ipv4Flags;
use ingot::types::primitives::*;
use ingot::types::Emit;
use ingot::types::Header;
use ingot::types::HeaderLen;
use ingot::types::Vec;
use ingot::Ingot;
pub use opte_api::Ipv4Addr;
pub use opte_api::Ipv4Cidr;
pub use opte_api::Ipv4PrefixLen;
pub use opte_api::Protocol;
use serde::Deserialize;
use serde::Serialize;
use zerocopy::ByteSlice;
use zerocopy::ByteSliceMut;
use zerocopy::IntoBytes;

#[derive(Clone, Debug, Eq, Hash, PartialEq, Ingot)]
#[ingot(impl_default)]
pub struct Ipv4 {
    #[ingot(default = 4)]
    pub version: u4,
    #[ingot(default = 5)]
    pub ihl: u4,
    pub dscp: u6,
    #[ingot(is = "u2")]
    pub ecn: Ecn,
    pub total_len: u16be,

    pub identification: u16be,
    #[ingot(is = "u3")]
    pub flags: Ipv4Flags,
    pub fragment_offset: u13be,

    #[ingot(default = 128)]
    pub hop_limit: u8,
    #[ingot(is = "u8", next_layer)]
    pub protocol: IpProtocol,
    pub checksum: u16be,

    #[ingot(is = "[u8; 4]", default = Ipv4Addr::ANY_ADDR)]
    pub source: Ipv4Addr,
    #[ingot(is = "[u8; 4]", default = Ipv4Addr::ANY_ADDR)]
    pub destination: Ipv4Addr,

    #[ingot(var_len = "(ihl * 4).saturating_sub(20)")]
    pub options: Vec<u8>,
}

impl Ipv4 {
    #[inline]
    pub fn compute_checksum(&mut self) {
        self.checksum = 0;

        let mut csum = Checksum::new();

        let mut bytes = [0u8; 56];
        self.emit_raw(&mut bytes[..]);
        csum.add_bytes(&bytes[..]);

        self.checksum = csum.finalize_for_ingot();
    }
}

impl<V: ByteSliceMut> ValidIpv4<V> {
    #[inline]
    pub fn compute_checksum(&mut self) {
        self.set_checksum(0);

        let mut csum = Checksum::new();

        csum.add_bytes(self.0.as_bytes());

        match &self.1 {
            Header::Repr(opts) => {
                csum.add_bytes(&*opts);
            }
            Header::Raw(opts) => {
                csum.add_bytes(&*opts);
            }
        }

        self.set_checksum(csum.finalize_for_ingot());
    }
}

impl<V: ByteSlice> ValidIpv4<V> {
    #[inline]
    pub fn validate(&self, bytes_after: usize) -> Result<(), ParseError> {
        let v = self.version();
        if self.version() != 4 {
            return Err(ParseError::IllegalValue(MismatchError {
                location: c"Ipv4.version",
                expected: 4,
                actual: v as u64,
            }));
        }

        let own_len = self.packet_length();
        let ihl = self.ihl();
        let expt_ihl = (own_len >> 2) as u8;
        if expt_ihl != ihl {
            return Err(ParseError::IllegalValue(MismatchError {
                location: c"Ipv4.ihl",
                expected: expt_ihl as u64,
                actual: ihl as u64,
            }));
        }

        // Packets can have arbitrary zero-padding at the end so
        // our length *could* be larger than the packet reports.
        // Unlikely in practice as Encap headers push us past the 64B
        // minimum packet size.
        let expt_internal_len = (self.ihl() as usize) << 2;
        if (self.total_len() as usize) < expt_internal_len {
            return Err(ParseError::BadLength(MismatchError {
                location: c"Ipv4.total_len(min)",
                expected: expt_internal_len as u64,
                actual: self.total_len() as u64,
            }));
        }

        // Packets can have arbitrary zero-padding at the end so
        // our length *could* be larger than the packet reports.
        // Unlikely in practice as Encap headers push us past the 64B
        // minimum packet size.
        let expt_total_len = bytes_after + own_len;
        if expt_total_len < self.total_len() as usize {
            return Err(ParseError::BadLength(MismatchError {
                location: c"Ipv4.total_len",
                expected: expt_total_len as u64,
                actual: self.total_len() as u64,
            }));
        }

        Ok(())
    }
}

impl MatchPrefixVal for Ipv4Cidr {}
impl MatchExactVal for Ipv4Addr {}
impl MatchRangeVal for Ipv4Addr {}

impl MatchExact<Ipv4Addr> for Ipv4Addr {
    fn match_exact(&self, val: &Ipv4Addr) -> bool {
        *self == *val
    }
}

impl MatchPrefix<Ipv4Cidr> for Ipv4Addr {
    fn match_prefix(&self, prefix: &Ipv4Cidr) -> bool {
        prefix.is_member(*self)
    }
}

impl MatchExactVal for Protocol {}

impl MatchExact<Protocol> for Protocol {
    fn match_exact(&self, val: &Protocol) -> bool {
        *self == *val
    }
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct Ipv4Push {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub proto: Protocol,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Ipv4Mod {
    pub src: Option<Ipv4Addr>,
    pub dst: Option<Ipv4Addr>,
    pub proto: Option<Protocol>,
}

#[cfg(test)]
mod test {
    use super::*;

    use ingot::types::HeaderLen;

    pub const DEF_ROUTE: &str = "0.0.0.0/0";

    #[test]
    fn match_check() {
        let ip = "192.168.2.11".parse::<Ipv4Addr>().unwrap();
        assert!(ip.match_exact(&ip));
        assert!(ip.match_prefix(&"192.168.2.0/24".parse::<Ipv4Cidr>().unwrap()));
    }

    #[test]
    fn cidr_match() {
        let ip1 = "192.168.2.22".parse::<Ipv4Addr>().unwrap();
        let cidr1 = "192.168.2.0/24".parse().unwrap();
        assert!(ip1.match_prefix(&cidr1));

        let ip2 = "10.7.7.7".parse::<Ipv4Addr>().unwrap();
        let cidr2 = "10.0.0.0/8".parse().unwrap();
        assert!(ip2.match_prefix(&cidr2));

        let ip3 = "52.10.128.69".parse::<Ipv4Addr>().unwrap();
        let cidr3 = DEF_ROUTE.parse().unwrap();
        assert!(ip3.match_prefix(&cidr3));
    }

    #[test]
    fn emit() {
        let ip = Ipv4 {
            source: Ipv4Addr::from([10, 0, 0, 54]),
            destination: Ipv4Addr::from([52, 10, 128, 69]),
            protocol: IpProtocol::TCP,
            flags: Ipv4Flags::DONT_FRAGMENT,
            hop_limit: 64,
            identification: 2662,
            ihl: 5,
            total_len: 60,

            ..Default::default()
        };

        let len = ip.packet_length();
        assert_eq!(len, 20);

        let bytes = ip.emit_vec();
        assert_eq!(len, bytes.len());

        #[rustfmt::skip]
        let expected_bytes = vec![
            // version + IHL
            0x45,
            // DSCP + ECN
            0x00,
            // total length
            0x00, 0x3C,
            // ident
            0x0A, 0x66,
            // flags + frag offset
            0x40, 0x00,
            // TTL
            0x40,
            // protocol
            0x06,
            // checksum
            0x00, 0x00,
            // source
            0x0A, 0x00, 0x00, 0x36,
            // dest
            0x34, 0x0A, 0x80, 0x45,
        ];
        assert_eq!(&expected_bytes, &bytes);
    }
}
