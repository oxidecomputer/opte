// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! IPv6 Headers.

use crate::engine::headers::HeaderActionError;
use crate::engine::packet::MismatchError;
use crate::engine::packet::ParseError;
use crate::engine::predicate::MatchExact;
use crate::engine::predicate::MatchExactVal;
use crate::engine::predicate::MatchPrefix;
use crate::engine::predicate::MatchPrefixVal;
use ingot::ip::Ecn;
use ingot::ip::IpProtocol;
use ingot::ip::IpV6Ext6564Mut;
use ingot::ip::IpV6Ext6564Ref;
use ingot::ip::IpV6ExtFragmentMut;
use ingot::ip::IpV6ExtFragmentRef;
use ingot::ip::LowRentV6EhRepr;
use ingot::ip::ValidLowRentV6Eh;
use ingot::types::primitives::*;
use ingot::types::util::Repeated;
use ingot::types::FieldMut;
use ingot::types::FieldRef;
use ingot::types::Header;
use ingot::types::HeaderLen;
use ingot::types::ParseChoice;
use ingot::Ingot;
pub use opte_api::Ipv6Addr;
pub use opte_api::Ipv6Cidr;
use opte_api::Protocol;
use serde::Deserialize;
use serde::Serialize;
use zerocopy::ByteSlice;
use zerocopy::ByteSliceMut;

pub const DDM_HEADER_ID: u8 = 0xFE;

#[derive(Debug, Clone, Ingot, Eq, PartialEq)]
#[ingot(impl_default)]
pub struct Ipv6 {
    #[ingot(default = "6")]
    pub version: u4,
    pub dscp: u6,
    #[ingot(is = "u2")]
    pub ecn: Ecn,
    pub flow_label: u20be,

    pub payload_len: u16be,
    #[ingot(is = "u8", next_layer)]
    pub next_header: IpProtocol,
    #[ingot(default = 128)]
    pub hop_limit: u8,

    #[ingot(is = "[u8; 16]", default = Ipv6Addr::ANY_ADDR)]
    pub source: Ipv6Addr,
    #[ingot(is = "[u8; 16]", default = Ipv6Addr::ANY_ADDR)]
    pub destination: Ipv6Addr,

    #[ingot(subparse(on_next_layer))]
    pub v6ext: Repeated<LowRentV6EhRepr>,
}

impl MatchExactVal for Ipv6Addr {}
impl MatchPrefixVal for Ipv6Cidr {}

impl MatchExact<Ipv6Addr> for Ipv6Addr {
    fn match_exact(&self, val: &Ipv6Addr) -> bool {
        *self == *val
    }
}

impl MatchPrefix<Ipv6Cidr> for Ipv6Addr {
    fn match_prefix(&self, prefix: &Ipv6Cidr) -> bool {
        prefix.is_member(*self)
    }
}

impl<V: ByteSlice> ValidIpv6<V> {
    #[inline]
    pub fn validate(&self, bytes_after: usize) -> Result<(), ParseError> {
        let v = self.version();
        if self.version() != 6 {
            return Err(ParseError::IllegalValue(MismatchError {
                location: c"Ipv6.version",
                expected: 6,
                actual: v as u64,
            }));
        }

        // Packets can have arbitrary zero-padding at the end so
        // our length *could* be larger than the packet reports.
        // Unlikely in practice as Encap headers push us past the 64B
        // minimum packet size.
        let ex_len = bytes_after + self.1.packet_length();
        let pll = self.payload_len();
        if ex_len < (self.payload_len() as usize) {
            return Err(ParseError::BadLength(MismatchError {
                location: c"Ipv6.payload_len",
                expected: ex_len as u64,
                actual: pll as u64,
            }));
        }

        Ok(())
    }

    pub fn ulp_len(&self) -> usize {
        self.payload_len() as usize - self.1.packet_length()
    }

    pub fn set_ulp_len(&mut self, len: usize)
    where
        V: ByteSliceMut,
    {
        self.set_payload_len((self.1.packet_length() + len) as u16)
    }

    pub fn ext_len(&self) -> usize {
        self.1.packet_length()
    }
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct Ipv6Push {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub proto: Protocol,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Ipv6Mod {
    pub src: Option<Ipv6Addr>,
    pub dst: Option<Ipv6Addr>,
    pub proto: Option<Protocol>,
}

#[inline]
pub fn v6_set_next_header<V: ByteSliceMut>(
    ipp: IpProtocol,
    v6: &mut (impl Ipv6Mut<V> + Ipv6Ref<V>),
) -> Result<(), HeaderActionError> {
    let mut curr_ipp = v6.next_header();
    if curr_ipp.class().is_none() {
        v6.set_next_header(ipp);
        return Ok(());
    }

    match v6.v6ext_mut() {
        FieldMut::Repr(a) => match a.iter_mut().last() {
            Some(LowRentV6EhRepr::IpV6ExtFragment(f)) => {
                f.next_header = ipp;
            }
            Some(LowRentV6EhRepr::IpV6Ext6564(f)) => {
                f.next_header = ipp;
            }
            None => {
                v6.set_next_header(ipp);
            }
        },
        FieldMut::Raw(Header::Repr(a)) => match a.iter_mut().last() {
            Some(LowRentV6EhRepr::IpV6ExtFragment(f)) => {
                f.next_header = ipp;
            }
            Some(LowRentV6EhRepr::IpV6Ext6564(f)) => {
                f.next_header = ipp;
            }
            None => {
                v6.set_next_header(ipp);
            }
        },
        FieldMut::Raw(Header::Raw(a)) => {
            // This would be better done over all `Repeated` in ingot,
            // however making mutable access generic in that case proved
            // challenging. We can just do it manually for now.
            let mut buf = a.as_mut();

            while curr_ipp.class().is_some() {
                let (hdr, nh, rem) =
                    ValidLowRentV6Eh::parse_choice(buf, Some(curr_ipp))
                        .map_err(|_| HeaderActionError::MalformedExtension)?;
                let nh = nh.expect("V6EHs always have a next_header field");
                buf = rem;
                curr_ipp = nh;

                // We're at the last EH -- now we can update the next header.
                if nh.class().is_none() {
                    match hdr {
                        ValidLowRentV6Eh::IpV6ExtFragment(mut f) => {
                            f.set_next_header(ipp);
                        }
                        ValidLowRentV6Eh::IpV6Ext6564(mut f) => {
                            f.set_next_header(ipp);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

#[inline]
pub fn v6_get_next_header<V: ByteSlice>(
    v6: &impl Ipv6Ref<V>,
) -> Result<IpProtocol, HeaderActionError> {
    let curr_ipp = v6.next_header();
    if curr_ipp.class().is_none() {
        return Ok(curr_ipp);
    }

    Ok(match v6.v6ext_ref() {
        FieldRef::Repr(a) => match a.iter().last() {
            Some(LowRentV6EhRepr::IpV6ExtFragment(f)) => f.next_header,
            Some(LowRentV6EhRepr::IpV6Ext6564(f)) => f.next_header,
            None => curr_ipp,
        },
        FieldRef::Raw(Header::Repr(a)) => match a.iter().last() {
            Some(LowRentV6EhRepr::IpV6ExtFragment(f)) => f.next_header,
            Some(LowRentV6EhRepr::IpV6Ext6564(f)) => f.next_header,
            None => curr_ipp,
        },
        FieldRef::Raw(Header::Raw(a)) => match a.iter(Some(curr_ipp)).last() {
            Some(Ok(ValidLowRentV6Eh::IpV6ExtFragment(f))) => f.next_header(),
            Some(Ok(ValidLowRentV6Eh::IpV6Ext6564(f))) => f.next_header(),
            _ => curr_ipp,
        },
    })
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use ingot::ip::IpProtocol as IngotIpProtocol;
    use ingot::types::Accessor;
    use ingot::types::Emit;
    use ingot::types::Header;
    use ingot::types::HeaderParse;
    use itertools::Itertools;
    use smoltcp::wire::IpProtocol;
    use smoltcp::wire::Ipv6Address;
    use smoltcp::wire::Ipv6ExtHeader;
    use smoltcp::wire::Ipv6FragmentHeader;
    use smoltcp::wire::Ipv6FragmentRepr;
    use smoltcp::wire::Ipv6HopByHopHeader;
    use smoltcp::wire::Ipv6HopByHopRepr;
    use smoltcp::wire::Ipv6OptionRepr;
    use smoltcp::wire::Ipv6Packet;
    use smoltcp::wire::Ipv6Repr;
    use smoltcp::wire::Ipv6RoutingHeader;
    use smoltcp::wire::Ipv6RoutingRepr;
    use std::vec::Vec;

    // Test packet size and payload length
    const BUFFER_LEN: usize = 512;
    const PAYLOAD_LEN: usize = 512 - Ipv6::MINIMUM_LENGTH;
    pub(crate) const SUPPORTED_EXTENSIONS: [IpProtocol; 4] = [
        IpProtocol::HopByHop,
        IpProtocol::Ipv6Route,
        IpProtocol::Ipv6Frag,
        IpProtocol::Unknown(DDM_HEADER_ID),
    ];

    #[test]
    fn from_pairs() {
        let ip6 = super::Ipv6Addr::from([
            0x2601, 0x0284, 0x4100, 0xE240, 0x0000, 0x0000, 0xC0A8, 0x01F5,
        ]);

        assert_eq!(
            ip6.bytes(),
            [
                0x26, 0x01, 0x02, 0x84, 0x41, 0x00, 0xE2, 0x40, 0x00, 0x00,
                0x00, 0x00, 0xC0, 0xA8, 0x01, 0xF5
            ]
        );
    }

    fn base_header() -> Ipv6Repr {
        Ipv6Repr {
            src_addr: Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 1),
            dst_addr: Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            next_header: IpProtocol::Tcp,
            payload_len: PAYLOAD_LEN,
            hop_limit: 6,
        }
    }

    fn hop_by_hop_header() -> Ipv6HopByHopRepr<'static> {
        // in 8-octet units, not including the first
        const OPTION_LEN: usize = 1;
        // SmolTCP limits us to 2 max HBH options in its repr.
        // Pad to the next multiple of 8, then one more 8-octet unit.
        // - Ext header takes 2B
        // - PadN(n) takes 2B, then n bytes.
        // => 4 + fill
        const LEN: usize = 4 + OPTION_LEN * 8;
        static OPTIONS: [Ipv6OptionRepr; 1] =
            [Ipv6OptionRepr::PadN(LEN as u8); 1];
        Ipv6HopByHopRepr {
            options: heapless::Vec::from_slice(&OPTIONS).unwrap(),
        }
    }

    fn route_header() -> Ipv6RoutingRepr<'static> {
        // In 8-octet units, not including the first, i.e., this just needs the
        // home address, 128 bits.
        let segments_left = 1;
        let home_address = Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        Ipv6RoutingRepr::Type2 { segments_left, home_address }
    }

    fn fragment_header() -> Ipv6FragmentRepr {
        Ipv6FragmentRepr { frag_offset: 128, more_frags: false, ident: 0x17 }
    }

    // Generate a test packet.
    //
    // This creates a base IPv6 header, and any extension headers with protocols
    // defined by `extensions`. There is always a base header, and the ULP is
    // always defined to be TCP. `extensions` can be empty.
    //
    // This returns the byte array of the packet, plus the size of the entire
    // header, including extensions.
    pub(crate) fn generate_test_packet(
        extensions: &[IpProtocol],
    ) -> (Vec<u8>, usize) {
        // Create a chain of headers, starting with the base. Emit them into
        // byte arrays, to test parsing.
        let mut data = vec![0; BUFFER_LEN];
        let mut header_start = 0;
        let mut next_header_pos = 6;
        let mut header_end = Ipv6::MINIMUM_LENGTH;
        let mut buf = &mut data[header_start..];

        // The base header. The payload length is always the same, but the base
        // protocol may be updated.
        let base = base_header();
        let mut packet = Ipv6Packet::new_checked(&mut buf).unwrap();
        base.emit(&mut packet);

        if extensions.is_empty() {
            // No extensions at all, just base header with a TCP ULP
            return (buf.to_vec(), Ipv6::MINIMUM_LENGTH);
        }

        for extension in extensions {
            // First, update the _previous_ next_header with the type of this
            // extension header. They form a linked-list. We do this first, so
            // that in the case of the first extension header, we're rewriting
            // the `next_header` value in the base header.
            buf[next_header_pos] = u8::from(*extension);

            // For every extension header, the `next_header` is the first octet.
            // That is, the base header is the only one where it's a different
            // position.
            next_header_pos = 0;

            // Grab the remaining packet buffer, from the end of the previous
            // header. This is where we'll start inserting the current extension
            // header.
            buf = &mut data[header_end..];

            // Insert the bytes of each extension header, returning the number
            // of octets written.
            //
            // For each extension header, we need to build the top level ExtHeader
            // and set length manually: this is (inner_len / 8) := the number of
            // 8-byte blocks FOLLOWING the first.
            use IpProtocol::*;
            let mut ext_packet = Ipv6ExtHeader::new_checked(&mut buf).unwrap();
            ext_packet.set_next_header(IpProtocol::Tcp);
            // Temporarily set high enough to give us enough bytes to emit into.
            // XXX: propose a joint emit + set_len for smoltcp.
            ext_packet.set_header_len(3);
            let len = 2 + match extension {
                HopByHop => {
                    let hbh = hop_by_hop_header();
                    let mut hbh_packet = Ipv6HopByHopHeader::new_checked(
                        ext_packet.payload_mut(),
                    )
                    .unwrap();
                    hbh.emit(&mut hbh_packet);
                    hbh.buffer_len()
                }
                Ipv6Frag => {
                    let frag = fragment_header();
                    let mut frag_packet = Ipv6FragmentHeader::new_checked(
                        ext_packet.payload_mut(),
                    )
                    .unwrap();
                    fragment_header().emit(&mut frag_packet);
                    frag.buffer_len()
                }
                Ipv6Route => {
                    let route = route_header();
                    let mut route_packet = Ipv6RoutingHeader::new_checked(
                        ext_packet.payload_mut(),
                    )
                    .unwrap();
                    route.emit(&mut route_packet);
                    route.buffer_len()
                }
                Unknown(x) if x == &DDM_HEADER_ID => {
                    // TODO: actually build DDM ID + Timestamp values here.
                    //       for now we just emit an empty header here.
                    14
                }
                _ => unimplemented!(
                    "Extension header {:#?} unsupported",
                    extension
                ),
            };
            ext_packet.set_header_len(match extension {
                Ipv6Frag => 0,
                _ => u8::try_from((len - 8) / 8).unwrap(),
            });

            // Move the position markers to the new header.
            header_start = header_end;
            header_end += len;
        }

        // Set the last header to point to the ULP
        data[header_start] = u8::from(IpProtocol::Tcp);

        (data, header_end)
    }

    // Test every permuation of the supported extension headers, verifying the
    // computed lengths of:
    //
    // - Payload length
    // - ULP length
    // - Extension header length
    // - Full header length
    #[test]
    fn test_extension_header_lengths_ok() {
        for n_extensions in 0..SUPPORTED_EXTENSIONS.len() {
            for extensions in
                SUPPORTED_EXTENSIONS.into_iter().permutations(n_extensions)
            {
                let (buf, pos) = generate_test_packet(extensions.as_slice());
                let (header, ..) = ValidIpv6::parse(&buf[..]).unwrap();
                assert_all_lengths_ok(&header, pos);
            }
        }
    }

    fn assert_all_lengths_ok<V: ByteSlice>(
        header: &ValidIpv6<V>,
        header_end: usize,
    ) {
        assert_eq!(
            header.packet_length() as usize,
            header_end,
            "Header length does not include all extension headers"
        );
        assert_eq!(
            header.payload_len() as usize,
            PAYLOAD_LEN,
            "Payload length does not include all extension headers",
        );
        assert_eq!(
            header.1.packet_length(),
            header_end - Ipv6::MINIMUM_LENGTH,
            "Extension header size is incorrect",
        );
        assert_eq!(
            header.ulp_len(),
            PAYLOAD_LEN - header.ext_len(),
            "ULP length is not correct"
        );
    }

    #[test]
    fn test_ipv6_addr_match_exact() {
        let addr: Ipv6Addr = "fd00::1".parse().unwrap();
        assert!(addr.match_exact(&addr));
        assert!(!addr.match_exact(&("fd00::2".parse().unwrap())));
    }

    #[test]
    fn test_ipv6_cidr_match_prefix() {
        let cidr: Ipv6Cidr = "fd00::1/16".parse().unwrap();
        let addr: Ipv6Addr = "fd00::1".parse().unwrap();
        assert!(addr.match_prefix(&cidr));

        let addr: Ipv6Addr = "fd00::2".parse().unwrap();
        assert!(addr.match_prefix(&cidr));

        let addr: Ipv6Addr = "fd01::1".parse().unwrap();
        assert!(!addr.match_prefix(&cidr));

        let addr: Ipv6Addr = "fd01::2".parse().unwrap();
        assert!(!addr.match_prefix(&cidr));
    }

    #[test]
    fn emit() {
        let ip = Ipv6 {
            source: Ipv6Addr::from_const([
                0xFE80, 0x0000, 0x0000, 0x0000, 0xBAF8, 0x53FF, 0xFEAF, 0x537D,
            ]),
            destination: Ipv6Addr::from_const([
                0xFE80, 0x000, 0x0000, 0x0000, 0x56BE, 0xF7FF, 0xFE0B, 0x09EC,
            ]),
            next_header: IngotIpProtocol::ICMP_V6,
            hop_limit: 255,
            payload_len: 32,
            ..Default::default()
        };

        let len = ip.packet_length();
        let pkt = ip.emit_vec();
        assert_eq!(len, pkt.len());

        #[rustfmt::skip]
        let expected_bytes = [
            // version + class + label
            0x60, 0x00, 0x00, 0x00,
            // payload len
            0x00, 0x20,
            // next header + hop limit
            0x3A, 0xFF,
            // source address
            0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xBA, 0xF8, 0x53, 0xFF, 0xFE, 0xAF, 0x53, 0x7D,
            // dest address
            0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x56, 0xBE, 0xF7, 0xFF, 0xFE, 0x0B, 0x09, 0xEC,
        ];
        assert_eq!(&expected_bytes, &pkt[..]);
    }

    #[test]
    fn test_set_total_len() {
        // Create a packet with one extension header.
        let (mut buf, _) = generate_test_packet(&[IpProtocol::Ipv6Frag]);
        let (mut header, ..) = ValidIpv6::parse(&mut buf[..]).unwrap();

        // Set the total length to 128.
        //
        // The Payload Length field contains the length of both the extension
        // headers and the actual ULP. Because we have the Fragmentation header,
        // which is a fixed 8-octet thing, this should result in a Payload
        // Length of 128 - Ipv6Hdr::BASE_SIZE = 78.
        const NEW_SIZE: usize = 128;
        header.set_ulp_len(NEW_SIZE);
        assert_eq!(header.ulp_len(), NEW_SIZE);
        assert_eq!(header.packet_length(), Ipv6::MINIMUM_LENGTH + 8);
        assert_eq!(header.payload_len() as usize, NEW_SIZE + 8);
    }

    #[test]
    fn bad_ipv6_version_caught() {
        // This packet was produced due to prior sidecar testing,
        // and put 4B between Eth and IPv6. This should fail to
        // parse 0x00 as a v6 version.
        #[rustfmt::skip]
        let buf: &[u8] = &[
            // Garbage
            0x00, 0xc8, 0x08, 0x00,
            // IPv6
            0x60, 0x00, 0x00, 0x00, 0x02, 0x27, 0x11, 0xfe, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xfd, 0x00, 0x11, 0x22, 0x33, 0x44, 0x01, 0x11, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x17, 0xc1, 0x17, 0xc1,
            0x02, 0x27, 0xcf, 0x4e, 0x01, 0x00, 0x65, 0x58, 0x00, 0x00, 0x64,
            0x00, 0x01, 0x29, 0x00, 0x00, 0xa8, 0x40, 0x25, 0xff, 0xe8, 0x5f,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81, 0x00, 0x45, 0x00, 0x02,
            0x05, 0xe0, 0x80, 0x40, 0x00, 0x37, 0x06, 0x1a, 0x9f, 0xc6, 0xd3,
            0x7a, 0x40, 0x2d, 0x9a, 0xd8, 0x25, 0xa1, 0x22, 0x01, 0xbb, 0xad,
            0x22, 0x51, 0x93, 0xa5, 0xf8, 0x01, 0x58, 0x80, 0x18, 0x01, 0x26,
            0x02, 0x24, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x48, 0xd7, 0x9a,
            0x23, 0x04, 0x31, 0x9f, 0x43, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01,
            0x17, 0x03, 0x03, 0x00, 0x45, 0xf6, 0xcd, 0xe2, 0xc1, 0xe5, 0xa0,
            0x65, 0xa7, 0xfe, 0x29, 0xa8, 0xa2, 0xb0, 0x57, 0x91, 0x7e, 0xac,
            0xc8, 0x34, 0xdd, 0x6b, 0xfa, 0x21,
        ];

        // Parsing this one will fail -- next header is hop-by-hop, which is
        // an RFC6564 header -- we don't have (0xc1 * 8) bytes here!!
        assert!(ValidIpv6::parse(&buf[..]).is_err());

        // We can construct this manually via ingot...
        let (v6, _rem) = Accessor::read_from_prefix(&buf[..]).unwrap();
        let ip = ValidIpv6(v6, Header::Repr(Default::default()));
        assert!(ip.validate(120).is_err());
    }
}
