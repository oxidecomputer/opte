use std::convert::From;
use std::mem;
use std::prelude::v1::*;

use serde::{Deserialize, Serialize};

use crate::ether::{EtherHdrRaw, ETHER_TYPE_IPV4};
use crate::headers::{
    csum_incremental, EtherMeta, GeneveMeta, IcmpDuMeta, IcmpEchoMeta, IpMeta,
    Ipv4Meta, TcpMeta, UdpMeta, UlpMeta,
};
use crate::icmp::{
    IcmpBaseHdrRaw, IcmpDuHdrRaw, IcmpEchoHdrRaw, ICMP_DEST_UNREACHABLE,
    ICMP_ECHO, ICMP_ECHO_REPLY,
};
use crate::input::PacketReader;
use crate::ip4::{Ipv4HdrRaw, Protocol};
use crate::tcp::TcpHdrRaw;
use crate::udp::UdpHdrRaw;

#[derive(
    Clone,
    Debug,
    Default,
    Deserialize,
    Eq,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
pub struct PacketMeta {
    pub outer_ether: Option<EtherMeta>,
    pub outer_ip: Option<IpMeta>,
    pub outer_udp: Option<UdpMeta>,
    // TODO Don't forget to add ability to put INT data in Geneve
    pub outer_geneve: Option<GeneveMeta>,
    pub inner_ether: Option<EtherMeta>,
    pub inner_ip: Option<IpMeta>,
    pub ulp: Option<UlpMeta>,
}

impl PacketMeta {
    fn new() -> Self {
        PacketMeta::default()
    }
}

// TODO: Once we have encap/decap support we will want to rename this
// `parse_out()`. Then create a `parse_in()` which fill out `outer_`
// fields first, then calls this function.x
pub fn parse<R: PacketReader>(rdr: &mut R) -> PacketMeta {
    let mut meta = PacketMeta::new();

    let ether_raw = match EtherHdrRaw::parse::<R>(rdr) {
        Ok(raw) => raw,
        Err(e) => {
            // TODO: return error
            todo!("error parsing ether header: {:?}", e);
        }
    };

    let ether_meta = EtherMeta::from(&ether_raw);
    meta.inner_ether = Some(ether_meta);

    match u16::from_be_bytes(ether_raw.ether_type) {
        ETHER_TYPE_IPV4 => parse_ipv4(rdr, meta),

        _ => {
            todo!(
                "implement parse for EtherType: 0x{:X}",
                u16::from_be_bytes(ether_raw.ether_type)
            );
        }
    }
}

fn parse_ipv4<R>(rdr: &mut R, mut meta: PacketMeta) -> PacketMeta
where
    R: PacketReader,
{
    let ip4_raw = match Ipv4HdrRaw::parse::<R>(rdr) {
        Ok(raw) => raw,
        Err(e) => {
            // TODO return errorx
            todo!("error parsing ipv4 header: {:?}", e);
        }
    };

    let ip4_meta = Ipv4Meta::from(&ip4_raw);
    let proto = ip4_meta.proto;
    let ip_meta = IpMeta::from(ip4_meta);
    meta.inner_ip = Some(ip_meta);

    match proto {
        Protocol::TCP => parse_tcp(rdr, meta),
        Protocol::UDP => parse_udp(rdr, meta),
        Protocol::ICMP => parse_icmp(rdr, meta),
        _ => meta,
    }
}

fn parse_icmp<R>(rdr: &mut R, mut meta: PacketMeta) -> PacketMeta
where
    R: PacketReader,
{
    let icmp_base_raw = match IcmpBaseHdrRaw::parse::<R>(rdr) {
        Ok(raw) => raw,
        Err(e) => {
            // TODO return error
            todo!("error parsing ICMP header: {:?}", e);
        }
    };

    match icmp_base_raw.icmp_type {
        ICMP_ECHO_REPLY | ICMP_ECHO => {
            rdr.seek_back(mem::size_of::<IcmpBaseHdrRaw>())
                .expect("failed to seek_back");
            match IcmpEchoHdrRaw::parse::<R>(rdr) {
                Ok(raw) => {
                    let icmp_echo_meta = IcmpEchoMeta::from(&raw);
                    let ulp_meta = UlpMeta::from(icmp_echo_meta);
                    meta.ulp = Some(ulp_meta);
                    meta
                }

                // TODO return error
                Err(e) => todo!("error parsing ICMP echo: {:?}", e),
            }
        }

        ICMP_DEST_UNREACHABLE => {
            rdr.seek_back(mem::size_of::<IcmpBaseHdrRaw>())
                .expect("failed to seek_back");
            match IcmpDuHdrRaw::parse::<R>(rdr) {
                Ok(raw) => {
                    let icmp_du_meta = IcmpDuMeta::from(&raw);
                    let ulp_meta = UlpMeta::from(icmp_du_meta);
                    meta.ulp = Some(ulp_meta);
                    meta
                }

                Err(e) => todo!("error parsing ICMP DU: {:?}", e),
            }
        }

        msg_type => {
            todo!("implement parse_icmp() for type: {}", msg_type);
        }
    }
}

fn parse_tcp<R>(rdr: &mut R, mut meta: PacketMeta) -> PacketMeta
where
    R: PacketReader,
{
    let tcp_raw = match TcpHdrRaw::parse::<R>(rdr) {
        Ok(raw) => raw,
        Err(_err) => {
            // TODO This should be an SDT probe as well.
            // TODO This should be a kstat.
            // dbg(format!("error parsing TCP header: {:?}", err));
            // return Err(L4MetaError::BadHeader);
            todo!("parse_tcp() return result");
        }
    };

    let tcp_meta = TcpMeta::from(&tcp_raw);
    let ulp_meta = UlpMeta::from(tcp_meta);
    meta.ulp = Some(ulp_meta);
    meta
}

fn parse_udp<R>(rdr: &mut R, mut meta: PacketMeta) -> PacketMeta
where
    R: PacketReader,
{
    let udp_raw = match UdpHdrRaw::parse::<R>(rdr) {
        Ok(raw) => raw,
        Err(_err) => {
            // TODO This should be an SDT probe as well.
            // TODO This should be a kstat.
            // dbg(format!("error parsing TCP header: {:?}", err));
            // return Err(L4MetaError::BadHeader);
            todo!("parse_udp() return result");
        }
    };

    let udp_meta = UdpMeta::from(&udp_raw);
    let ulp_meta = UlpMeta::from(udp_meta);
    meta.ulp = Some(ulp_meta);
    meta
}

#[test]
fn parse_guest_out() {
    use crate::input::{VecPacket, VecPacketReader};
    use crate::ip4::Ipv4Addr;
    use crate::layer::{InnerFlowId, IpAddr};
    use std::convert::TryFrom;

    #[rustfmt::skip]
    let bytes = [
        // Ethernet Header
        0x78, 0x23, 0xae, 0x5d, 0x4f, 0x0d,
        0xa8, 0x40, 0x25, 0x00, 0x00, 0x63,
        0x08, 0x00,

        // IPv4 Header
        0x45, 0x00, 0x00, 0x3c, 0xf2, 0x11,
        0x40, 0x00, 0x40, 0x06, 0x27, 0x03,
        0x0a, 0x00, 0x00, 0x63, 0x22, 0xd7,
        0xf4, 0x6d,

        // TCP Header
        0x0f, 0xb5, 0x01, 0xbb, 0x0c, 0xab,
        0x91, 0x08, 0x00, 0x00, 0x00, 0x00,
        0xa0, 0x02, 0xfa, 0xf0, 0x56, 0xc5,
        0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
        0x04, 0x02, 0x08, 0x0a, 0x46, 0x4e,
        0xdf, 0x30, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x03, 0x03, 0x07,
    ];

    let src_ip = "10.0.0.99".parse::<Ipv4Addr>().unwrap();
    let dst_ip = "34.215.244.109".parse::<Ipv4Addr>().unwrap();

    let mut pkt = VecPacket::copy_slice(&bytes);
    let mut rdr = VecPacketReader::new(&mut pkt);
    let meta = parse(&mut rdr);
    let ifid = InnerFlowId::try_from(&meta).unwrap();

    assert_eq!(ifid.proto, Protocol::TCP);
    let ifid_src_ip = match ifid.src_ip {
        IpAddr::Ip4(v) => v,
        _ => panic!("expect IPv4"),
    };
    assert_eq!(ifid_src_ip, src_ip);
    let ifid_dst_ip = match ifid.dst_ip {
        IpAddr::Ip4(v) => v,
        _ => panic!("expect IPv4"),
    };
    assert_eq!(ifid_dst_ip, dst_ip);
    assert_eq!(ifid.src_port, 4021);
    assert_eq!(ifid.dst_port, 443);

    assert_eq!(
        meta.inner_ether.as_ref().unwrap().src,
        [0xa8, 0x40, 0x25, 0x00, 0x00, 0x63]
    );
    assert_eq!(
        meta.inner_ether.as_ref().unwrap().dst,
        [0x78, 0x23, 0xae, 0x5d, 0x4f, 0x0d]
    );

    let ip4_meta = match meta.inner_ip.as_ref().unwrap() {
        IpMeta::Ip4(v) => v,
        _ => panic!("expect Ipv4Meta"),
    };

    assert_eq!(ip4_meta.src, src_ip);
    assert_eq!(ip4_meta.dst, dst_ip);
    assert_eq!(ip4_meta.proto, Protocol::TCP);

    let tcp_meta = match meta.ulp.as_ref().unwrap() {
        UlpMeta::Tcp(v) => v,
        _ => panic!("expect TcpMeta"),
    };

    assert_eq!(tcp_meta.src, 4021);
    assert_eq!(tcp_meta.dst, 443);
    assert_eq!(tcp_meta.flags, 2);
}

// It's easy to become confused by endianess and networking code when
// looking at code that deals with checksums; it's worth making clear
// what is going on.
//
// Any logical value stored in a network header (or application data
// for that matter) needs to consider endianess. That is, a multi-byte
// value like an IP header's "total length" or TCP's "port", which has
// a logical value like "total length = 60" or "port = 443", needs to
// make sure its value is interpreted correctly no matter which byte
// order the underlying hardware uses. To this effect, all logical
// values sent across the network are sent in "network order" (big
// endian) and then adjusted accordingly on the host. In an AMD64 arch
// you will see network code which calls `hton{s,l}()` in order to
// convert the logical value in memory to the correct byte order for
// the network. However, not all values have a logical, numerial
// meaning. For example, a mac address is made up of 6 consecutive
// bytes, for which the order is important, but this string of bytes
// is never interpreted as an integer. Thus, there is no conversion to
// be made: the bytes are in the same order in the network as they are
// in memory (because they are just that, a sequence of bytes). The
// same goes for the various checksums. The internet checksum is just
// a sequence of two bytes. However, in order to implement the
// checksum (one's complement sum), we happen to treat these two bytes
// as a 16-bit integer, and the sequence of bytes to be summed as a
// set of 16-bit integers. Because of this it's easy to think of the
// checksum as a logical value when it's really not. This brings us to
// the point: you never perform byte-order conversion on the checksum
// field. You treat each pair of bytes (both the checksum field
// itself, and the bytes you are summing) as if it's a native 16-bit
// integer. Yes, this means that on a little-endian architecture you
// are logically flipping the bytes, but as the bytes being summed are
// all in network-order, you are also storing them in network-order
// when you write the final sum to memory.
//
// While said a slightly different way, this is also covered in RFC
// 1071 §1.B.
//
// > Therefore, the sum may be calculated in exactly the same way
// > regardless of the byte order ("big-endian" or "little-endian")
// > of the underlaying hardware.  For example, assume a "little-
// > endian" machine summing data that is stored in memory in network
// > ("big-endian") order.  Fetching each 16-bit word will swap
// > bytes, resulting in the sum [4]; however, storing the result
// > back into memory will swap the sum back into network byte order.
//
// TODO: Not sure this is where this function should live, just
// putting it here for now since it's kinda-sorta the dual of parse().
//
// TODO: It's pretty odd that we are using a "reader" to perform
// modification (this code was written in a rush to test PoC). We
// should add a PacketWriter trait as well and use that instead.
pub fn set_headers<R: PacketReader>(meta: &PacketMeta, mut rdr: R) {
    // For the moment we assume any header modification starts at the
    // beginning of the buffer. This prevents passing an already
    // offset reader, which could result in corrupted packets. This
    // restriction may change in the future.
    if rdr.get_pos() != 0 {
        panic!(
            "attempting to modify headers starting at non-zero offset: {}",
            rdr.get_pos()
        );
    }

    let mut ether = match EtherHdrRaw::parse_mut::<R>(&mut rdr) {
        Ok(v) => v,
        Err(err) => {
            crate::dbg(format!("error reading ether header: {:?}", err));
            return;
        }
    };

    ether.src = meta.inner_ether.as_ref().unwrap().src;
    ether.dst = meta.inner_ether.as_ref().unwrap().dst;
    drop(ether);

    let mut ip4 = match Ipv4HdrRaw::parse_mut::<R>(&mut rdr) {
        Ok(v) => v,
        Err(e) => {
            crate::dbg(format!("error reading IPv4 header: {:?}", e));
            return;
        }
    };

    // We stash these here because we need them for the pseudo-header
    // checksum update for the ULP.
    let old_ip_src = ip4.src;
    let old_ip_dst = ip4.dst;
    let (new_ip_src, new_ip_dst, proto) = match meta.inner_ip.as_ref().unwrap()
    {
        IpMeta::Ip4(v) => (v.src.to_be_bytes(), v.dst.to_be_bytes(), v.proto),
        _ => panic!("unexpected IPv6 in set_headers"),
    };

    let mut csum: u32 = (!u16::from_ne_bytes(ip4.csum)) as u32;
    csum_incremental(
        &mut csum,
        u16::from_ne_bytes([ip4.src[0], ip4.src[1]]),
        u16::from_ne_bytes([new_ip_src[0], new_ip_src[1]]),
    );
    csum_incremental(
        &mut csum,
        u16::from_ne_bytes([ip4.src[2], ip4.src[3]]),
        u16::from_ne_bytes([new_ip_src[2], new_ip_src[3]]),
    );
    csum_incremental(
        &mut csum,
        u16::from_ne_bytes([ip4.dst[0], ip4.dst[1]]),
        u16::from_ne_bytes([new_ip_dst[0], new_ip_dst[1]]),
    );
    csum_incremental(
        &mut csum,
        u16::from_ne_bytes([ip4.dst[2], ip4.dst[3]]),
        u16::from_ne_bytes([new_ip_dst[2], new_ip_dst[3]]),
    );
    assert_eq!(csum & 0xFFFF_0000, 0);

    ip4.src = new_ip_src;
    ip4.dst = new_ip_dst;
    // Note: We do not convert the endianess of the checksum because
    // the sum was computed in network order. If you change this to
    // `to_be_bytes()`, you will break the checksum.
    ip4.csum = (!(csum as u16)).to_ne_bytes();

    drop(ip4);

    match proto {
        Protocol::UDP => {
            let mut udp = match UdpHdrRaw::parse_mut::<R>(&mut rdr) {
                Ok(udp) => udp,
                Err(err) => {
                    crate::dbg(format!("error parsing UDP header: {:?}", err));
                    return;
                }
            };

            let (new_sport, new_dport) = match meta.ulp.as_ref().unwrap() {
                UlpMeta::Udp(v) => (v.src.to_be_bytes(), v.dst.to_be_bytes()),
                _ => panic!("ULP data doesn't match IP protocol"),
            };
            let mut csum: u32 = (!u16::from_ne_bytes(udp.csum)) as u32;

            // Update pseudo-header checksum.
            csum_incremental(
                &mut csum,
                u16::from_ne_bytes([old_ip_src[0], old_ip_src[1]]),
                u16::from_ne_bytes([new_ip_src[0], new_ip_src[1]]),
            );
            csum_incremental(
                &mut csum,
                u16::from_ne_bytes([old_ip_src[2], old_ip_src[3]]),
                u16::from_ne_bytes([new_ip_src[2], new_ip_src[3]]),
            );
            csum_incremental(
                &mut csum,
                u16::from_ne_bytes([old_ip_dst[0], old_ip_dst[1]]),
                u16::from_ne_bytes([new_ip_dst[0], new_ip_dst[1]]),
            );
            csum_incremental(
                &mut csum,
                u16::from_ne_bytes([old_ip_dst[2], old_ip_dst[3]]),
                u16::from_ne_bytes([new_ip_dst[2], new_ip_dst[3]]),
            );

            // Update UDP checksum.
            csum_incremental(
                &mut csum,
                u16::from_ne_bytes([udp.src_port[0], udp.src_port[1]]),
                u16::from_ne_bytes([new_sport[0], new_sport[1]]),
            );
            csum_incremental(
                &mut csum,
                u16::from_ne_bytes([udp.dst_port[0], udp.dst_port[1]]),
                u16::from_ne_bytes([new_dport[0], new_dport[1]]),
            );
            assert_eq!(csum & 0xFFFF_0000, 0);

            udp.src_port = new_sport;
            udp.dst_port = new_dport;
            udp.csum = (!(csum as u16)).to_ne_bytes();
        }

        Protocol::TCP => {
            let mut tcp = match TcpHdrRaw::parse_mut::<R>(&mut rdr) {
                Ok(tcp) => tcp,
                Err(err) => {
                    crate::dbg(format!("error parsing TCP header: {:?}", err));
                    return;
                }
            };

            let (new_sport, new_dport) = match meta.ulp.as_ref().unwrap() {
                UlpMeta::Tcp(v) => (v.src.to_be_bytes(), v.dst.to_be_bytes()),
                _ => panic!("ULP data doesn't match IP protocol"),
            };
            let mut csum: u32 = (!u16::from_ne_bytes(tcp.csum)) as u32;

            // Update pseudo-header checksum.
            csum_incremental(
                &mut csum,
                u16::from_ne_bytes([old_ip_src[0], old_ip_src[1]]),
                u16::from_ne_bytes([new_ip_src[0], new_ip_src[1]]),
            );
            csum_incremental(
                &mut csum,
                u16::from_ne_bytes([old_ip_src[2], old_ip_src[3]]),
                u16::from_ne_bytes([new_ip_src[2], new_ip_src[3]]),
            );
            csum_incremental(
                &mut csum,
                u16::from_ne_bytes([old_ip_dst[0], old_ip_dst[1]]),
                u16::from_ne_bytes([new_ip_dst[0], new_ip_dst[1]]),
            );
            csum_incremental(
                &mut csum,
                u16::from_ne_bytes([old_ip_dst[2], old_ip_dst[3]]),
                u16::from_ne_bytes([new_ip_dst[2], new_ip_dst[3]]),
            );

            // Update TCP checksum.
            csum_incremental(
                &mut csum,
                u16::from_ne_bytes([tcp.src_port[0], tcp.src_port[1]]),
                u16::from_ne_bytes([new_sport[0], new_sport[1]]),
            );
            csum_incremental(
                &mut csum,
                u16::from_ne_bytes([tcp.dst_port[0], tcp.dst_port[1]]),
                u16::from_ne_bytes([new_dport[0], new_dport[1]]),
            );
            assert_eq!(csum & 0xFFFF_0000, 0);

            tcp.src_port = new_sport;
            tcp.dst_port = new_dport;
            tcp.csum = (!(csum as u16)).to_ne_bytes();
        }

        _ => (),
    }
}
