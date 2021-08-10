use std::convert::From;
use std::mem;
use std::prelude::v1::*;

use serde::{Deserialize, Serialize};

use crate::ether::{EtherHdrRaw, ETHER_TYPE_IPV4};
use crate::headers::{
    EtherMeta, GeneveMeta, IcmpDuMeta, IcmpEchoMeta, IpMeta, Ipv4Meta, TcpMeta,
    UdpMeta, UlpMeta,
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
        Err(_err) => {
            // dbg(format!("error reading raw ether header: {:?}", err));
            // freemsgchain(mp_chain);
            todo!("return Result");
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
        Err(_e) => {
            // dbg(format!("error reading IPv4 header: {:?}", e));
            // return Err(L4MetaError::BadHeader);
            todo!("return result/error");
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
        Err(_) => {
            todo!("parse_icmp() return result");
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

                Err(_) => todo!("IcmpEchoHdrRaw::parse() return result"),
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

                Err(_) => todo!("IcmpDuHdrRaw::parse() return result"),
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

    let mut pkt = VecPacket::from_slice(&bytes);
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
