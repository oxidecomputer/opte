use super::checksum::Checksum;
use ingot::choice;
use ingot::ethernet::Ethertype;
use ingot::icmp::IcmpV4;
use ingot::icmp::IcmpV4Mut;
use ingot::icmp::IcmpV4Ref;
use ingot::icmp::IcmpV6;
use ingot::icmp::IcmpV6Mut;
use ingot::icmp::IcmpV6Ref;
use ingot::icmp::ValidIcmpV4;
use ingot::icmp::ValidIcmpV6;
use ingot::ip::Ecn;
use ingot::ip::IpProtocol;
use ingot::ip::Ipv4Flags;
use ingot::ip::LowRentV6EhRepr;
use ingot::tcp::Tcp;
use ingot::tcp::TcpMut;
use ingot::tcp::TcpRef;
use ingot::tcp::ValidTcp;
use ingot::types::primitives::*;
use ingot::types::util::Repeated;
use ingot::types::ByteSlice;
use ingot::types::Emit;
use ingot::types::Header;
use ingot::types::NextLayer;
use ingot::types::Vec;
use ingot::udp::Udp;
use ingot::udp::UdpMut;
use ingot::udp::UdpRef;
use ingot::udp::ValidUdp;
use ingot::Ingot;
use opte_api::Ipv4Addr;
use opte_api::Ipv6Addr;
use opte_api::MacAddr;
use zerocopy::ByteSliceMut;
use zerocopy::IntoBytes;

// Redefine Ethernet and v4/v6 because we have our own, internal,
// address types already.

#[choice(on = Ethertype)]
pub enum L3 {
    Ipv4 = Ethertype::IPV4,
    Ipv6 = Ethertype::IPV6,
}

impl<V: ByteSlice> L3<V> {
    pub fn pseudo_header(&self) -> Checksum {
        match self {
            L3::Ipv4(v4) => {
                let mut pseudo_hdr_bytes = [0u8; 12];
                pseudo_hdr_bytes[0..4].copy_from_slice(v4.source().as_ref());
                pseudo_hdr_bytes[4..8]
                    .copy_from_slice(v4.destination().as_ref());
                pseudo_hdr_bytes[9] = v4.protocol().0;
                let ulp_len = v4.total_len() - 4 * (v4.ihl() as u16);
                pseudo_hdr_bytes[10..].copy_from_slice(&ulp_len.to_be_bytes());

                Checksum::compute(&pseudo_hdr_bytes)
            }
            L3::Ipv6(v6) => {
                let mut pseudo_hdr_bytes = [0u8; 40];
                pseudo_hdr_bytes[0..16].copy_from_slice(&v6.source().as_ref());
                pseudo_hdr_bytes[16..32]
                    .copy_from_slice(&v6.destination().as_ref());
                pseudo_hdr_bytes[39] = v6.next_layer().unwrap_or_default().0;
                let ulp_len = v6.payload_len() as u32;
                pseudo_hdr_bytes[32..36]
                    .copy_from_slice(&ulp_len.to_be_bytes());
                Checksum::compute(&pseudo_hdr_bytes)
            }
        }
    }
}

impl<V: ByteSlice> ValidL3<V> {
    pub fn pseudo_header(&self) -> Checksum {
        match self {
            ValidL3::Ipv4(v4) => {
                let mut pseudo_hdr_bytes = [0u8; 12];
                pseudo_hdr_bytes[0..4].copy_from_slice(v4.source().as_ref());
                pseudo_hdr_bytes[4..8]
                    .copy_from_slice(v4.destination().as_ref());
                // pseudo_hdr_bytes[8] reserved
                pseudo_hdr_bytes[9] = v4.protocol().0;
                let ulp_len = v4.total_len() - 4 * (v4.ihl() as u16);
                pseudo_hdr_bytes[10..].copy_from_slice(&ulp_len.to_be_bytes());

                Checksum::compute(&pseudo_hdr_bytes)
            }
            ValidL3::Ipv6(v6) => {
                let mut pseudo_hdr_bytes = [0u8; 40];
                pseudo_hdr_bytes[0..16].copy_from_slice(&v6.source().as_ref());
                pseudo_hdr_bytes[16..32]
                    .copy_from_slice(&v6.destination().as_ref());
                pseudo_hdr_bytes[39] = v6.next_layer().unwrap_or_default().0;
                let ulp_len = v6.payload_len() as u32;
                pseudo_hdr_bytes[32..36]
                    .copy_from_slice(&ulp_len.to_be_bytes());

                Checksum::compute(&pseudo_hdr_bytes)
            }
        }
    }
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

impl<V: ByteSliceMut> L3<V> {
    #[inline]
    pub fn compute_checksum(&mut self) {
        if let L3::Ipv4(ip) = self {
            match ip {
                Header::Repr(ip) => ip.compute_checksum(),
                Header::Raw(ip) => ip.compute_checksum(),
            }
        }
    }
}

impl<V: ByteSliceMut> ValidL3<V> {
    #[inline]
    pub fn compute_checksum(&mut self) {
        if let ValidL3::Ipv4(ip) = self {
            ip.set_checksum(0);

            let mut csum = Checksum::new();
            csum.add_bytes(ip.0.as_bytes());
            match &ip.1 {
                Header::Repr(opts) => {
                    csum.add_bytes(&*opts);
                }
                Header::Raw(opts) => {
                    csum.add_bytes(&*opts);
                }
            }

            ip.set_checksum(csum.finalize_for_ingot());
        }
    }
}

#[choice(on = IpProtocol)]
pub enum L4 {
    Tcp = IpProtocol::TCP,
    Udp = IpProtocol::UDP,
}

#[choice(on = IpProtocol)]
pub enum Ulp {
    Tcp = IpProtocol::TCP,
    Udp = IpProtocol::UDP,
    IcmpV4 = IpProtocol::ICMP,
    IcmpV6 = IpProtocol::ICMP_V6,
}

impl<B: ByteSlice> ValidUlp<B> {
    pub fn csum(&self) -> [u8; 2] {
        match self {
            ValidUlp::Tcp(t) => t.checksum(),
            ValidUlp::Udp(u) => u.checksum(),
            ValidUlp::IcmpV4(i4) => i4.checksum(),
            ValidUlp::IcmpV6(i6) => i6.checksum(),
        }
        .to_be_bytes()
    }
}

impl<B: ByteSliceMut> ValidUlp<B> {
    pub fn compute_checksum(
        &mut self,
        mut body_csum: Checksum,
        l3: &ValidL3<B>,
    ) {
        match self {
            // ICMP4 requires the body_csum *without*
            // the pseudoheader added back in.
            ValidUlp::IcmpV4(i4) => {
                i4.set_checksum(0);
                body_csum.add_bytes(i4.0.as_bytes());
                i4.set_checksum(body_csum.finalize_for_ingot());
            }
            ValidUlp::IcmpV6(i6) => {
                body_csum += l3.pseudo_header();

                i6.set_checksum(0);
                body_csum.add_bytes(i6.0.as_bytes());
                i6.set_checksum(body_csum.finalize_for_ingot());
            }
            ValidUlp::Tcp(tcp) => {
                body_csum += l3.pseudo_header();

                tcp.set_checksum(0);
                body_csum.add_bytes(tcp.0.as_bytes());
                match &tcp.1 {
                    Header::Repr(opts) => {
                        body_csum.add_bytes(&*opts);
                    }
                    Header::Raw(opts) => {
                        body_csum.add_bytes(&*opts);
                    }
                }
                tcp.set_checksum(body_csum.finalize_for_ingot());
            }
            ValidUlp::Udp(udp) => {
                body_csum += l3.pseudo_header();

                udp.set_checksum(0);
                body_csum.add_bytes(udp.0.as_bytes());
                udp.set_checksum(body_csum.finalize_for_ingot());
            }
        }
    }
}

impl<B: ByteSlice> Ulp<B> {
    pub fn src_port(&self) -> Option<u16> {
        match self {
            Ulp::Tcp(t) => Some(t.source()),
            Ulp::Udp(u) => Some(u.source()),
            _ => None,
        }
    }
}

impl<B: ByteSlice> ValidL3<B> {
    pub fn csum(&self) -> [u8; 2] {
        match self {
            ValidL3::Ipv4(i4) => i4.checksum(),
            ValidL3::Ipv6(_) => 0,
        }
        .to_be_bytes()
    }
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Ingot)]
#[ingot(impl_default)]
pub struct Ethernet {
    #[ingot(is = "[u8; 6]")]
    pub destination: MacAddr,
    #[ingot(is = "[u8; 6]")]
    pub source: MacAddr,
    #[ingot(is = "u16be", next_layer)]
    pub ethertype: Ethertype,
}

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
    // #[ingot(payload_len() + packet_len())]
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

#[derive(Debug, Clone, Ingot, Eq, PartialEq)]
#[ingot(impl_default)]
pub struct Ipv6 {
    #[ingot(default = "6")]
    pub version: u4,
    pub dscp: u6,
    #[ingot(is = "u2")]
    pub ecn: Ecn,
    pub flow_label: u20be,

    // #[ingot(payload_len)]
    pub payload_len: u16be,
    #[ingot(is = "u8", next_layer)]
    pub next_header: IpProtocol,
    // #[ingot(default = 128)]
    pub hop_limit: u8,

    #[ingot(is = "[u8; 16]", default = Ipv6Addr::ANY_ADDR)]
    pub source: Ipv6Addr,
    #[ingot(is = "[u8; 16]", default = Ipv6Addr::ANY_ADDR)]
    pub destination: Ipv6Addr,

    #[ingot(subparse(on_next_layer))]
    pub v6ext: Repeated<LowRentV6EhRepr>,
}
