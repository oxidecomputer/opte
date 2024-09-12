use bitflags::bitflags;
use ingot::choice;
use ingot::ethernet::Ethertype;
use ingot::icmp::IcmpV4;
use ingot::icmp::IcmpV6;
use ingot::icmp::ValidIcmpV4;
use ingot::icmp::ValidIcmpV6;
use ingot::ip::Ecn;
use ingot::ip::IpProtocol;
use ingot::ip::Ipv4Flags;
use ingot::ip::LowRentV6EhRepr;
use ingot::tcp::Tcp;
use ingot::tcp::ValidTcp;
use ingot::types::primitives::*;
use ingot::types::NetworkRepr;
use ingot::types::Packet;
use ingot::types::ParseError;
use ingot::types::Repeated;
use ingot::types::Vec;
use ingot::udp::Udp;
use ingot::udp::ValidUdp;
use ingot::Ingot;
use opte_api::Ipv4Addr;
use opte_api::Ipv6Addr;
use opte_api::MacAddr;
use zerocopy::ByteSlice;

// Redefine Ethernet and v4/v6 because we have our own, internal,
// types already.

#[choice(on = Ethertype)]
pub enum L3 {
    Ipv4 = Ethertype::IPV4,
    Ipv6 = Ethertype::IPV6,
}

#[choice(on = IpProtocol)]
pub enum Ulp {
    Tcp = IpProtocol::TCP,
    Udp = IpProtocol::UDP,
    IcmpV4 = IpProtocol::ICMP,
    IcmpV6 = IpProtocol::ICMP_V6,
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

// Why TF do I need to redefine these? Check...
impl<V: ByteSlice, Any> From<ValidIpv4<V>> for Packet<Any, ValidIpv4<V>> {
    fn from(value: ValidIpv4<V>) -> Self {
        Packet::Raw(value)
    }
}

impl<V: ByteSlice, Any> From<ValidIpv6<V>> for Packet<Any, ValidIpv6<V>> {
    fn from(value: ValidIpv6<V>) -> Self {
        Packet::Raw(value)
    }
}
