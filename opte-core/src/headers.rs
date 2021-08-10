use crate::ether::{EtherAddr, EtherHdrRaw};
use crate::icmp::{IcmpDuHdrRaw, IcmpEchoHdrRaw};
use crate::ip4::{Ipv4Addr, Ipv4HdrRaw, Protocol};
use crate::tcp::TcpHdrRaw;
use crate::udp::UdpHdrRaw;

use std::convert::TryFrom;
use std::fmt;

use serde::{Deserialize, Serialize};

use zerocopy::LayoutVerified;

/// Port 0 is reserved by the sockets layer. It is used by clients to
/// indicate they want the operating system to choose a port on their
/// behalf.
pub const DYNAMIC_PORT: u16 = 0;

pub trait PushActionArg {}
pub trait ModActionArg {}

#[derive(
    Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct EtherMeta {
    pub src: EtherAddr,
    pub dst: EtherAddr,
}

impl From<&LayoutVerified<&[u8], EtherHdrRaw>> for EtherMeta {
    fn from(raw: &LayoutVerified<&[u8], EtherHdrRaw>) -> Self {
        EtherMeta { src: raw.src, dst: raw.dst }
    }
}

impl EtherMeta {
    pub fn modify(
        src: Option<EtherAddr>,
        dst: Option<EtherAddr>,
    ) -> HeaderAction<EtherMeta, EtherMetaOpt> {
        HeaderAction::Modify(EtherMetaOpt { src, dst })
    }
}

impl HeaderActionModify<EtherMetaOpt> for EtherMeta {
    fn run_modify(&mut self, spec: &EtherMetaOpt) {
        if spec.src.is_some() {
            self.src = spec.src.unwrap()
        }

        if spec.dst.is_some() {
            self.dst = spec.dst.unwrap()
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EtherMetaOpt {
    src: Option<EtherAddr>,
    dst: Option<EtherAddr>,
}

impl PushActionArg for EtherMeta {}
impl ModActionArg for EtherMetaOpt {}

#[derive(
    Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct Ipv4Meta {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub proto: Protocol,
}

impl Ipv4Meta {
    // TODO: check that at least one field was specified.
    pub fn modify(
        src: Option<Ipv4Addr>,
        dst: Option<Ipv4Addr>,
        proto: Option<Protocol>,
    ) -> HeaderAction<IpMeta, IpMetaOpt> {
        HeaderAction::Modify(Ipv4MetaOpt { src, dst, proto }.into())
    }
}

impl From<&LayoutVerified<&[u8], Ipv4HdrRaw>> for Ipv4Meta {
    fn from(raw: &LayoutVerified<&[u8], Ipv4HdrRaw>) -> Self {
        Ipv4Meta {
            src: u32::from_be_bytes(raw.src).into(),
            dst: u32::from_be_bytes(raw.dst).into(),
            proto: match Protocol::try_from(raw.proto) {
                Ok(v) => v,
                Err(_) => {
                    todo!("deal with protocol: {}", raw.proto);
                }
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Ipv4MetaOpt {
    src: Option<Ipv4Addr>,
    dst: Option<Ipv4Addr>,
    proto: Option<Protocol>,
}

impl ModActionArg for Ipv4MetaOpt {}

impl HeaderActionModify<Ipv4MetaOpt> for Ipv4Meta {
    fn run_modify(&mut self, spec: &Ipv4MetaOpt) {
        if spec.src.is_some() {
            self.src = spec.src.unwrap()
        }

        if spec.dst.is_some() {
            self.dst = spec.dst.unwrap()
        }

        if spec.proto.is_some() {
            self.proto = spec.proto.unwrap()
        }
    }
}

// TODO We haven't actually done any IPv6 work yet, this is just a
// stand in.
#[derive(
    Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct Ipv6Meta {
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub proto: Protocol,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Ipv6MetaOpt {
    src: Option<[u8; 16]>,
    dst: Option<[u8; 16]>,
}

#[derive(
    Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum IpMeta {
    Ip4(Ipv4Meta),
    Ip6(Ipv6Meta),
}

impl From<Ipv4Meta> for IpMeta {
    fn from(ip4: Ipv4Meta) -> Self {
        IpMeta::Ip4(ip4)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum IpMetaOpt {
    Ip4(Ipv4MetaOpt),
    Ip6(Ipv6MetaOpt),
}

impl PushActionArg for IpMeta {}
impl ModActionArg for IpMetaOpt {}

impl From<Ipv4MetaOpt> for IpMetaOpt {
    fn from(ip4: Ipv4MetaOpt) -> Self {
        IpMetaOpt::Ip4(ip4)
    }
}

impl HeaderActionModify<IpMetaOpt> for IpMeta {
    fn run_modify(&mut self, spec: &IpMetaOpt) {
        match (self, spec) {
            (IpMeta::Ip4(ip4_meta), IpMetaOpt::Ip4(ip4_spec)) => {
                ip4_meta.run_modify(&ip4_spec);
            }

            (IpMeta::Ip6(_ip6_meta), IpMetaOpt::Ip6(_ip6_spec)) => {
                todo!("implement IPv6 run_modify()");
            }

            (meta, spec) => {
                panic!("differeing IP meta and spec: {:?} {:?}", meta, spec);
            }
        }
    }
}

#[derive(
    Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct IcmpEchoMeta {
    pub id: u16,
}

impl PushActionArg for IcmpEchoMeta {}

impl IcmpEchoMeta {
    pub fn modify(
        id: Option<u16>,
    ) -> HeaderAction<IcmpEchoMeta, IcmpEchoMetaOpt> {
        HeaderAction::Modify(IcmpEchoMetaOpt { id }.into())
    }
}

impl From<&LayoutVerified<&[u8], IcmpEchoHdrRaw>> for IcmpEchoMeta {
    fn from(raw: &LayoutVerified<&[u8], IcmpEchoHdrRaw>) -> Self {
        IcmpEchoMeta { id: u16::from_be_bytes(raw.id) }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IcmpEchoMetaOpt {
    id: Option<u16>,
}

impl ModActionArg for IcmpEchoMetaOpt {}

impl HeaderActionModify<IcmpEchoMetaOpt> for IcmpEchoMeta {
    fn run_modify(&mut self, spec: &IcmpEchoMetaOpt) {
        if spec.id.is_some() {
            self.id = spec.id.unwrap()
        }
    }
}

#[derive(
    Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct IcmpDuMeta {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
}

impl PushActionArg for IcmpDuMeta {}

// TODO Need to inspect protocol and set port numbers.
impl From<&LayoutVerified<&[u8], IcmpDuHdrRaw>> for IcmpDuMeta {
    fn from(raw: &LayoutVerified<&[u8], IcmpDuHdrRaw>) -> Self {
        let ip4: LayoutVerified<_, Ipv4HdrRaw> =
            LayoutVerified::new(&raw.ip_hdr[..]).unwrap();
        IcmpDuMeta {
            src_ip: u32::from_be_bytes(ip4.src).into(),
            dst_ip: u32::from_be_bytes(ip4.dst).into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IcmpDuMetaOpt {
    src_ip: Option<Ipv4Addr>,
    dst_ip: Option<Ipv4Addr>,
}

impl ModActionArg for IcmpDuMetaOpt {}

#[derive(
    Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct TcpMeta {
    pub src: u16,
    pub dst: u16,
    pub flags: u8,
    pub seq: u32,
    pub ack: u32,
}

impl TcpMeta {
    pub fn has_flag(&self, flag: u8) -> bool {
        (self.flags & flag) != 0
    }

    // TODO: check that at least one field was specified.
    pub fn modify(
        src: Option<u16>,
        dst: Option<u16>,
        flags: Option<u8>,
    ) -> HeaderAction<TcpMeta, TcpMetaOpt> {
        HeaderAction::Modify(TcpMetaOpt { src, dst, flags }.into())
    }
}

impl PushActionArg for TcpMeta {}

impl From<&LayoutVerified<&[u8], TcpHdrRaw>> for TcpMeta {
    fn from(raw: &LayoutVerified<&[u8], TcpHdrRaw>) -> Self {
        TcpMeta {
            src: u16::from_be_bytes(raw.src_port),
            dst: u16::from_be_bytes(raw.dst_port),
            flags: raw.flags,
            seq: u32::from_be_bytes(raw.seq),
            ack: u32::from_be_bytes(raw.ack),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TcpMetaOpt {
    src: Option<u16>,
    dst: Option<u16>,
    flags: Option<u8>,
}

impl ModActionArg for TcpMetaOpt {}

impl HeaderActionModify<TcpMetaOpt> for TcpMeta {
    fn run_modify(&mut self, spec: &TcpMetaOpt) {
        if spec.src.is_some() {
            self.src = spec.src.unwrap()
        }

        if spec.dst.is_some() {
            self.dst = spec.dst.unwrap()
        }

        if spec.flags.is_some() {
            self.flags = spec.flags.unwrap()
        }
    }
}

#[derive(
    Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct UdpMeta {
    pub src: u16,
    pub dst: u16,
}

impl UdpMeta {
    pub fn modify(
        src: Option<u16>,
        dst: Option<u16>,
    ) -> HeaderAction<UdpMeta, UdpMetaOpt> {
        HeaderAction::Modify(UdpMetaOpt { src, dst }.into())
    }
}

impl PushActionArg for UdpMeta {}

impl From<&LayoutVerified<&[u8], UdpHdrRaw>> for UdpMeta {
    fn from(raw: &LayoutVerified<&[u8], UdpHdrRaw>) -> Self {
        UdpMeta {
            src: u16::from_be_bytes(raw.src_port),
            dst: u16::from_be_bytes(raw.dst_port),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UdpMetaOpt {
    src: Option<u16>,
    dst: Option<u16>,
}

impl ModActionArg for UdpMetaOpt {}

impl HeaderActionModify<UdpMetaOpt> for UdpMeta {
    fn run_modify(&mut self, spec: &UdpMetaOpt) {
        if spec.src.is_some() {
            self.src = spec.src.unwrap()
        }

        if spec.dst.is_some() {
            self.dst = spec.dst.unwrap()
        }
    }
}

#[derive(
    Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum UlpMeta {
    IcmpDu(IcmpDuMeta),
    IcmpEcho(IcmpEchoMeta),
    Tcp(TcpMeta),
    Udp(UdpMeta),
}

impl From<IcmpDuMeta> for UlpMeta {
    fn from(icmp: IcmpDuMeta) -> Self {
        UlpMeta::IcmpDu(icmp)
    }
}

impl From<IcmpEchoMeta> for UlpMeta {
    fn from(icmp: IcmpEchoMeta) -> Self {
        UlpMeta::IcmpEcho(icmp)
    }
}

impl From<TcpMeta> for UlpMeta {
    fn from(tcp: TcpMeta) -> Self {
        UlpMeta::Tcp(tcp)
    }
}

impl From<UdpMeta> for UlpMeta {
    fn from(udp: UdpMeta) -> Self {
        UlpMeta::Udp(udp)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum UlpMetaOpt {
    Tcp(TcpMetaOpt),
    Udp(UdpMetaOpt),
}

impl PushActionArg for UlpMeta {}
impl ModActionArg for UlpMetaOpt {}

impl From<TcpMetaOpt> for UlpMetaOpt {
    fn from(tcp: TcpMetaOpt) -> Self {
        UlpMetaOpt::Tcp(tcp)
    }
}

impl From<UdpMetaOpt> for UlpMetaOpt {
    fn from(udp: UdpMetaOpt) -> Self {
        UlpMetaOpt::Udp(udp)
    }
}

#[derive(
    Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct GeneveMeta {
    vni: u32,
}

impl PushActionArg for GeneveMeta {}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneveMetaOpt {
    vni: Option<u32>,
}

impl ModActionArg for GeneveMetaOpt {}

/// The action to take for a particular header transposition.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum HeaderAction<P, M>
where
    P: PushActionArg + fmt::Debug,
    M: ModActionArg + fmt::Debug,
{
    Push(P),
    Pop(),
    Modify(M),
    Ignore,
    NotPresent,
}

impl<P, M> Default for HeaderAction<P, M>
where
    P: PushActionArg + fmt::Debug,
    M: ModActionArg + fmt::Debug,
{
    fn default() -> HeaderAction<P, M> {
        HeaderAction::NotPresent
    }
}

impl<P, M> HeaderAction<P, M>
where
    P: HeaderActionModify<M> + PushActionArg + fmt::Debug,
    M: ModActionArg + fmt::Debug,
{
    pub fn run(&self, meta: &mut Option<P>) {
        match self {
            Self::Modify(arg) => meta.as_mut().unwrap().run_modify(arg),
            Self::Ignore => (),
            action => todo!("implment run() for action {:?}", action),
        }
        return;
    }
}

pub trait HeaderActionModify<M: ModActionArg> {
    fn run_modify(&mut self, mod_spec: &M);
}

// Perform incremental checksum update. It is expected that `csum` is
// the one's complement of the header checksum (i.e.: `!hdr.csum`).
//
// RFC 1624 Computation of the Internet Checksum via Incremental Update
pub fn csum_incremental(csum: &mut u32, old: u16, new: u16) {
    *csum += (!old as u32) + new as u32;
    while (*csum >> 16) != 0 {
        *csum = (*csum >> 16) + (*csum & 0xFFFF);
    }
}

// Test actual NAT-rewrite incremental checksum update scenario.
#[test]
fn csum_nat_rewrite() {
    use zerocopy::AsBytes;

    fn rfc1071_sum(initial: u32, bytes: &[u8]) -> u16 {
        let mut sum = initial;
        let mut len = bytes.len();
        let mut pos = 0;

        while len > 1 {
            sum += (u16::from_ne_bytes([bytes[pos], bytes[pos + 1]])) as u32;
            pos += 2;
            len -= 2;
        }

        if len == 1 {
            sum += bytes[pos] as u32;
        }

        while (sum >> 16) != 0 {
            sum = (sum >> 16) + (sum & 0xFFFF);
        }

        (!sum & 0xFFFF) as u16
    }

    let mut ip4 = Ipv4HdrRaw {
        ver_hdr_len: 0x45,
        dscp_ecn: 0x00,
        total_len: 60u16.to_be_bytes(),
        ident: 16335u16.to_be_bytes(),
        frag_and_flags: [0x40, 0x00],
        ttl: 64,
        proto: 6,
        csum: 0u16.to_be_bytes(),
        src: "10.0.0.210".parse::<Ipv4Addr>().unwrap().to_be_bytes(),
        dst: "52.13.236.190".parse::<Ipv4Addr>().unwrap().to_be_bytes(),
    };
    ip4.csum = rfc1071_sum(0, ip4.as_bytes()).to_ne_bytes();
    assert_ne!(u16::from_be_bytes(ip4.csum), 0);

    let new_ip_src = "10.0.0.99".parse::<Ipv4Addr>().unwrap().to_be_bytes();
    let new_ip_dst = ip4.dst;

    //================================================================
    // The code starting here is from opte-drv
    //================================================================
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
    ip4.csum = (!(csum as u16)).to_ne_bytes();
    //================================================================
    // End of code from opte-drv
    //================================================================

    let check_csum = rfc1071_sum(0, ip4.as_bytes()).to_ne_bytes();
    assert_eq!(check_csum, [0u8; 2]);
}
