#![no_std]

// NOTE: Things get weird if you move the extern crate into cfg_if!.
#[cfg(any(feature = "std", test))]
#[macro_use]
extern crate std;

#[cfg(all(not(feature = "std"), not(test)))]
#[macro_use]
extern crate alloc;

#[macro_use]
extern crate cfg_if;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use core::result;
        use alloc::string::String;
        use alloc::vec::Vec;
    } else {
        use std::result;
        use std::str::FromStr;
        use std::string::{String, ToString};
        use std::vec::Vec;
    }
}

use core::fmt::{self, Display};
use serde::{Deserialize, Serialize};

use illumos_sys_hdrs::{c_int, datalink_id_t, size_t};

/// The overall version of the API. Anytmie an API is added, removed,
/// or modified, this number should increment. Currently we attach no
/// semantic meaning to the number other than as a means to verify
/// that the user and kernel are compiled for the same API.
///
/// NOTE: Unfortunately this doesn't automatically catch changes to
/// the API and upate itself. We must be vigilant to increment this
/// number when modifying the API.
///
/// NOTE: A u64 is used to give future wiggle room to play bit games
/// if neeeded.
///
/// NOTE: XXX This method of catching version mismatches is currently
/// soft; better ideas are welcome.
pub const API_VERSION: u64 = 3;

// TODO These two constants belong in xde, not here.
pub const XDE_DLD_PREFIX: i32 = (0xde00u32 << 16) as i32;
pub const XDE_DLD_OPTE_CMD: i32 = XDE_DLD_PREFIX | 7777;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub enum OpteCmd {
    ListPorts = 1,           // list all ports
    AddFwRule = 20,          // add firewall rule
    RemFwRule = 21,          // remove firewall rule
    DumpTcpFlows = 30,       // dump TCP flows
    DumpLayer = 31,          // dump the specified Layer
    DumpUft = 32,            // dump the Unified Flow Table
    ListLayers = 33,         // list the layers on a given port
    ClearUft = 40,           // clear the UFT
    SetVirt2Phys = 50,       // set a v2p mapping
    DumpVirt2Phys = 51,      // dump the v2p mappings
    AddRouterEntryIpv4 = 60, // add a router entry for IPv4 dest
    CreateXde = 70,          // create a new xde device
    DeleteXde = 71,          // delete an xde device
    SetXdeUnderlay = 72,     // set xde underlay devices
}

impl TryFrom<c_int> for OpteCmd {
    type Error = ();

    fn try_from(num: c_int) -> Result<Self, Self::Error> {
        match num {
            1 => Ok(Self::ListPorts),
            20 => Ok(Self::AddFwRule),
            21 => Ok(Self::RemFwRule),
            30 => Ok(Self::DumpTcpFlows),
            31 => Ok(Self::DumpLayer),
            32 => Ok(Self::DumpUft),
            33 => Ok(Self::ListLayers),
            40 => Ok(Self::ClearUft),
            50 => Ok(Self::SetVirt2Phys),
            51 => Ok(Self::DumpVirt2Phys),
            60 => Ok(Self::AddRouterEntryIpv4),
            70 => Ok(Self::CreateXde),
            71 => Ok(Self::DeleteXde),
            72 => Ok(Self::SetXdeUnderlay),
            _ => Err(()),
        }
    }
}

/// Indicates that a command response has been written to the response
/// buffer (`resp_bytes`).
pub const OPTE_CMD_RESP_COPY_OUT: u64 = 0x1;

/// The `ioctl(2)` argument passed when sending an `OpteCmd`.
///
/// We need `repr(C)` for a stable layout across compilations. This is
/// a generic structure used to carry the various commands; the
/// command's actual request/response data is serialized/deserialized
/// by serde into the user supplied pointers in
/// `req_bytes`/`resp_bytes`. In the future, if we need this to work
/// with non-Rust programs in illumos, we could write an nvlist
/// provider that works with serde.
#[derive(Debug)]
#[repr(C)]
pub struct OpteCmdIoctl {
    pub api_version: u64,
    pub cmd: OpteCmd,
    pub flags: u64,
    // Reserve some additional bytes in case we need them in the
    // future.
    pub reserved1: u64,
    pub req_bytes: *const u8,
    pub req_len: size_t,
    pub resp_bytes: *mut u8,
    pub resp_len: size_t,
    pub resp_len_actual: size_t,
}

impl OpteCmdIoctl {
    pub fn cmd_err_resp(&self) -> Option<OpteError> {
        if self.has_cmd_resp() {
            // Safety: We know the resp_bytes point to a Vec and that
            // resp_len_actual is within range.
            let resp = unsafe {
                core::slice::from_raw_parts(
                    self.resp_bytes,
                    self.resp_len_actual,
                )
            };

            match postcard::from_bytes(resp) {
                Ok(cmd_err) => Some(cmd_err),
                Err(deser_err) => {
                    Some(OpteError::DeserCmdErr(format!("{}", deser_err)))
                }
            }
        } else {
            None
        }
    }

    fn has_cmd_resp(&self) -> bool {
        (self.flags & OPTE_CMD_RESP_COPY_OUT) != 0
    }
}

impl OpteCmdIoctl {
    /// Is this the expected API version?
    ///
    /// NOTE: This function is compiled twice: once for the userland
    /// client, again for the kernel driver. As long as we remember to
    /// update the `API_VERSION` value when making API changes, this
    /// method will return `false` when user and kernel disagree.
    pub fn check_version(&self) -> bool {
        self.api_version == API_VERSION
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum OpteError {
    BadApiVersion { user: u64, kernel: u64 },
    BadLayerPos { layer: String, pos: String },
    BadName,
    CopyinReq,
    CopyoutResp,
    DeserCmdErr(String),
    DeserCmdReq(String),
    FlowExists(String),
    InvalidRouteDest(String),
    LayerNotFound(String),
    MaxCapacity(u64),
    PortNotFound(String),
    RespTooLarge { needed: usize, given: usize },
    RuleNotFound(u64),
    SerCmdErr(String),
    SerCmdResp(String),
    System { errno: c_int, msg: String },
}

impl OpteError {
    /// Convert to an errno value.
    ///
    /// NOTE: In order for opteadm `run_cmd_ioctl()` to function
    /// correctly only `RespTooLarge` may use `ENOBUFS`.
    ///
    /// XXX We should probably add the extra code necessary to enforce
    /// this constraint at compile time.
    pub fn to_errno(&self) -> c_int {
        use illumos_sys_hdrs::*;

        match self {
            Self::BadApiVersion { .. } => EPROTO,
            Self::BadLayerPos { .. } => EINVAL,
            Self::BadName => EINVAL,
            Self::CopyinReq => EFAULT,
            Self::CopyoutResp => EFAULT,
            Self::DeserCmdErr(_) => ENOMSG,
            Self::DeserCmdReq(_) => ENOMSG,
            Self::FlowExists(_) => EEXIST,
            Self::InvalidRouteDest(_) => EINVAL,
            Self::LayerNotFound(_) => ENOENT,
            Self::MaxCapacity(_) => ENFILE,
            Self::PortNotFound(_) => ENOENT,
            Self::RespTooLarge { .. } => ENOBUFS,
            Self::RuleNotFound(_) => ENOENT,
            Self::SerCmdErr(_) => ENOMSG,
            Self::SerCmdResp(_) => ENOMSG,
            Self::System { errno, .. } => *errno,
        }
    }
}

/// A marker trait indicating a success response type that is returned
/// from a command and may be passed across the ioctl/API boundary.
pub trait CmdOk: core::fmt::Debug + Serialize {}

impl CmdOk for () {}

// Use this type to indicate no meaningful response value on success.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct NoResp {
    pub unused: u64,
}

impl CmdOk for NoResp {}

/// An IPv4 or IPv6 address.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum IpAddr {
    Ip4(Ipv4Addr),
    Ip6(Ipv6Addr),
}

/// An IPv4 address.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Ipv4Addr {
    inner: [u8; 4],
}

#[cfg(any(feature = "std", test))]
impl From<std::net::Ipv4Addr> for Ipv4Addr {
    fn from(ip4: std::net::Ipv4Addr) -> Self {
        Self { inner: ip4.octets() }
    }
}

#[cfg(any(feature = "std", test))]
impl FromStr for Ipv4Addr {
    type Err = String;

    fn from_str(val: &str) -> result::Result<Self, Self::Err> {
        let ip =
            val.parse::<std::net::Ipv4Addr>().map_err(|e| format!("{}", e))?;
        Ok(ip.into())
    }
}

#[cfg(any(feature = "std", test))]
impl Display for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", std::net::Ipv4Addr::from(self.bytes()))
    }
}

pub const ANY_ADDR: Ipv4Addr = Ipv4Addr { inner: [0; 4] };

impl Ipv4Addr {
    /// Return the bytes of the address.
    pub fn bytes(&self) -> [u8; 4] {
        self.inner
    }

    /// Return the address after applying the network mask.
    pub fn mask(mut self, mask: u8) -> Result<Self, String> {
        if mask > 32 {
            return Err(format!("bad mask: {}", mask));
        }

        if mask == 0 {
            return Ok(ANY_ADDR);
        }

        let mut n = u32::from_be_bytes(self.inner);

        let mut bits = i32::MIN;
        bits = bits >> (mask - 1);
        n = n & bits as u32;
        self.inner = n.to_be_bytes();
        Ok(self)
    }
}

/// An IPv6 address.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Ipv6Addr {
    inner: [u8; 16],
}

#[cfg(any(feature = "std", test))]
impl From<std::net::Ipv6Addr> for Ipv6Addr {
    fn from(ip6: std::net::Ipv6Addr) -> Self {
        Self { inner: ip6.octets() }
    }
}

#[cfg(any(feature = "std", test))]
impl FromStr for Ipv6Addr {
    type Err = String;

    fn from_str(val: &str) -> result::Result<Self, Self::Err> {
        let ip =
            val.parse::<std::net::Ipv6Addr>().map_err(|e| format!("{}", e))?;
        Ok(ip.into())
    }
}

impl Ipv6Addr {
    /// Return the bytes of the address.
    pub fn bytes(&self) -> [u8; 16] {
        self.inner
    }

    /// Return the address after applying the network mask.
    pub fn mask(mut self, mask: u8) -> Result<Self, String> {
        if mask > 128 {
            return Err(format!("bad mask: {}", mask));
        }

        if mask == 128 {
            return Ok(self);
        }

        if mask == 0 {
            for byte in &mut self.inner[0..15] {
                *byte = 0;
            }
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
            self.inner[byte_idx] = self.inner[byte_idx] & bits as u8;
            byte_idx += 1;
        }

        for byte in &mut self.inner[byte_idx..16] {
            *byte = 0;
        }

        Ok(self)
    }
}

/// An IPv4 or IPv6 CIDR.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum IpCidr {
    Ip4(Ipv4Cidr),
    Ip6(Ipv6Cidr),
}

/// An IPv4 CIDR.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Ipv4Cidr {
    ip: Ipv4Addr,
    prefix_len: u8,
}

#[cfg(any(feature = "std", test))]
impl FromStr for Ipv4Cidr {
    type Err = String;

    /// Convert a string like "192.168.2.0/24" into an `Ipv4Cidr`.
    fn from_str(val: &str) -> result::Result<Self, Self::Err> {
        let (ip_s, prefix_s) = match val.split_once("/") {
            Some(v) => v,
            None => return Err(format!("no '/' found")),
        };

        let ip = match ip_s.parse::<std::net::Ipv4Addr>() {
            Ok(v) => v.into(),
            Err(e) => return Err(format!("bad IP: {}", e)),
        };

        let prefix_len = match prefix_s.parse::<u8>() {
            Ok(v) => v,
            Err(e) => {
                return Err(format!("bad prefix length: {}", e));
            }
        };

        Ipv4Cidr::new(ip, prefix_len)
    }
}

#[cfg(any(feature = "std", test))]
impl Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.ip, self.prefix_len)
    }
}

impl Ipv4Cidr {
    pub fn new(ip: Ipv4Addr, prefix_len: u8) -> result::Result<Self, String> {
        // In this case we are only checking that it's a valid CIDR in
        // the general sense; VPC-specific CIDR enforcement is done by
        // the VPC types.
        if prefix_len > 32 {
            return Err(format!("bad prefix length: {}", prefix_len));
        }

        let ip = ip.mask(prefix_len)?;
        Ok(Ipv4Cidr { ip, prefix_len })
    }

    pub fn parts(&self) -> (Ipv4Addr, u8) {
        (self.ip, self.prefix_len)
    }
}

/// An IPv6 CIDR.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Ipv6Cidr {
    ip: Ipv6Addr,
    prefix_len: u8,
}

#[cfg(any(feature = "std", test))]
impl FromStr for Ipv6Cidr {
    type Err = String;

    /// Convert a string like "fd00:dead:beef:cafe::/64" into an [`Ipv6Cidr`].
    fn from_str(val: &str) -> result::Result<Self, Self::Err> {
        let (ip_s, prefix_s) = match val.split_once("/") {
            Some(v) => v,
            None => return Err(format!("no '/' found")),
        };

        let ip = match ip_s.parse::<std::net::Ipv6Addr>() {
            Ok(v) => v.into(),
            Err(e) => return Err(format!("bad IP: {}", e)),
        };

        let prefix_len = match prefix_s.parse::<u8>() {
            Ok(v) => v,
            Err(e) => {
                return Err(format!("bad prefix length: {}", e));
            }
        };

        Ipv6Cidr::new(ip, prefix_len)
    }
}

impl Ipv6Cidr {
    pub fn new(ip: Ipv6Addr, prefix_len: u8) -> result::Result<Self, String> {
        if prefix_len > 128 {
            return Err(format!("bad prefix length: {}", prefix_len));
        }

        let ip = ip.mask(prefix_len)?;
        Ok(Ipv6Cidr { ip, prefix_len })
    }

    pub fn parts(&self) -> (Ipv6Addr, u8) {
        (self.ip, self.prefix_len)
    }
}

#[test]
fn bad_cidr() {
    let ip = "10.0.0.1".parse().unwrap();
    let mut msg = "bad prefix length: 33".to_string();
    assert_eq!(Ipv4Cidr::new(ip, 33), Err(msg.clone()));
    assert_eq!("192.168.2.9/33".parse::<Ipv4Cidr>(), Err(msg.clone()));

    msg = "bad prefix length: 129".to_string();
    let ip6 = "fd01:dead:beef::1".parse().unwrap();
    assert_eq!(Ipv6Cidr::new(ip6, 129), Err(msg.clone()));

    assert_eq!("fd01:dead:beef::1/129".parse::<Ipv6Cidr>(), Err(msg.clone()))
}

#[test]
fn good_cidr() {
    let ip = "192.168.2.0".parse().unwrap();
    assert_eq!(
        Ipv4Cidr::new(ip, 24),
        Ok(Ipv4Cidr {
            ip: Ipv4Addr { inner: [192, 168, 2, 0] },
            prefix_len: 24,
        })
    );

    assert_eq!(
        "192.168.2.0/24".parse(),
        Ok(Ipv4Cidr {
            ip: Ipv4Addr { inner: [192, 168, 2, 0] },
            prefix_len: 24
        })
    );

    assert_eq!(
        "192.168.2.9/24".parse(),
        Ok(Ipv4Cidr {
            ip: Ipv4Addr { inner: [192, 168, 2, 0] },
            prefix_len: 24,
        })
    );

    assert_eq!(
        "192.168.2.9/24".parse::<Ipv4Cidr>().unwrap().to_string(),
        "192.168.2.0/24".to_string()
    );

    let mut ip6_cidr = "fd01:dead:beef::1/64".parse::<Ipv6Cidr>().unwrap();
    let mut ip6_prefix = "fd01:dead:beef::".parse().unwrap();
    assert_eq!(ip6_cidr.parts(), (ip6_prefix, 64));

    ip6_cidr = "fe80::8:20ff:fe35:f794/10".parse::<Ipv6Cidr>().unwrap();
    ip6_prefix = "fe80::".parse().unwrap();
    assert_eq!(ip6_cidr.parts(), (ip6_prefix, 10));

    ip6_cidr = "fe80::8:20ff:fe35:f794/128".parse::<Ipv6Cidr>().unwrap();
    ip6_prefix = "fe80::8:20ff:fe35:f794".parse().unwrap();
    assert_eq!(ip6_cidr.parts(), (ip6_prefix, 128));

    ip6_cidr = "fd00:1122:3344:0201::/56".parse::<Ipv6Cidr>().unwrap();
    ip6_prefix = "fd00:1122:3344:0200::".parse().unwrap();
    assert_eq!(ip6_cidr.parts(), (ip6_prefix, 56));
}

#[test]
fn ip_mask() {
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
}

/// A MAC address.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct MacAddr {
    inner: [u8; 6],
}

impl From<[u8; 6]> for MacAddr {
    fn from(bytes: [u8; 6]) -> Self {
        Self { inner: bytes }
    }
}

impl From<&[u8; 6]> for MacAddr {
    fn from(bytes: &[u8; 6]) -> Self {
        Self { inner: bytes.clone() }
    }
}

#[cfg(any(feature = "std", test))]
impl FromStr for MacAddr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let octets: Vec<u8> = s
            .split(":")
            .map(|s| {
                u8::from_str_radix(s, 16).or(Err(format!("bad octet: {}", s)))
            })
            .collect::<result::Result<Vec<u8>, _>>()?;

        if octets.len() != 6 {
            return Err(format!("incorrect number of bytes: {}", octets.len()));
        }

        // At the time of writing there is no TryFrom impl for Vec to
        // array in the alloc create. Honestly this looks a bit
        // cleaner anyways.
        let bytes =
            [octets[0], octets[1], octets[2], octets[3], octets[4], octets[5]];

        Ok(MacAddr { inner: bytes })
    }
}

impl Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.inner[0],
            self.inner[1],
            self.inner[2],
            self.inner[3],
            self.inner[4],
            self.inner[5]
        )
    }
}

impl MacAddr {
    /// Return the bytes of the MAC address.
    pub fn bytes(&self) -> [u8; 6] {
        self.inner
    }
}

/// A Geneve Virtual Network Identifier (VNI).
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct Vni {
    // A VNI is 24-bit. By storing it this way we don't have to check
    // the value on the opte-core side to know if it's a valid VNI, we
    // just decode the bytes.
    //
    // The bytes are in network order.
    inner: [u8; 3],
}

impl From<Vni> for u32 {
    fn from(vni: Vni) -> u32 {
        let bytes = vni.inner;
        u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]])
    }
}

#[cfg(any(feature = "std", test))]
impl FromStr for Vni {
    type Err = String;

    fn from_str(val: &str) -> Result<Self, Self::Err> {
        let n = val.parse::<u32>().map_err(|e| e.to_string())?;
        Self::new(n)
    }
}

impl Display for Vni {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", u32::from(*self))
    }
}

const VNI_MAX: u32 = 0x00_FF_FF_FF;

impl Vni {
    /// Return the bytes that represent this VNI. The bytes are in
    /// network order.
    pub fn bytes(&self) -> [u8; 3] {
        return self.inner;
    }

    /// Attempt to create a new VNI from any value which can be
    /// converted to a `u32`.
    ///
    /// # Errors
    ///
    /// Returns an error when the value exceeds the 24-bit maximum.
    pub fn new<N: Into<u32>>(val: N) -> Result<Vni, String> {
        let val = val.into();
        if val > VNI_MAX {
            return Err(format!("VNI value exceeds maximum: {}", val));
        }

        let be_bytes = val.to_be_bytes();
        Ok(Vni { inner: [be_bytes[1], be_bytes[2], be_bytes[3]] })
    }
}

#[test]
fn vni_round_trip() {
    let vni = Vni::new(7777u32).unwrap();
    assert_eq!([0x00, 0x1E, 0x61], vni.inner);
    assert_eq!(7777, u32::from(vni));
}

/// A network destination on the Oxide Rack's physical network (underlay)
///
/// XXX This is oxide-specific and ultimately should not live here.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct PhysNet {
    pub ether: MacAddr,
    pub ip: Ipv6Addr,
    pub vni: Vni,
}

/// The target for a given router entry.
///
/// * Drop: Packets matching this entry are dropped.
///
/// * InternetGateway: Packets matching this entry are forwarded to
/// the internet. In the case of the Oxide Network the IG is not an
/// actual destination, but rather a configuration that determines how
/// we should NAT the flow.
///
/// * Ip: Packets matching this entry are forwarded to the specified IP.
///
/// XXX Make sure that if a router's target is an IP address that it
/// matches the destination IP type.
///
/// * VpcSubnet: Packets matching this entry are forwarded to the
/// specified VPC Subnet. In the Oxide Network this is just an
/// abstraction, it's simply allowing one subnet to talk to another.
/// There is no separate VPC router process, the real routing is done
/// by the underlay.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum RouterTarget {
    Drop,
    InternetGateway,
    Ip(IpAddr),
    VpcSubnet(IpCidr),
}

#[cfg(any(feature = "std", test))]
impl FromStr for RouterTarget {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "drop" => Ok(Self::Drop),
            "ig" => Ok(Self::InternetGateway),
            lower => match lower.split_once("=") {
                Some(("ip4", ip4s)) => {
                    let ip4 = ip4s
                        .parse::<std::net::Ipv4Addr>()
                        .map_err(|e| format!("bad IP: {}", e))?;
                    Ok(Self::Ip(IpAddr::Ip4(ip4.into())))
                }

                Some(("sub4", cidr4s)) => {
                    let cidr4 = cidr4s.parse()?;
                    Ok(Self::VpcSubnet(IpCidr::Ip4(cidr4)))
                }

                _ => Err(format!("malformed router target: {}", lower)),
            },
        }
    }
}

/// Xde create ioctl parameter data.
///
/// XXX This is oxide-specific and ultimately should not live here.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateXdeReq {
    pub linkid: datalink_id_t,
    pub xde_devname: String,

    pub private_ip: Ipv4Addr,
    pub private_mac: MacAddr,
    pub gw_mac: MacAddr,
    pub gw_ip: Ipv4Addr,

    pub bsvc_addr: Ipv6Addr,
    pub bsvc_vni: Vni,
    pub src_underlay_addr: Ipv6Addr,
    pub vpc_vni: Vni,

    pub passthrough: bool,
}

/// Xde delete ioctl parameter data.
///
/// XXX This is oxide-specific and ultimately should not live here.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeleteXdeReq {
    pub xde_devname: String,
}

/// Set mapping from VPC IP to physical network destination.
///
/// XXX This is oxide-specific and ultimately should not live here.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SetVirt2PhysReq {
    pub vip: IpAddr,
    pub phys: PhysNet,
}

/// Add an entry to the IPv4 router.
///
/// XXX This is oxide-specific and ultimately should not live here.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AddRouterEntryIpv4Req {
    pub port_name: String,
    pub dest: Ipv4Cidr,
    pub target: RouterTarget,
}

cfg_if! {
    if #[cfg(target_os = "illumos")] {
        use std::fs::{File, OpenOptions};
        use std::os::unix::io::AsRawFd;
        use libc;
        use serde::de::DeserializeOwned;
        use thiserror::Error;
    }
}

/// Errors related to administering the OPTE driver.
#[derive(Debug, Error)]
#[cfg(target_os = "illumos")]
pub enum Error {
    #[error("OPTE driver is not attached")]
    DriverNotAttached,

    #[error("error interacting with device: {0}")]
    Io(std::io::Error),

    /// Something in the opte ioctl(2) handler failed.
    #[error("ioctl {0:?} failed: {1}")]
    IoctlFailed(OpteCmd, String),

    #[error("invalid argument {0}")]
    InvalidArgument(String),

    #[error("netadm failed {0}")]
    NetadmFailed(libnet::Error),

    #[error("request serialization failed for command {0:?}: {1}")]
    ReqSer(OpteCmd, postcard::Error),

    #[error("response deserialization failed for command {0:?}: {1}")]
    RespDeser(OpteCmd, postcard::Error),

    #[error("failed to get response for command {0:?} in {1} attempts")]
    MaxAttempts(OpteCmd, u8),

    #[error("command {0:?} failed: {1:?}")]
    CommandError(OpteCmd, OpteError),
}

#[cfg(target_os = "illumos")]
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::NotFound => Error::DriverNotAttached,
            _ => Error::Io(e),
        }
    }
}

#[cfg(target_os = "illumos")]
impl From<libnet::Error> for Error {
    fn from(e: libnet::Error) -> Self {
        Self::NetadmFailed(e)
    }
}

/// The handle used to send administration commands to the OPTE
/// control node.
#[derive(Debug)]
#[cfg(target_os = "illumos")]
pub struct OpteAdm {
    device: File,
}

#[cfg(target_os = "illumos")]
impl OpteAdm {
    pub const DLD_CTL: &'static str = "/dev/dld";

    /// Add xde device
    pub fn create_xde(
        &self,
        name: &str,
        private_mac: MacAddr,
        private_ip: std::net::Ipv4Addr,
        gw_mac: MacAddr,
        gw_ip: std::net::Ipv4Addr,
        bsvc_addr: std::net::Ipv6Addr,
        bsvc_vni: Vni,
        vpc_vni: Vni,
        src_underlay_addr: std::net::Ipv6Addr,
        passthrough: bool,
    ) -> Result<NoResp, Error> {
        let linkid = libnet::link::create_link_id(
            name,
            libnet::LinkClass::Xde,
            libnet::LinkFlags::Active,
        )?;

        let xde_devname = name.into();
        let cmd = OpteCmd::CreateXde;
        let req = CreateXdeReq {
            xde_devname,
            linkid,
            private_mac,
            private_ip: private_ip.into(),
            gw_mac,
            gw_ip: gw_ip.into(),
            bsvc_addr: bsvc_addr.into(),
            bsvc_vni,
            vpc_vni,
            src_underlay_addr: src_underlay_addr.into(),
            passthrough,
        };

        run_cmd_ioctl(self.device.as_raw_fd(), cmd, &req)
    }

    /// Delete xde device
    pub fn delete_xde(&self, name: &str) -> Result<NoResp, Error> {
        let link_id = libnet::LinkHandle::Name(name.into()).id()?;
        let req = DeleteXdeReq { xde_devname: name.into() };
        let cmd = OpteCmd::DeleteXde;
        let resp = run_cmd_ioctl(self.device.as_raw_fd(), cmd, &req)?;
        libnet::link::delete_link_id(link_id, libnet::LinkFlags::Active)?;
        Ok(resp)
    }

    /// Create a new handle to the OPTE control node.
    pub fn open(what: &str) -> Result<Self, Error> {
        Ok(OpteAdm {
            device: OpenOptions::new().read(true).write(true).open(what)?,
        })
    }

    pub fn set_v2p(&self, req: &SetVirt2PhysReq) -> Result<NoResp, Error> {
        let cmd = OpteCmd::SetVirt2Phys;
        run_cmd_ioctl(self.device.as_raw_fd(), cmd, &req)
    }

    pub fn add_router_entry_ip4(
        &self,
        req: &AddRouterEntryIpv4Req,
    ) -> Result<NoResp, Error> {
        let cmd = OpteCmd::AddRouterEntryIpv4;
        run_cmd_ioctl(self.device.as_raw_fd(), cmd, &req)
    }
}

#[cfg(target_os = "illumos")]
fn run_cmd_ioctl<T, R>(
    dev: libc::c_int,
    cmd: OpteCmd,
    req: &R,
) -> Result<T, Error>
where
    T: CmdOk + DeserializeOwned,
    R: Serialize,
{
    let req_bytes =
        postcard::to_allocvec(req).map_err(|e| Error::ReqSer(cmd, e))?;

    // It would be a shame if the command failed and we didn't have
    // enough bytes to serialize the error response, so we set this to
    // default to 16 KiB.
    let mut resp_buf: Vec<u8> = vec![0; 16 * 1024];
    let mut rioctl = OpteCmdIoctl {
        api_version: API_VERSION,
        cmd,
        flags: 0,
        reserved1: 0,
        req_bytes: req_bytes.as_ptr(),
        req_len: req_bytes.len(),
        resp_bytes: resp_buf.as_mut_ptr(),
        resp_len: resp_buf.len(),
        resp_len_actual: 0,
    };

    const MAX_ITERATIONS: u8 = 3;
    for _ in 0..MAX_ITERATIONS {
        let ret = unsafe {
            libc::ioctl(dev, XDE_DLD_OPTE_CMD as libc::c_int, &rioctl)
        };

        // The ioctl(2) failed for a reason other than the response
        // buffer being too small.
        //
        // errno == ENOBUFS
        //
        //    The command ran successfully, but there is not enough
        //    space to copyout(9F) the response. In this case bump
        //    up the size of the response buffer and retry.
        //
        // errno != 0 && OPTE_CMD_RESP_COPY_OUT
        //
        //    The command failed and we have an error response
        //    serialized in the response buffer.
        //
        // errno != 0
        //
        //    Either the command failed or the general ioctl mechanism
        //    failed: make our best guess as to what might have gone
        //    wrong based on errno value.
        if ret == -1 && unsafe { *libc::___errno() } != libc::ENOBUFS {
            // Anytime a response is present it will have more context
            // for the error. Otherwise, we have to approximate the
            // error via errno.
            if let Some(cmd_err) = rioctl.cmd_err_resp() {
                return Err(Error::CommandError(cmd, cmd_err));
            }

            let msg = match unsafe { *libc::___errno() } {
                libc::EPROTO => "API version mismatch".to_string(),

                libc::EFAULT => "failed to copyin/copyout req/resp".to_string(),

                libc::ENOMSG => {
                    "opte driver failed to deser/ser req/resp".to_string()
                }

                errno => {
                    format!("unexpected errno: {}", errno)
                }
            };

            return Err(Error::IoctlFailed(cmd, msg));
        }

        // Check for successful response, try to deserialize it
        assert!(rioctl.resp_len_actual != 0);
        if ret == 0 && rioctl.resp_len_actual <= rioctl.resp_len {
            let response = unsafe {
                std::slice::from_raw_parts(
                    rioctl.resp_bytes,
                    rioctl.resp_len_actual,
                )
            };
            return postcard::from_bytes(response)
                .map_err(|e| Error::RespDeser(cmd, e));
        }

        // The buffer wasn't large enough to hold the response.
        // Enlarge the buffer by asking for more capacity and
        // initializing it so that it is usable.
        resp_buf.resize(rioctl.resp_len_actual, 0);
        rioctl.resp_bytes = resp_buf.as_mut_ptr();
        rioctl.resp_len = resp_buf.len();
        rioctl.resp_len_actual = 0;
    }

    Err(Error::MaxAttempts(cmd, MAX_ITERATIONS))
}
