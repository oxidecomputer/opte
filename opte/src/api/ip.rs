use core::fmt::{self, Debug, Display};
use core::result;
use core::str::FromStr;
use super::mac::MacAddr;
use serde::{Deserialize, Serialize};

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::string::String;
        use alloc::vec::Vec;
    } else {
        use std::string::String;
        use std::vec::Vec;
    }
}

/// Generate an ICMPv4 Echo Reply message.
///
/// Map an ICMPv4 Echo Message (Type=8, Code=0) from `src` to `dst`
/// into an ICMPv4 Echo Reply Message (Type=0, Code=0) from `dst` to
/// `src`.
///
/// TODO Go over each field in detail.
#[derive(Clone, Debug)]
pub struct Icmp4EchoReply {
    pub echo_src_mac: MacAddr,
    pub echo_src_ip: Ipv4Addr,
    pub echo_dst_mac: MacAddr,
    pub echo_dst_ip: Ipv4Addr,
}

impl Display for Icmp4EchoReply {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ICMPv4 Echo Reply ({},{}) => ({},{})",
            self.echo_dst_mac, self.echo_dst_ip, self.echo_src_mac,
            self.echo_src_ip,
        )
    }
}

/// Generate DHCPv4 Offer+Ack.
///
/// Respond to a cilent's Discover and Request messages with Offer+Ack
/// replies based on the information contained in this struct.
///
/// XXX Currently we return the same options no matter what the client
/// specifies in the parameter request list. This has worked thus far,
/// but we should come back to this and comb over RFC 2131 more
/// carefully -- particularly §4.3.1 and §4.3.2.
pub struct Dhcp4Action {
    /// The client's MAC address.
    pub client_mac: MacAddr,
    /// The client's IPv4 address. Used to fill in the `yiaddr` field.
    pub client_ip: Ipv4Addr,
    /// The client's subnet mask specified as a prefix length. Used as
    /// the value of `Subnet Mask Option (code 1)`.
    pub subnet_prefix_len: Ipv4PrefixLen,
    /// The gateway MAC address. The use of this action assumes that
    /// the OPTE port is acting as gateway; this MAC address is what
    /// the port will use when acting as a gateway to the client. This
    /// is used as the Ethernet header's source address.
    pub gw_mac: MacAddr,
    /// The gateway IPv4 address. This is used for several purposes:
    ///
    /// * As the IP header's source address.
    ///
    /// * As the value of the `siaddr` field.
    ///
    /// * As the value of the `Router Option (code 3)`.
    ///
    /// * As the value of the `Server Identifier Option (code 54)`.
    pub gw_ip: Ipv4Addr,
    /// The value of the `DHCP Message Type Option (code 53)`. This
    /// action supports only the Offer and Ack messages.
    pub reply_type: Dhcp4ReplyType,
    /// A static route entry, sent to the client via the `Classless
    /// Static Route Option (code 131)`.
    pub re1: SubnetRouterPair,
    /// An optional second entry (see `re1`).
    pub re2: Option<SubnetRouterPair>,
    /// An optional third entry (see `re1`).
    pub re3: Option<SubnetRouterPair>,
}

impl Display for Dhcp4Action {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "DHCPv4 {}: {}", self.reply_type, self.client_ip)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Dhcp4ReplyType {
    Offer,
    Ack,
}

impl Display for Dhcp4ReplyType {
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
    pub fn new(subnet: Ipv4Cidr, router: Ipv4Addr) -> Self {
        Self { subnet, router }
    }
}

/// An IP protocol value.
///
/// TODO repr(u8)?
#[repr(C)]
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum Protocol {
    ICMP = 0x1,
    IGMP = 0x2,
    TCP = 0x6,
    UDP = 0x11,
    Reserved = 0xFF,
}

impl Default for Protocol {
    fn default() -> Self {
        Protocol::Reserved
    }
}

impl Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Protocol::ICMP => write!(f, "ICMP"),
            Protocol::IGMP => write!(f, "IGMP"),
            Protocol::TCP => write!(f, "TCP"),
            Protocol::UDP => write!(f, "UDP"),
            Protocol::Reserved => write!(f, "Reserved"),
        }
    }
}

impl TryFrom<u8> for Protocol {
    type Error = String;

    fn try_from(proto: u8) -> core::result::Result<Self, Self::Error> {
        match proto {
            0x1 => Ok(Protocol::ICMP),
            0x2 => Ok(Protocol::IGMP),
            0x6 => Ok(Protocol::TCP),
            0x11 => Ok(Protocol::UDP),
            proto => Err(format!("unhandled IP protocol: 0x{:X}", proto)),
        }
    }
}

/// An IPv4 or IPv6 address.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum IpAddr {
    Ip4(Ipv4Addr),
    Ip6(Ipv6Addr),
}

/// An IPv4 address.
#[derive(
    Clone, Copy, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct Ipv4Addr {
    inner: [u8; 4],
}

#[cfg(any(feature = "std", test))]
impl From<std::net::Ipv4Addr> for Ipv4Addr {
    fn from(ip4: std::net::Ipv4Addr) -> Self {
        Self { inner: ip4.octets() }
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
            .split(".")
            .map(|s| s.parse().map_err(|e| format!("{}", e)))
            .collect::<result::Result<Vec<u8>, _>>()?;

        if octets.len() != 4 {
            return Err(format!("malformed ip: {}", val));
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
        write!(f, "Ipv4Addr {{ inner: {} }}", self)
    }
}

impl Ipv4Addr {
    pub const ANY_ADDR: Self = Self { inner: [0; 4] };
    pub const LOCAL_BCAST: Self = Self { inner: [255; 4] };

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
            return Ok(Ipv4Addr::ANY_ADDR);
        }

        let mut n = u32::from_be_bytes(self.inner);

        let mut bits = i32::MIN;
        bits = bits >> (mask - 1);
        n = n & bits as u32;
        self.inner = n.to_be_bytes();
        Ok(self)
    }

    pub fn safe_mask(self, prefix_len: Ipv4PrefixLen) -> Self {
        self.mask(prefix_len.0).unwrap()
    }
}

/// An IPv6 address.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
pub struct Ipv6Addr {
    inner: [u8; 16],
}

#[cfg(any(feature = "std", test))]
impl From<std::net::Ipv6Addr> for Ipv6Addr {
    fn from(ip6: std::net::Ipv6Addr) -> Self {
        Self { inner: ip6.octets() }
    }
}

impl From<&[u8; 16]> for Ipv6Addr {
    fn from(bytes: &[u8; 16]) -> Ipv6Addr {
        Ipv6Addr { inner: *bytes }
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

    pub fn safe_mask(self, mask: Ipv6PrefixLen) -> Self {
        self.mask(mask.val()).unwrap()
    }
}

/// An IPv4 or IPv6 CIDR.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum IpCidr {
    Ip4(Ipv4Cidr),
    Ip6(Ipv6Cidr),
}

/// A valid IPv4 prefix legnth.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Ipv4PrefixLen(u8);

impl Ipv4PrefixLen {
    pub const NETMASK_NONE: Self = Self(0);
    pub const NETMASK_ALL: Self = Self(32);

    pub fn new(prefix_len: u8) -> Result<Self, String> {
        if prefix_len > 32 {
            return Err(format!("bad IPv4 prefix length: {}", prefix_len));
        }

        Ok(Self(prefix_len))
    }

    /// Convert the prefix length into a subnet mask.
    pub fn to_netmask(self) -> Ipv4Addr {
        let mut bits = i32::MIN;
        bits = bits >> (self.0 - 1);
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

impl FromStr for Ipv4Cidr {
    type Err = String;

    /// Convert a string like "192.168.2.0/24" into an `Ipv4Cidr`.
    fn from_str(val: &str) -> result::Result<Self, Self::Err> {
        let (ip_s, prefix_s) = match val.split_once("/") {
            Some(v) => v,
            None => return Err(format!("no '/' found")),
        };

        let ip = match ip_s.parse() {
            Ok(v) => v,
            Err(e) => return Err(format!("bad IP: {}", e)),
        };

        let raw = match prefix_s.parse::<u8>() {
            Ok(v) => v,
            Err(e) => {
                return Err(format!("bad prefix length: {}", e));
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
}

/// An IPv6 CIDR.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Ipv6Cidr {
    ip: Ipv6Addr,
    prefix_len: Ipv6PrefixLen,
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

        Ipv6Cidr::new_checked(ip, prefix_len)
    }
}

/// A valid IPv6 prefix length.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Ipv6PrefixLen(u8);

impl Ipv6PrefixLen {
    pub fn new(prefix_len: u8) -> result::Result<Self, String> {
        if prefix_len > 128 {
            return Err(format!("bad IPv6 prefix length: {}", prefix_len));
        }

        Ok(Self(prefix_len))
    }

    pub fn val(&self) -> u8 {
        self.0
    }
}

impl Ipv6Cidr {
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

        assert_eq!(
            "fd01:dead:beef::1/129".parse::<Ipv6Cidr>(),
            Err(msg.clone())
        )
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
    }
}
