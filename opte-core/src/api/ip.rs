use core::result;
use serde::{Deserialize, Serialize};

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::string::String;
    } else {
        use std::fmt::{self, Display};
        use std::str::FromStr;
        use std::string::String;
    }
}

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

#[cfg(test)]
mod test {
    use std::string::ToString;
    use super::*;

    #[test]
    fn bad_cidr() {
        let ip = "10.0.0.1".parse().unwrap();
        let mut msg = "bad prefix length: 33".to_string();
        assert_eq!(Ipv4Cidr::new(ip, 33), Err(msg.clone()));
        assert_eq!("192.168.2.9/33".parse::<Ipv4Cidr>(), Err(msg.clone()));

        msg = "bad prefix length: 129".to_string();
        let ip6 = "fd01:dead:beef::1".parse().unwrap();
        assert_eq!(Ipv6Cidr::new(ip6, 129), Err(msg.clone()));

        assert_eq!(
            "fd01:dead:beef::1/129".parse::<Ipv6Cidr>(),
            Err(msg.clone())
        )
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
}
