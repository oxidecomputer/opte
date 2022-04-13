use core::fmt::{self, Display};

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::string::ToString;
        use alloc::vec::Vec;
    } else {
        use std::string::ToString;
        use std::vec::Vec;
    }
}

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::api::SubnetRouterPair;

/// The DHCP message type.
///
/// Why define our own wrapper type when smoltcp already provides this
/// type? We need to use this type as part of a rule predicate value;
/// therefore it must be serializable. There are ways to get around
/// this without creating a new type; the author prefers this way as
/// it's less "magic".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageType {
    inner: smoltcp::wire::DhcpMessageType,
}

impl From<smoltcp::wire::DhcpMessageType> for MessageType {
    fn from(inner: smoltcp::wire::DhcpMessageType) -> Self {
        Self { inner }
    }
}

impl From<MessageType> for smoltcp::wire::DhcpMessageType {
    fn from(mt: MessageType) -> Self {
        mt.inner
    }
}

// smoltcp provides no way to convert the Message Type to a u8, so we
// do it ourselves. It might be nice to send a PR to smoltcp to add
// this impl to its `enum_with_unknown!` macro.
impl From<MessageType> for u8 {
    fn from(mt: MessageType) -> u8 {
        use smoltcp::wire::DhcpMessageType::*;

        match mt.inner {
            Discover => 1,
            Offer => 2,
            Request => 3,
            Decline => 4,
            Ack => 5,
            Nak => 6,
            Release => 7,
            Inform => 8,
            Unknown(val) => val,
        }
    }
}

impl From<u8> for MessageType {
    fn from(val: u8) -> Self {
        use smoltcp::wire::DhcpMessageType as SmolDMT;

        Self { inner: SmolDMT::from(val) }
    }
}

struct MessageTypeVisitor;

impl<'de> Visitor<'de> for MessageTypeVisitor {
    type Value = MessageType;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("an unsigned integer from 0 to 255")
    }

    fn visit_u8<E>(self, value: u8) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(MessageType::from(value))
    }
}

impl<'de> Deserialize<'de> for MessageType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_u8(MessageTypeVisitor)
    }
}

impl Serialize for MessageType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(u8::from(*self))
    }
}

impl Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use smoltcp::wire::DhcpMessageType::*;

        let s = match self.inner {
            Discover => "Discover".to_string(),
            Offer => "Offer".to_string(),
            Request => "Request".to_string(),
            Decline => "Decline".to_string(),
            Ack => "Ack".to_string(),
            Nak => "Nak".to_string(),
            Release => "Release".to_string(),
            Inform => "Inform".to_string(),
            Unknown(val) => format!("Unknown: {}", val),
        };
        write!(f, "{}", s)
    }
}

/// A Classes Static Route Option (121).
///
/// We must implement this type ourselves as smoltcp does not provide
/// this option out of the box. We allow for up to three routes to be
/// specified. See RFC 3442 for more detail.
#[derive(Clone, Debug)]
pub struct ClasslessStaticRouteOpt {
    routes: Vec<SubnetRouterPair>,
}

impl SubnetRouterPair {
    fn encode_len(&self) -> u8 {
        // One byte for the subnet mask width.
        let mut entry_size = 1u8;

        // Variable length for the subnet number. Only significant
        // bytes are included.
        entry_size += self.subnet_encode_len();

        // Four bytes for the router's address.
        entry_size += 4;
        entry_size
    }

    fn encode(&self, bytes: &mut [u8]) {
        let mut pos = 0;
        bytes[pos] = self.subnet.prefix_len();
        pos += 1;
        let n = self.subnet_encode_len();
        let subnet_bytes = self.subnet.ip().bytes();
        for i in 0..n {
            bytes[pos] = subnet_bytes[i as usize];
            pos += 1;
        }

        for b in self.router.bytes() {
            bytes[pos] = b;
            pos += 1;
        }
    }

    fn subnet_encode_len(&self) -> u8 {
        let prefix = self.subnet.prefix_len();

        if prefix == 0 {
            0
        } else {
            let round = if prefix % 8 != 0 { 1 } else { 0 };
            (prefix / 8) + round
        }
    }
}

impl ClasslessStaticRouteOpt {
    /// Create a new Classless Static Route Option (121).
    ///
    /// At least one [`SubnetRouterPair`] must be specified. Up to two
    /// additional pairs may also be specified.
    pub fn new(
        r1: SubnetRouterPair,
        r2: Option<SubnetRouterPair>,
        r3: Option<SubnetRouterPair>,
    ) -> Self {
        let mut routes = vec![r1];

        if r2.is_some() {
            routes.push(r2.unwrap());
        }

        if r3.is_some() {
            routes.push(r3.unwrap());
        }

        Self { routes }
    }

    /// The length needed to encode this value into a series of bytes
    /// as described in RFC 3442.
    ///
    /// XXX Do we need to pad to 4-byte boundary?
    pub fn encode_len(&self) -> u8 {
        // * One byte to specify option code.
        // * One byte to speicfy length of option value.
        let mut total = 2u8;

        for r in &self.routes {
            total += r.encode_len();
        }

        total
    }

    /// Encode the value to a series of bytes as described in RFC 3442.
    pub fn encode(&self) -> Vec<u8> {
        let len = self.encode_len();
        assert!(len < 255);
        let mut bytes = vec![0u8; len as usize];
        bytes[0] = 121;
        // The length byte indicates the length of the encoded subnet
        // and router pairs; it does not include the option code or
        // itself.
        bytes[1] = len - 2;
        let mut pos = 2;

        for r in &self.routes {
            r.encode(&mut bytes[pos..]);
            pos += r.encode_len() as usize;
        }

        bytes
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::engine::ip4::{Ipv4Addr, Ipv4Cidr};

    #[test]
    fn offlink_encode() {
        let if_ip = SubnetRouterPair {
            subnet: Ipv4Cidr::new_checked(Ipv4Addr::from([172, 30, 7, 77]), 32)
                .unwrap(),
            router: Ipv4Addr::from([0, 0, 0, 0]),
        };

        let gw = SubnetRouterPair {
            subnet: Ipv4Cidr::new_checked(Ipv4Addr::from([0, 0, 0, 0]), 0)
                .unwrap(),
            router: Ipv4Addr::from([172, 30, 4, 1]),
        };

        let opt =
            ClasslessStaticRouteOpt::new(if_ip.clone(), Some(gw.clone()), None);
        assert_eq!(
            opt.encode(),
            vec![121, 14, 32, 172, 30, 7, 77, 0, 0, 0, 0, 0, 172, 30, 4, 1]
        );
    }

    #[test]
    fn rfc3442_encode() {
        let router = Ipv4Addr::from([10, 0, 0, 1]);

        let p1 = SubnetRouterPair {
            subnet: Ipv4Cidr::new_checked(Ipv4Addr::from([0, 0, 0, 0]), 0)
                .unwrap(),
            router,
        };

        let p2 = SubnetRouterPair {
            subnet: Ipv4Cidr::new_checked(Ipv4Addr::from([10, 0, 0, 0]), 8)
                .unwrap(),
            router,
        };

        let p3 = SubnetRouterPair {
            subnet: Ipv4Cidr::new_checked(Ipv4Addr::from([10, 0, 0, 0]), 24)
                .unwrap(),
            router,
        };

        let p4 = SubnetRouterPair {
            subnet: Ipv4Cidr::new_checked(Ipv4Addr::from([10, 17, 0, 0]), 16)
                .unwrap(),
            router,
        };

        let p5 = SubnetRouterPair {
            subnet: Ipv4Cidr::new_checked(Ipv4Addr::from([10, 27, 129, 0]), 24)
                .unwrap(),
            router,
        };

        let p6 = SubnetRouterPair {
            subnet: Ipv4Cidr::new_checked(
                Ipv4Addr::from([10, 229, 0, 128]),
                25,
            )
            .unwrap(),
            router,
        };

        let p7 = SubnetRouterPair {
            subnet: Ipv4Cidr::new_checked(
                Ipv4Addr::from([10, 198, 122, 47]),
                32,
            )
            .unwrap(),
            router,
        };

        let p8 = SubnetRouterPair {
            subnet: Ipv4Cidr::new_checked(Ipv4Addr::from([10, 16, 0, 0]), 15)
                .unwrap(),
            router,
        };

        let opt = ClasslessStaticRouteOpt::new(p1.clone(), None, None);
        assert_eq!(opt.encode(), vec![121, 5, 0, 10, 0, 0, 1]);

        let opt =
            ClasslessStaticRouteOpt::new(p1.clone(), Some(p2.clone()), None);
        assert_eq!(
            opt.encode(),
            vec![121, 11, 0, 10, 0, 0, 1, 8, 10, 10, 0, 0, 1]
        );

        let opt = ClasslessStaticRouteOpt::new(
            p1.clone(),
            Some(p2.clone()),
            Some(p3.clone()),
        );
        assert_eq!(
            opt.encode(),
            vec![
                121, 19, 0, 10, 0, 0, 1, 8, 10, 10, 0, 0, 1, 24, 10, 0, 0, 10,
                0, 0, 1
            ]
        );

        let opt = ClasslessStaticRouteOpt::new(p4.clone(), None, None);
        assert_eq!(opt.encode(), vec![121, 7, 16, 10, 17, 10, 0, 0, 1],);

        let opt =
            ClasslessStaticRouteOpt::new(p4.clone(), Some(p5.clone()), None);
        assert_eq!(
            opt.encode(),
            vec![
                121, 15, 16, 10, 17, 10, 0, 0, 1, 24, 10, 27, 129, 10, 0, 0, 1
            ],
        );

        let opt = ClasslessStaticRouteOpt::new(
            p4.clone(),
            Some(p5.clone()),
            Some(p6.clone()),
        );
        assert_eq!(
            opt.encode(),
            vec![
                121, 24, 16, 10, 17, 10, 0, 0, 1, 24, 10, 27, 129, 10, 0, 0, 1,
                25, 10, 229, 0, 128, 10, 0, 0, 1
            ],
        );

        let opt =
            ClasslessStaticRouteOpt::new(p6.clone(), Some(p7.clone()), None);
        assert_eq!(
            opt.encode(),
            vec![
                121, 18, 25, 10, 229, 0, 128, 10, 0, 0, 1, 32, 10, 198, 122,
                47, 10, 0, 0, 1
            ]
        );

        let opt = ClasslessStaticRouteOpt::new(
            p6.clone(),
            Some(p7.clone()),
            Some(p8.clone()),
        );
        assert_eq!(
            opt.encode(),
            vec![
                121, 25, 25, 10, 229, 0, 128, 10, 0, 0, 1, 32, 10, 198, 122,
                47, 10, 0, 0, 1, 15, 10, 16, 10, 0, 0, 1
            ]
        );
    }
}
