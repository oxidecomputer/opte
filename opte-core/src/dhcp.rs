use core::fmt::{self, Display};

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::string::ToString;
#[cfg(any(feature = "std", test))]
use std::string::ToString;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

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
