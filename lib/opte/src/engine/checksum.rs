// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Types for calculating the internet checksum.
//!
//! This module contains types for calculating the "internet
//! checksum". The [`Checksum`] type provides a rolling one's
//! complement checksum, allowing one to more efficiently build up (or
//! incrementally update) a sum before finalizing it into a
//! [`HeaderChecksum`], which is the value stored in the actual header
//! bytes.
//!
//! # Checksums and Endianness
//!
//! It's easy to become confused by endianness and networking code
//! when looking at checksums. It's worth making clear what is going
//! on.
//!
//! Any logical value stored in a network header needs to consider
//! endianness. A multi-byte value like an IP header's "total length"
//! or TCP's "port", which has a logical value like "total length =
//! 60" or "port = 443", needs to make sure its value is interpreted
//! correctly no matter which byte order the underlying hardware uses.
//! To this effect, all logical values sent across the network are
//! sent in "network order" (big endian) and then adjusted accordingly
//! on the host. For example, AMD64 arch network code calls
//! `hton{s,l}()` to convert the logical value in memory to the
//! correct byte order for the network, and uses `ntoh{s,l}()` to
//! convert in the other direction. However, not all values have a
//! logical, numerical meaning. A MAC address is made up of six
//! consecutive bytes, for which the order is important. This string
//! of bytes is never interpreted as an integer. There is no
//! conversion to be made. The bytes are in the same order in the
//! network as they are in memory (because the logical value is just
//! that, a sequence of bytes). The same goes for the various
//! checksums. The internet checksum is just a sequence of two bytes.
//! However, in order to implement the checksum (one's complement
//! sum), we happen to treat these two bytes as a 16-bit integer, and
//! the sequence of bytes to be summed as a set of 16-bit integers.
//! Because of this it's easy to think of the checksum as a logical
//! `u16` when it's really not. This brings us to the point: you never
//! perform byte-order conversion on the checksum field. You treat
//! each pair of bytes (both the checksum value itself, and the bytes
//! you are summing) as if it's a native 16-bit integer. In C this
//! takes the form of a direct cast to `(uint16_t *)`, in Rust it's
//! `{to,from}_ne_bytes()`. Yes, this means that on a little-endian
//! architecture you are logically flipping the bytes, but as the
//! bytes being summed are all in network-order, you are also storing
//! them in network-order when you write the sum to memory.
//!
//! While said a slightly different way, this is also covered in RFC
//! 1071 §1.B.
//!
//! > Therefore, the sum may be calculated in exactly the same way
//! > regardless of the byte order ("big-endian" or "little-endian")
//! > of the underlaying hardware. For example, assume a "little-
//! > endian" machine summing data that is stored in memory in
//! > network ("big-endian") order. Fetching each 16-bit word will
//! > swap bytes, resulting in the sum \[4\]; however, storing the
//! > result back into memory will swap the sum back into network
//! > byte order.
//!
//! # Relevant RFCs
//!
//! * 1071 Computing the Internet Checksum
//!
//! * 1141 Incremental Updating of the Internet Checksum
//!
//! * 1624 Computation of the Internet Checksum via Incremental Update

/// The checksum values, as it is contained in a network header.
///
/// This is meant to hold the bytes as they are stored in the header
/// itself. Notably, it contains the bytes with one's complement
/// applied.
pub struct HeaderChecksum {
    inner: [u8; 2],
}

impl HeaderChecksum {
    /// Return the bytes of this header checksum.
    pub fn bytes(&self) -> [u8; 2] {
        self.inner
    }

    /// Wrap the checksum bytes in a header.
    ///
    /// NOTE: This could just as well be a `From<[u8; 2]>`
    /// implementation, but the "wrap" verbiage is meant to make it
    /// clear that we are wrapping a pair of bytes which represent a
    /// header checksum -- i.e., the one's complement of a one's
    /// complement sum.
    pub fn wrap(hc: [u8; 2]) -> Self {
        Self { inner: hc }
    }
}

impl From<Checksum> for HeaderChecksum {
    /// Finalize the rolling checksum and put it into header form by
    /// performing one's complement.
    fn from(mut csum: Checksum) -> HeaderChecksum {
        // See the module-level comment about why it's important to
        // convert using native-endian.
        Self { inner: (!csum.finalize()).to_ne_bytes() }
    }
}

/// A rolling one's complement checksum calculation.
///
/// This is useful for keeping a rolling checksum in a more efficient
/// manner; as opposed to constantly taking the one's complement
/// (bitwise negation), incrementally updating the sum, and then
/// re-applying one's complement. It also delays summing the carries
/// until the finalized sum is needed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Checksum {
    inner: u32,
}

impl Checksum {
    /// Creates a new checksum counter.
    pub fn new() -> Self {
        Self::from(0)
    }

    /// Update the sum based by adding the contents of `bytes`.
    ///
    /// This is useful for incrementally updating an existing checksum
    /// where only a portion of the bytes are being rewritten.
    pub fn add_bytes(&mut self, bytes: &[u8]) {
        self.inner = csum_add(self.inner, bytes);
    }

    /// Create a new rolling checksum, starting with the passed in
    /// `bytes`.
    pub fn compute(bytes: &[u8]) -> Self {
        Self { inner: csum_add(0, bytes) }
    }

    /// Update the sum by subtracting the contents of `bytes`.
    ///
    /// This is useful for incrementally updating an existing checksum
    /// where only a portion of the bytes are being rewritten.
    pub fn sub_bytes(&mut self, bytes: &[u8]) {
        self.inner = csum_sub(self.inner, bytes);
    }

    /// Finalize the sum by adding up all the accumulated carries and
    /// returning the resulting value as a `u16`.
    pub fn finalize(&mut self) -> u16 {
        while (self.inner >> 16) != 0 {
            self.inner = (self.inner >> 16) + (self.inner & 0xFFFF);
        }

        (self.inner & 0xFFFF) as u16
    }

    /// Calls [`Self::finalize`], and returns the one's complement value
    /// of the checksum for storage as a `u16be`.
    pub fn finalize_for_ingot(&mut self) -> u16 {
        let out = self.finalize();

        (!out).to_be()
    }
}

impl From<HeaderChecksum> for Checksum {
    // Convert a header's checksum bytes into a rolling checksum.
    fn from(hc: HeaderChecksum) -> Self {
        // See the module-level comment about why it's important to
        // convert using native-endian.
        Self { inner: (!u16::from_ne_bytes(hc.bytes())) as u32 }
    }
}

impl From<u32> for Checksum {
    fn from(csum: u32) -> Self {
        Self { inner: csum }
    }
}

impl core::ops::Add for Checksum {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self { inner: self.inner + other.inner }
    }
}

impl core::ops::AddAssign for Checksum {
    fn add_assign(&mut self, other: Self) {
        self.inner += other.inner
    }
}

impl core::ops::SubAssign for Checksum {
    fn sub_assign(&mut self, other: Self) {
        let other_bytes = other.clone().finalize().to_ne_bytes();
        self.sub_bytes(&other_bytes);
    }
}

fn csum_add(mut csum: u32, bytes: &[u8]) -> u32 {
    let mut len = bytes.len();
    let mut pos = 0;

    while len > 1 {
        // See the module-level comment about why it's important to
        // convert using native-endian.
        csum += (u16::from_ne_bytes([bytes[pos], bytes[pos + 1]])) as u32;
        pos += 2;
        len -= 2;
    }

    if len == 1 {
        csum += bytes[pos] as u32;
    }

    csum
}

fn csum_sub(mut csum: u32, bytes: &[u8]) -> u32 {
    let mut len = bytes.len();
    let mut pos = 0;

    while len > 1 {
        // See the module-level comment about why it's important to
        // convert using native-endian.
        let sub = (!u16::from_ne_bytes([bytes[pos], bytes[pos + 1]])) as u32;
        csum += sub;
        pos += 2;
        len -= 2;
    }

    if len == 1 {
        csum += (!bytes[pos]) as u32;
    }

    csum
}
