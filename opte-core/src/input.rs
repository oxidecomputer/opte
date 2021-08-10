//! TODO document me!
#[cfg(any(feature = "std", test))]
use std::convert::TryInto;

use std::prelude::v1::*;

use crate::ether::EtherAddr;
use crate::ip4::{Ipv4Addr, Protocol};
use crate::Direction;

// ================================================================
// Packet Parsing for mblk and Vec
// ===============================================================
pub trait Packet {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadErr {
    BadLayout,
    NotEnoughBytes,
    StraddledHeader,
}

// TODO rename ReadResult?
pub type Result<T> = core::result::Result<T, ReadErr>;

pub trait PacketReader {
    fn get_slice(&mut self, len: usize)
        -> core::result::Result<&[u8], ReadErr>;
    fn get_slice_mut(
        &mut self,
        len: usize,
    ) -> core::result::Result<&mut [u8], ReadErr>;
    fn read_bytes(&mut self, dst: &mut [u8]) -> Result<()>;
    fn read_u8(&mut self, dst: &mut u8) -> Result<()>;
    fn read_u16(&mut self, dst: &mut u16) -> Result<()>;
    fn read_u32(&mut self, dst: &mut u32) -> Result<()>;
    fn seek_back(&mut self, offset: usize) -> Result<()>;
    fn seek(&mut self, offset: usize) -> Result<()>;
}

#[cfg(any(feature = "std", test))]
pub struct VecPacket {
    bytes: Vec<u8>,
}

#[cfg(any(feature = "std", test))]
impl VecPacket {
    pub fn from_slice(bslice: &[u8]) -> Self {
        let mut bytes = Vec::with_capacity(bslice.len());
        bytes.extend_from_slice(bslice);
        VecPacket { bytes }
    }
}

#[cfg(any(feature = "std", test))]
impl Packet for VecPacket {}

#[cfg(any(feature = "std", test))]
pub struct VecPacketReader<'a> {
    pkt: &'a mut VecPacket,
    pos: usize,
}

#[cfg(any(feature = "std", test))]
impl<'a> VecPacketReader<'a> {
    pub fn new(pkt: &'a mut VecPacket) -> VecPacketReader<'a> {
        VecPacketReader { pkt, pos: 0 }
    }
}

#[cfg(any(feature = "std", test))]
impl<'a> PacketReader for VecPacketReader<'a> {
    fn get_slice(
        &mut self,
        len: usize,
    ) -> core::result::Result<&[u8], ReadErr> {
        if self.pos + len > self.pkt.bytes.len() {
            return Err(ReadErr::NotEnoughBytes);
        }

        let s = &self.pkt.bytes[self.pos..self.pos + len];
        self.pos += len;
        Ok(s)
    }

    fn get_slice_mut(
        &mut self,
        len: usize,
    ) -> core::result::Result<&mut [u8], ReadErr> {
        if self.pos + len > self.pkt.bytes.len() {
            return Err(ReadErr::NotEnoughBytes);
        }

        let s = &mut self.pkt.bytes[self.pos..self.pos + len];
        self.pos += len;
        Ok(s)
    }

    fn read_bytes(&mut self, dst: &mut [u8]) -> Result<()> {
        if self.pos + dst.len() > self.pkt.bytes.len() {
            return Err(ReadErr::NotEnoughBytes);
        }

        dst.clone_from_slice(&self.pkt.bytes[self.pos..self.pos + dst.len()]);
        self.pos += dst.len();
        Ok(())
    }

    fn read_u8(&mut self, dst: &mut u8) -> Result<()> {
        if self.pos + 1 > self.pkt.bytes.len() {
            return Err(ReadErr::NotEnoughBytes);
        }

        *dst = self.pkt.bytes[self.pos];
        self.pos += 1;
        Ok(())
    }

    fn read_u16(&mut self, dst: &mut u16) -> Result<()> {
        if self.pos + 2 > self.pkt.bytes.len() {
            return Err(ReadErr::NotEnoughBytes);
        }

        *dst = u16::from_be_bytes(
            (&self.pkt.bytes[self.pos..self.pos + 2]).try_into().unwrap(),
        );
        self.pos += 2;
        Ok(())
    }

    fn read_u32(&mut self, dst: &mut u32) -> Result<()> {
        if self.pos + 4 > self.pkt.bytes.len() {
            return Err(ReadErr::NotEnoughBytes);
        }

        *dst = u32::from_be_bytes(
            (&self.pkt.bytes[self.pos..self.pos + 4]).try_into().unwrap(),
        );
        self.pos += 4;
        Ok(())
    }

    fn seek_back(&mut self, offset: usize) -> Result<()> {
        if offset > self.pos {
            return Err(ReadErr::NotEnoughBytes);
        }

        self.pos -= offset;
        Ok(())
    }

    fn seek(&mut self, offset: usize) -> Result<()> {
        if self.pos + offset > self.pkt.bytes.len() {
            return Err(ReadErr::NotEnoughBytes);
        }

        self.pos += offset;
        Ok(())
    }
}

#[repr(align(64))]
#[derive(Debug)]
pub struct PacketMetaOld {
    pub dir: Direction,
    pub packet_len: u32,
    pub ether_src: EtherAddr,
    pub ether_dst: EtherAddr,
    pub ip_src: Ipv4Addr,
    pub ip_dst: Ipv4Addr,
    pub ip_proto: Protocol,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_seq: Option<u32>,
    pub tcp_ack: Option<u32>,
    pub tcp_flags: u8,
}

impl PacketMetaOld {
    pub fn new(dir: Direction) -> Self {
        PacketMetaOld {
            dir,
            packet_len: 0,
            ether_src: [0; 6],
            ether_dst: [0; 6],
            ip_src: 0.into(),
            ip_dst: 0.into(),
            ip_proto: Protocol::TCP,
            src_port: None,
            dst_port: None,
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: 0,
        }
    }

    pub fn has_tcp_flag(&self, flag: u8) -> bool {
        (self.tcp_flags & flag) != 0
    }
}
