// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Routines for building packet capture files.

use opte::ddi::mblk::MsgBlk;
use pcap_parser::Linktype;
use pcap_parser::ToVec;
use pcap_parser::pcap;
use pcap_parser::pcap::LegacyPcapBlock;
use pcap_parser::pcap::PcapHeader;
use std::fs::File;
use std::io::Write;

#[allow(dead_code)]
fn get_header(offset: &[u8]) -> (&[u8], PcapHeader) {
    match pcap::parse_pcap_header(offset) {
        Ok((new_offset, header)) => (new_offset, header),
        Err(e) => panic!("failed to get header: {e:?}"),
    }
}

#[allow(dead_code)]
fn next_block(offset: &[u8]) -> (&[u8], LegacyPcapBlock<'_>) {
    match pcap::parse_pcap_frame(offset) {
        Ok((new_offset, block)) => {
            // We always want access to the entire packet.
            assert_eq!(block.origlen, block.caplen);
            (new_offset, block)
        }

        Err(e) => panic!("failed to get next block: {e:?}"),
    }
}

/// Build a packet capture file from a series of packets.
pub struct PcapBuilder {
    file: File,
}

impl PcapBuilder {
    /// Create a new pcap builder, writing all captures to `path`.
    pub fn new(path: &str) -> Self {
        let mut file = File::create(path).unwrap();

        let mut hdr = PcapHeader {
            magic_number: 0xa1b2c3d4,
            version_major: 2,
            version_minor: 4,
            thiszone: 0,
            sigfigs: 0,
            snaplen: 1500,
            network: Linktype::ETHERNET,
        };

        file.write_all(&hdr.to_vec().unwrap()).unwrap();

        Self { file }
    }

    /// Add a packet to the capture.
    pub fn add_pkt(&mut self, pkt: &MsgBlk) {
        let pkt_bytes = pkt.copy_all();
        let mut block = LegacyPcapBlock {
            ts_sec: 7777,
            ts_usec: 7777,
            caplen: pkt_bytes.len() as u32,
            origlen: pkt_bytes.len() as u32,
            data: &pkt_bytes,
        };

        self.file.write_all(&block.to_vec().unwrap()).unwrap();
    }
}
