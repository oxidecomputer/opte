// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

pub mod firewall;
pub mod gateway;
pub mod nat;
pub mod overlay;
#[cfg(any(feature = "std", test))]
pub mod print;
pub mod router;

use crate::cfg::VpcCfg;
use opte::engine::ether::EtherType;
use opte::engine::flow_table::FlowTable;
use opte::engine::headers::EncapMeta;
use opte::engine::ingot_packet::GeneveOverV6;
use opte::engine::ingot_packet::MsgBlk;
use opte::engine::ingot_packet::NoEncap;
use opte::engine::ingot_packet::OpteMeta;
use opte::engine::ingot_packet::OpteParsed;
use opte::engine::ingot_packet::Packet2;
use opte::engine::ingot_packet::Parsed2;
use opte::engine::ingot_packet::ValidGeneveOverV6;
use opte::engine::ingot_packet::ValidNoEncap;
use opte::engine::ip4::Protocol;
use opte::engine::packet::HeaderOffsets;
use opte::engine::packet::InnerFlowId;
use opte::engine::packet::Packet;
use opte::engine::packet::PacketInfo;
use opte::engine::packet::PacketMeta;
use opte::engine::packet::PacketRead;
use opte::engine::packet::PacketReaderMut;
use opte::engine::packet::ParseError;
use opte::engine::packet::Parsed;
use opte::engine::port::UftEntry;
use opte::engine::Direction;
use opte::engine::HdlPktAction;
use opte::engine::HdlPktError;
use opte::engine::NetworkImpl;
use opte::engine::NetworkParser;

use opte::engine::arp;
use opte::engine::arp::ArpEthIpv4;
use opte::engine::arp::ArpOp;
use opte::engine::ether::ETHER_TYPE_IPV4;
use opte::engine::ingot_base::EthernetRef;
use opte::engine::ip4::Ipv4Addr;
use opte::ingot::ethernet::Ethertype;
use opte::ingot::types::Read;
use zerocopy::ByteSlice;
use zerocopy::ByteSliceMut;

#[derive(Clone, Copy, Debug, Default)]
pub struct VpcParser {}

impl VpcParser {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Clone, Debug)]
pub struct VpcNetwork {
    pub cfg: VpcCfg,
}

// The ARP HTYPE for Ethernet.
const HTYPE_ETHER: u16 = 1;

fn is_arp_req(arp: &ArpEthIpv4) -> bool {
    arp.htype == HTYPE_ETHER
        && arp.ptype == ETHER_TYPE_IPV4
        && arp.op == ArpOp::Request
}

fn is_arp_req_for_tpa(tpa: Ipv4Addr, arp: &ArpEthIpv4) -> bool {
    is_arp_req(arp) && arp.tpa == tpa
}

impl VpcNetwork {
    fn handle_arp_out<T: Read>(
        &self,
        pkt: &mut Packet2<Parsed2<T>>,
    ) -> Result<HdlPktAction, HdlPktError>
    where
        T::Chunk: ByteSliceMut,
    {
        let body = pkt
            .body_segs()
            .ok_or_else(|| HdlPktError("outbound ARP (no body)"))?;
        let arp = ArpEthIpv4::parse_normally(body)
            .map_err(|_| HdlPktError("outbound ARP (parse)"))?;
        let gw_ip = self.cfg.ipv4_cfg().unwrap().gateway_ip;

        if is_arp_req_for_tpa(gw_ip, &arp) {
            let gw_mac = self.cfg.gateway_mac;

            let hp = arp::gen_arp_reply(gw_mac, gw_ip, arp.sha, arp.spa);
            // TODO: just emit into an mblk normally.
            return Ok(HdlPktAction::Hairpin(
                unsafe { MsgBlk::wrap_mblk(hp.unwrap_mblk()) }
                    .expect("known valid"),
            ));
        }

        Ok(HdlPktAction::Deny)
    }
}

impl NetworkImpl for VpcNetwork {
    type Parser = VpcParser;

    fn handle_pkt<T: Read>(
        &self,
        dir: Direction,
        pkt: &mut Packet2<Parsed2<T>>,
        _uft_in: &FlowTable<UftEntry<InnerFlowId>>,
        _uft_out: &FlowTable<UftEntry<InnerFlowId>>,
    ) -> Result<HdlPktAction, HdlPktError>
    where
        T::Chunk: ByteSliceMut,
    {
        match (dir, pkt.meta().inner_ether().ethertype()) {
            (Direction::Out, Ethertype::ARP) => self.handle_arp_out(pkt),

            _ => Ok(HdlPktAction::Deny),
        }
    }

    fn parser(&self) -> Self::Parser {
        VpcParser {}
    }
}

impl NetworkParser for VpcParser {
    type InMeta<T: ByteSlice> = ValidGeneveOverV6<T>;
    type OutMeta<T: ByteSlice> = ValidNoEncap<T>;

    #[inline]
    fn parse_outbound<'a, T: Read + 'a>(
        &self,
        rdr: T,
    ) -> Result<OpteParsed<T>, ParseError>
    where
        T::Chunk: opte::ingot::types::IntoBufPointer<'a>,
    {
        let v = NoEncap::parse_read(rdr);
        Ok(OpteMeta::convert_ingot(v?))
    }

    #[inline]
    fn parse_inbound<'a, T: Read + 'a>(
        &self,
        rdr: T,
    ) -> Result<OpteParsed<T>, ParseError>
    where
        T::Chunk: opte::ingot::types::IntoBufPointer<'a>,
    {
        let v = GeneveOverV6::parse_read(rdr);
        Ok(OpteMeta::convert_ingot(v?))
    }
}
