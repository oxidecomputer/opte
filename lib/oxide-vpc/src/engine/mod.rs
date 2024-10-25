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
use opte::engine::arp;
use opte::engine::arp::ArpEthIpv4Ref;
use opte::engine::arp::ArpOp;
use opte::engine::arp::ValidArpEthIpv4;
use opte::engine::arp::ARP_HTYPE_ETHERNET;
use opte::engine::ether::EthernetRef;
use opte::engine::flow_table::FlowTable;
use opte::engine::ingot_packet::FullParsed;
use opte::engine::ingot_packet::OpteParsed2;
use opte::engine::ingot_packet::Packet2;
use opte::engine::ip::v4::Ipv4Addr;
use opte::engine::packet::InnerFlowId;
use opte::engine::packet::ParseError;
use opte::engine::parse::ValidGeneveOverV6;
use opte::engine::parse::ValidNoEncap;
use opte::engine::port::UftEntry;
use opte::engine::Direction;
use opte::engine::HdlPktAction;
use opte::engine::HdlPktError;
use opte::engine::NetworkImpl;
use opte::engine::NetworkParser;
use opte::ingot::ethernet::Ethertype;
use opte::ingot::types::HeaderParse;
use opte::ingot::types::Read;
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

fn is_arp_req(arp: &impl ArpEthIpv4Ref) -> bool {
    arp.htype() == ARP_HTYPE_ETHERNET
        && arp.ptype() == Ethertype::IPV4
        && arp.op() == ArpOp::REQUEST
}

fn is_arp_req_for_tpa(tpa: Ipv4Addr, arp: &impl ArpEthIpv4Ref) -> bool {
    is_arp_req(arp) && arp.tpa() == tpa
}

impl VpcNetwork {
    fn handle_arp_out<T: Read>(
        &self,
        pkt: &mut Packet2<FullParsed<T>>,
    ) -> Result<HdlPktAction, HdlPktError>
    where
        T::Chunk: ByteSliceMut,
    {
        let body = pkt
            .body_segs()
            .and_then(|v| v.get(0))
            .ok_or_else(|| HdlPktError("outbound ARP (no body)"))?;

        let (arp, ..) = ValidArpEthIpv4::parse(*body)
            .map_err(|_| HdlPktError("outbound ARP (parse)"))?;

        if !arp.values_valid() {
            return Err(HdlPktError("outbound ARP (parse -- bad values)"));
        }

        let gw_ip = self.cfg.ipv4_cfg().unwrap().gateway_ip;

        if is_arp_req_for_tpa(gw_ip, &arp) {
            let gw_mac = self.cfg.gateway_mac;

            let hp = arp::gen_arp_reply(gw_mac, gw_ip, arp.sha(), arp.spa());
            return Ok(HdlPktAction::Hairpin(hp));
        }

        Ok(HdlPktAction::Deny)
    }
}

impl NetworkImpl for VpcNetwork {
    type Parser = VpcParser;

    fn handle_pkt<T: Read>(
        &self,
        dir: Direction,
        pkt: &mut Packet2<FullParsed<T>>,
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
    type InMeta<T: ByteSliceMut> = ValidGeneveOverV6<T>;
    type OutMeta<T: ByteSliceMut> = ValidNoEncap<T>;

    #[inline]
    fn parse_outbound<'a, T: Read + 'a>(
        &self,
        rdr: T,
    ) -> Result<OpteParsed2<T, Self::OutMeta<T::Chunk>>, ParseError>
    where
        T::Chunk: opte::ingot::types::IntoBufPointer<'a> + ByteSliceMut,
    {
        Ok(ValidNoEncap::parse_read(rdr)?)
    }

    #[inline]
    fn parse_inbound<'a, T: Read + 'a>(
        &self,
        rdr: T,
    ) -> Result<OpteParsed2<T, Self::InMeta<T::Chunk>>, ParseError>
    where
        T::Chunk: opte::ingot::types::IntoBufPointer<'a> + ByteSliceMut,
    {
        Ok(ValidGeneveOverV6::parse_read(rdr)?)
    }
}
