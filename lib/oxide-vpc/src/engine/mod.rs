// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

pub mod attached_subnets;
pub mod firewall;
pub mod gateway;
pub mod geneve;
pub mod nat;
pub mod overlay;
pub mod router;

use crate::cfg::VpcCfg;
use core::ops::Deref;
use opte::engine::Direction;
use opte::engine::HdlPktAction;
use opte::engine::HdlPktError;
use opte::engine::LightweightMeta;
use opte::engine::NetworkImpl;
use opte::engine::NetworkParser;
use opte::engine::arp;
use opte::engine::arp::ARP_HTYPE_ETHERNET;
use opte::engine::arp::ArpEthIpv4Ref;
use opte::engine::arp::ArpOp;
use opte::engine::arp::ValidArpEthIpv4;
use opte::engine::checksum::Checksum;
use opte::engine::ether::EthernetRef;
use opte::engine::flow_table::FlowTable;
use opte::engine::ip::v4::Ipv4Addr;
use opte::engine::packet::FullParsed;
use opte::engine::packet::InnerFlowId;
use opte::engine::packet::OpteMeta;
use opte::engine::packet::Packet;
use opte::engine::packet::ParseError;
use opte::engine::packet::Pullup;
use opte::engine::parse::ValidGeneveOverV6;
use opte::engine::parse::ValidNoEncap;
use opte::engine::port::UftEntry;
use opte::engine::rule::CompiledTransform;
use opte::ingot::ethernet::Ethertype;
use opte::ingot::types::HeaderParse;
use opte::ingot::types::IntoBufPointer;
use opte::ingot::types::Parsed as IngotParsed;
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

fn is_arp_req(arp: &impl ArpEthIpv4Ref) -> bool {
    arp.htype() == ARP_HTYPE_ETHERNET
        && arp.ptype() == Ethertype::IPV4
        && arp.op() == ArpOp::REQUEST
}

fn is_arp_req_for_tpa(tpa: Ipv4Addr, arp: &impl ArpEthIpv4Ref) -> bool {
    is_arp_req(arp) && arp.tpa() == tpa
}

impl VpcNetwork {
    fn handle_arp_out<'a, T: Read + Pullup + 'a>(
        &self,
        pkt: &mut Packet<FullParsed<T>>,
    ) -> Result<HdlPktAction, HdlPktError>
    where
        T::Chunk: ByteSliceMut + IntoBufPointer<'a>,
    {
        let body = pkt.body().ok_or(HdlPktError("outbound ARP (no body)"))?;

        let (arp, ..) = ValidArpEthIpv4::parse(body)
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

    fn handle_pkt<'a, T: Read + Pullup + 'a>(
        &self,
        dir: Direction,
        pkt: &mut Packet<FullParsed<T>>,
        _uft_in: &FlowTable<UftEntry<InnerFlowId>>,
        _uft_out: &FlowTable<UftEntry<InnerFlowId>>,
    ) -> Result<HdlPktAction, HdlPktError>
    where
        T::Chunk: ByteSliceMut + IntoBufPointer<'a>,
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
    type InMeta<T: ByteSliceMut> = OxideGeneve<T>;
    type OutMeta<T: ByteSliceMut> = ValidNoEncap<T>;

    #[inline(always)]
    fn parse_outbound<'a, T: Read + 'a>(
        &self,
        rdr: T,
    ) -> Result<IngotParsed<Self::OutMeta<T::Chunk>, T>, ParseError>
    where
        T::Chunk: opte::ingot::types::IntoBufPointer<'a> + ByteSliceMut,
    {
        Ok(ValidNoEncap::parse_read(rdr)?)
    }

    #[inline(always)]
    fn parse_inbound<'a, T: Read + 'a>(
        &self,
        rdr: T,
    ) -> Result<IngotParsed<Self::InMeta<T::Chunk>, T>, ParseError>
    where
        T::Chunk: opte::ingot::types::IntoBufPointer<'a> + ByteSliceMut,
    {
        let IngotParsed { headers, last_chunk, data } =
            ValidGeneveOverV6::parse_read(rdr)?;

        Ok(IngotParsed { last_chunk, data, headers: OxideGeneve(headers) })
    }
}

#[repr(transparent)]
pub struct OxideGeneve<T: ByteSlice>(pub ValidGeneveOverV6<T>);

impl<T: ByteSlice> Deref for OxideGeneve<T> {
    type Target = ValidGeneveOverV6<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: ByteSliceMut> LightweightMeta<T> for OxideGeneve<T> {
    #[inline]
    fn run_compiled_transform(&mut self, transform: &CompiledTransform)
    where
        T: ByteSliceMut,
    {
        self.0.run_compiled_transform(transform);
    }

    #[inline]
    fn compute_body_csum(&self) -> Option<Checksum> {
        self.0.compute_body_csum()
    }

    #[inline]
    fn flow(&self) -> InnerFlowId {
        self.0.flow()
    }

    #[inline]
    fn encap_len(&self) -> u16 {
        self.0.encap_len()
    }

    #[inline]
    fn update_inner_checksums(&mut self, body_csum: Option<Checksum>) {
        self.0.update_inner_checksums(body_csum);
    }

    #[inline]
    fn inner_tcp(&self) -> Option<&impl ingot::tcp::TcpRef<T>> {
        self.0.inner_tcp()
    }

    #[inline]
    fn validate(&self, pkt_len: usize) -> Result<(), ParseError> {
        self.0.validate(pkt_len)?;

        geneve::validate_options(&self.0.outer_encap)
    }
}

impl<T: ByteSlice> From<OxideGeneve<T>> for OpteMeta<T> {
    #[inline]
    fn from(value: OxideGeneve<T>) -> Self {
        value.0.into()
    }
}
