// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Implementation of the main message types for DHCPv6.

use super::Dhcpv6Action;
use super::TransactionId;
use crate::engine::checksum::HeaderChecksum;
use crate::engine::dhcpv6::options::Code as OptionCode;
use crate::engine::dhcpv6::options::IaAddr;
use crate::engine::dhcpv6::options::IaNa;
use crate::engine::dhcpv6::options::IpList;
use crate::engine::dhcpv6::options::Option as Dhcpv6Option;
use crate::engine::dhcpv6::options::Status;
use crate::engine::dhcpv6::options::StatusCode;
use crate::engine::dhcpv6::Duid;
use crate::engine::dhcpv6::Lifetime;
use crate::engine::dhcpv6::ALL_RELAYS_AND_SERVERS;
use crate::engine::dhcpv6::ALL_SERVERS;
use crate::engine::dhcpv6::CLIENT_PORT;
use crate::engine::dhcpv6::SERVER_PORT;
use crate::engine::ether::EtherHdr;
use crate::engine::ether::EtherMeta;
use crate::engine::ether::EtherType;
use crate::engine::ingot_packet::MsgBlk;
use crate::engine::ingot_packet::PacketHeaders2;
use crate::engine::ip6::Ipv6Hdr;
use crate::engine::ip6::Ipv6Meta;
use crate::engine::ip6::UlpCsumOpt;
use crate::engine::packet::Packet;
use crate::engine::packet::PacketMeta;
use crate::engine::packet::PacketRead;
use crate::engine::packet::PacketReader;
use crate::engine::predicate::DataPredicate;
use crate::engine::predicate::EtherAddrMatch;
use crate::engine::predicate::IpProtoMatch;
use crate::engine::predicate::Ipv6AddrMatch;
use crate::engine::predicate::PortMatch;
use crate::engine::predicate::Predicate;
use crate::engine::rule::AllowOrDeny;
use crate::engine::rule::GenPacketResult;
use crate::engine::rule::HairpinAction;
use crate::engine::udp::UdpHdr;
use crate::engine::udp::UdpMeta;
use alloc::borrow::Cow;
use alloc::vec::Vec;
use core::fmt;
use core::ops::Range;
use ingot::ip::Ipv6Ref;
use opte_api::Ipv6Addr;
use opte_api::Ipv6Cidr;
use opte_api::MacAddr;
use opte_api::Protocol;
use serde::Deserialize;
use serde::Serialize;
use smoltcp::wire::IpProtocol;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum MessageType {
    Solicit,
    Advertise,
    Request,
    Confirm,
    Renew,
    Reply,
    InformationRequest,
    Other(u8),
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use MessageType::*;
        match self {
            Other(x) => write!(f, "Other({})", x),
            other => write!(
                f,
                "{}",
                match other {
                    Solicit => "Solicit",
                    Advertise => "Advertise",
                    Request => "Request",
                    Confirm => "Confirm",
                    Renew => "Renew",
                    Reply => "Reply",
                    InformationRequest => "InformationRequest",
                    _ => unreachable!(),
                }
            ),
        }
    }
}

impl From<u8> for MessageType {
    fn from(x: u8) -> Self {
        use MessageType::*;
        match x {
            1 => Solicit,
            2 => Advertise,
            3 => Request,
            4 => Confirm,
            5 => Renew,
            7 => Reply,
            11 => InformationRequest,
            x => Other(x),
        }
    }
}

impl From<MessageType> for u8 {
    fn from(mt: MessageType) -> Self {
        use MessageType::*;
        match mt {
            Solicit => 1,
            Advertise => 2,
            Request => 3,
            Confirm => 4,
            Renew => 5,
            Reply => 7,
            InformationRequest => 11,
            Other(x) => x,
        }
    }
}

impl PartialOrd for MessageType {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        u8::from(*self).partial_cmp(&u8::from(*other))
    }
}

/// A DHCPv6 message.
///
/// All DHCPv6 transactions occur through this type. Clients send messages,
/// usually requesting information about available servers or that particular
/// data be assigned to them. (The latter occurs through options.) Servers
/// respond with the same format, according to the protocol laid out in RFC
/// 8415, section 18.
#[derive(Clone, Debug)]
pub struct Message<'a> {
    /// The [`MessageType`] of this message.
    pub typ: MessageType,
    /// The transaction ID for this message.
    pub xid: TransactionId<'a>,
    /// The options contained in this message.
    pub options: Vec<Dhcpv6Option<'a>>,
}

impl<'a> Message<'a> {
    const TYPE: usize = 0;
    const XID: Range<usize> = 1..4;
    const DATA: usize = 4;

    /// Parse a message from the provided bytes, if it is valid. If not, return
    /// `None`.
    pub fn from_bytes(buf: &'a [u8]) -> Option<Self> {
        if buf.len() <= Self::DATA {
            return None;
        }
        let typ = MessageType::from(buf[Self::TYPE]);
        let xid = TransactionId(buf[Self::XID].into());
        let mut start = Self::DATA;
        let mut options = Vec::new();
        while start < buf.len() {
            let opt = Dhcpv6Option::from_bytes(&buf[start..]).ok()?;
            start += opt.buffer_len();
            options.push(opt);
        }
        Some(Self { typ, xid, options })
    }

    /// Return the Client DUID in the message, if any.
    pub fn client_duid(&self) -> Option<&Duid<'a>> {
        if let Dhcpv6Option::ClientId(duid) =
            self.find_option(OptionCode::ClientId)?
        {
            Some(duid)
        } else {
            None
        }
    }

    /// Return the Server DUID in the message, if any.
    pub fn server_duid(&self) -> Option<&Duid<'a>> {
        if let Dhcpv6Option::ServerId(duid) =
            self.find_option(OptionCode::ServerId)?
        {
            Some(duid)
        } else {
            None
        }
    }

    /// Return `true` if the message contains an option of the given type.
    pub fn has_option(&self, code: OptionCode) -> bool {
        self.find_option(code).is_some()
    }

    /// Return `true` if the message has an Option Request option, which
    /// contains the provided type.
    pub fn has_option_request_with(&self, code: OptionCode) -> bool {
        if let Some(Dhcpv6Option::OptionRequest(opts)) =
            self.find_option(OptionCode::OptionRequest)
        {
            opts.contains(code)
        } else {
            false
        }
    }

    /// Return the _first_ contained option of the provided type, or `None` if
    /// the message does not contain such an option.
    ///
    /// Note that this does not "recurse" into container options, such as the
    /// Option Request option. It only finds options at the top-level.
    pub fn find_option(&self, code: OptionCode) -> Option<&Dhcpv6Option<'a>> {
        self.options.iter().find(|opt| opt.code() == code)
    }

    /// Return an iterator over options of the provided type.
    pub fn option_iter(
        &self,
        code: OptionCode,
    ) -> impl Iterator<Item = &Dhcpv6Option<'a>> {
        self.options.iter().filter(move |opt| opt.code() == code)
    }

    /// Return `true` if this contains the Rapid Commit option, either at the
    /// top-level, or inside the Option Request container option.
    pub fn has_rapid_commit(&self) -> bool {
        // Look for top-level option first.
        if self.has_option(OptionCode::RapidCommit) {
            return true;
        }

        // Look for the Rapid Commit option contained in the Option Request
        // option.
        self.has_option_request_with(OptionCode::RapidCommit)
    }

    fn option_len(&self) -> usize {
        self.options.iter().map(|opt| opt.buffer_len()).sum()
    }

    /// Return the total length of the buffer required to contain the bytes of
    /// this DHCPv6 message.
    pub fn buffer_len(&self) -> usize {
        core::mem::size_of::<u8>() + TransactionId::SIZE + self.option_len()
    }

    /// Write this message into the provided buffer. If the buffer is not large
    /// enough, `None` is returned. The minimum size can be retrieved with
    /// `Message::buffer_len()`.
    pub fn copy_into(&self, buf: &mut [u8]) -> Option<()> {
        let len = self.buffer_len();
        if buf.len() < len {
            return None;
        }
        buf[Self::TYPE] = u8::from(self.typ);
        buf[Self::XID].copy_from_slice(&self.xid.0);
        let mut start = Self::DATA;
        for opt in &self.options {
            opt.copy_into(&mut buf[start..]).ok()?;
            start += opt.buffer_len();
        }
        Some(())
    }
}

// General packet header predicates to identify a DHCPv6 message from client to
// a server.
fn dhcpv6_server_predicates(client_mac: &MacAddr) -> Vec<Predicate> {
    // NOTE: We do not predicate receipt of DHCP messages on the Layer 2
    // address. See RFC 8415 Section 14.2
    // (https://www.rfc-editor.org/rfc/rfc8415.html#section-14), which
    // specifically says:
    //
    // > DHCP servers SHOULD NOT check to see whether the Layer 2 address
    // > used was multicast or not, as long as the Layer 3 address was
    // > correct.

    vec![
        // Request must come from the guest's MAC address
        Predicate::InnerEtherSrc(vec![EtherAddrMatch::Exact(*client_mac)]),
        // Request must come from a link-local address
        Predicate::InnerSrcIp6(vec![Ipv6AddrMatch::Prefix(
            Ipv6Cidr::LINK_LOCAL,
        )]),
        // Must be destined to one of the supported IPv6 multicast addresses.
        Predicate::InnerDstIp6(vec![
            Ipv6AddrMatch::Exact(ALL_RELAYS_AND_SERVERS),
            Ipv6AddrMatch::Exact(ALL_SERVERS),
        ]),
        // DHCPv6 runs over UDP
        Predicate::InnerIpProto(vec![IpProtoMatch::Exact(Protocol::UDP)]),
        // Request must be from the client port
        Predicate::InnerSrcPort(vec![PortMatch::Exact(CLIENT_PORT)]),
        // and destined to the server port
        Predicate::InnerDstPort(vec![PortMatch::Exact(SERVER_PORT)]),
    ]
}

// Panics: This panics if `msg` does not have a Client ID option in it.
fn generate_reply_options<'a>(
    action: &'a Dhcpv6Action,
    msg: &'a Message,
) -> Vec<Dhcpv6Option<'a>> {
    // We always send the Client ID that was included in the original message,
    // along with our Server ID option.
    let mut options = vec![
        server_id(action),
        // Safety: Callers are supposed to check that `msg` has a Client ID
        // option in it already.
        msg.find_option(OptionCode::ClientId).unwrap().clone(),
    ];

    // If requested, provide the list of DNS servers.
    if msg.has_option_request_with(OptionCode::DnsServers) {
        let ip_list = IpList(Cow::Borrowed(&action.dhcp_cfg.dns6_servers));
        let opt = Dhcpv6Option::DnsServers(ip_list);
        options.push(opt);
    }

    // Add the leased address(es), if they were requested, along with the IAID
    // provided by the client.
    //
    // TODO-correctness: The client can technically include many of these, so
    // `find_option` isn't enough, we need to find _all_ such options.
    if let Some(Dhcpv6Option::IaNa(requested_iana)) =
        msg.find_option(OptionCode::IaNa)
    {
        let ia_addrs = action
            .addrs
            .addrs
            .iter()
            .map(|lease| {
                Dhcpv6Option::IaAddr(IaAddr {
                    addr: lease.addr,
                    valid: Lifetime(lease.valid()),
                    preferred: Lifetime(lease.preferred()),
                    options: vec![],
                })
            })
            .collect();
        let iana = IaNa {
            id: requested_iana.id,
            t1: Lifetime(action.addrs.renew),
            t2: Lifetime(action.addrs.renew),
            options: ia_addrs,
        };
        options.push(Dhcpv6Option::IaNa(iana));
    }

    // If requested, provide the Domain Search List option.
    //
    // This is a list of domain names appended to hostnames before trying to
    // resolve them.
    if (msg.has_option(OptionCode::DomainList)
        || msg.has_option_request_with(OptionCode::DomainList))
        && !action.dhcp_cfg.domain_search_list.is_empty()
    {
        let opt =
            Dhcpv6Option::from(action.dhcp_cfg.domain_search_list.as_slice());

        // Slightly hacky assertion that the contents are owned.
        let Dhcpv6Option::DomainList(Cow::Owned(raw_list)) = opt else {
            panic!(
                "DHCPv6 DomainList creation allocs into new vec -- not found?"
            )
        };

        options.push(Dhcpv6Option::DomainList(Cow::Owned(raw_list)));
    }

    if msg.has_option(OptionCode::Fqdn)
        || msg.has_option_request_with(OptionCode::Fqdn)
    {
        // XXX: We should verify customer flow here -- correct
        //      for internal DNS, maybe not external?
        // Flags: we are (O)verriding client preference, and (S)erver is
        // installing AAAA DNS records, and server isn't (N)ot installing
        // any DNS records (yes, this is a negative flag).
        // https://datatracker.ietf.org/doc/html/rfc4704#section-4.1
        //                   xxxx_xNOS
        let mut buf = vec![0b0000_0011u8];
        action.dhcp_cfg.push_fqdn(&mut buf);

        // XXX: May want to reflect client's hostname request if
        //      we have no override.
        if buf.len() != 1 {
            options.push(Dhcpv6Option::Fqdn(Cow::Owned(buf)));
        }
    }
    options
}

// Handle a Solicit message, possibly with the Rapid Commit option.
//
// This results in a Reply message or and Advertise, depending on the message
// type and its options:
//
// - Solicit -> Advertise
// - Solicit + Rapid Commit -> Reply
//
// A reply to be sent back to the client is returned in `Some(_)`. If the
// message should be dropped, `None` is returned instead.
fn process_solicit_message<'a>(
    action: &'a Dhcpv6Action,
    client_msg: &'a Message<'a>,
) -> Option<Message<'a>> {
    // Solicit messages must not have a Server ID.
    if client_msg.has_option(OptionCode::ServerId) {
        return None;
    }

    // Must include an Elapsed Time option.
    if !client_msg.has_option(OptionCode::ElapsedTime) {
        return None;
    }

    // Must have a Client ID option.
    if !client_msg.has_option(OptionCode::ClientId) {
        return None;
    }

    // Generate all the options we'll send back to the client.
    let mut options = generate_reply_options(action, client_msg);

    // Set the message type.
    //
    // If the client sends a Solicit with Rapid Commit, we have to send back a
    // Reply. Otherwise we send an Advertise message, but it still contains all
    // the data we _would_ lease to the client.
    //
    // Note that if the message included the Rapid Commit option, we're also
    // required to send that back to the client as well. See
    // https://www.rfc-editor.org/rfc/rfc8415.html#section-21.14 for details.
    let reply_type = if client_msg.has_rapid_commit() {
        options.push(Dhcpv6Option::RapidCommit);
        MessageType::Reply
    } else {
        MessageType::Advertise
    };
    Some(Message { typ: reply_type, xid: client_msg.xid.clone(), options })
}

// Handle a Request message.
//
// This always results in a Reply message.
//
// A reply to be sent back to the client is returned in `Some(_)`. If the
// message should be dropped, `None` is returned instead.
fn process_request_message<'a>(
    action: &'a Dhcpv6Action,
    client_msg: &'a Message<'a>,
) -> Option<Message<'a>> {
    // Request messages must contain a Server ID, that matches our own.
    match client_msg.server_duid() {
        None => return None,
        Some(id) if !id.is_duid_ll_mac(&action.server_mac) => return None,
        _ => {}
    }

    // Must include an Elapsed Time option.
    if !client_msg.has_option(OptionCode::ElapsedTime) {
        return None;
    }

    // Must have a Client ID option.
    if !client_msg.has_option(OptionCode::ClientId) {
        return None;
    }

    // Generate all the options we'll send back to the client.
    let options = generate_reply_options(action, client_msg);

    let typ = MessageType::Reply;
    Some(Message { typ, xid: client_msg.xid.clone(), options })
}

// Return the server's DUID itself.
fn server_duid(action: &Dhcpv6Action) -> Duid<'_> {
    Duid::from(&action.server_mac)
}

// Return the DHCPv6 Option containing the server's DUID.
fn server_id(action: &Dhcpv6Action) -> Dhcpv6Option<'_> {
    Dhcpv6Option::ServerId(server_duid(action))
}

// Handle a Confirm message.
//
// See https://www.rfc-editor.org/rfc/rfc8415.html#section-18.3.3 for details of
// how servers are required to process such messages. Section 16.5 also includes
// a bit of information about validation.
//
// A reply to be sent back to the client is returned in `Some(_)`. If the
// message should be dropped, `None` is returned instead.
fn process_confirm_message<'a>(
    action: &'a Dhcpv6Action,
    client_msg: &'a Message<'a>,
) -> Option<Message<'a>> {
    // Client must include a Client ID.
    let client_id = client_msg.find_option(OptionCode::ClientId)?;

    // Client must not include a Server ID.
    if client_msg.has_option(OptionCode::ServerId) {
        return None;
    }

    // Client must include an Elapsed Time.
    if !client_msg.has_option(OptionCode::ElapsedTime) {
        return None;
    }

    let mut reply_options = vec![server_id(action), client_id.clone()];

    // The client should be sending us IAs for each IPv6 address we've leased to
    // them.
    //
    // If there are _no_ addresses at all, either no IANA option, or that option
    // contains no IA Address options, we don't send a reply, and just drop the
    // packet.
    let iana = client_msg.find_option(OptionCode::IaNa)?;
    if let Dhcpv6Option::IaNa(IaNa { options, .. }) = &iana {
        if options.is_empty() {
            return None;
        }

        // Check that we have the IP addresses "on file". If not, send back a
        // message indicating that the requested addresses are not on-link.
        //
        // NOTE: This may not be exactly right, based on the reading of RFC 8415
        // Section 18.3.3 paragraph 2. That states:
        //
        // > When the server receives a Confirm message, the server determines
        // > whether the addresses in the Confirm message are appropriate for
        // > the link to which the client is attached.  If all of the addresses
        // > in the Confirm message pass this test, the server returns a status
        // > of Success.
        //
        // If the client sends us a message that's on-link, but that we've not
        // leased: (1) that's really weird, and (2) it's not obvious how we
        // should respond. For now, we send back NotOnLink.
        let mut no_addresses = true;
        for option in options.iter() {
            if let Dhcpv6Option::IaNa(IaNa { options: inner_opt, .. }) = option
            {
                for opt in inner_opt.iter() {
                    if let Dhcpv6Option::IaAddr(IaAddr { addr, .. }) = opt {
                        // We've found at least one IA with an address.
                        no_addresses = false;
                        if !action.addresses().any(|a| &a == addr) {
                            // Send back NotOnLink
                            reply_options.push(Dhcpv6Option::Status(Status {
                                code: StatusCode::NotOnLink,
                                message: "Address(es) not on link",
                            }));
                            return Some(Message {
                                typ: MessageType::Reply,
                                xid: client_msg.xid.clone(),
                                options: reply_options,
                            });
                        }
                    }
                }
            }
        }

        // If we found no addresses at all, we have to drop the packet.
        if no_addresses {
            return None;
        }

        // All addresses in the Confirm message match those stored in the
        // `Action`, so things all look good. Send back a success.
        reply_options.push(Dhcpv6Option::Status(Status {
            code: StatusCode::Success,
            message: "",
        }));
        Some(Message {
            typ: MessageType::Reply,
            xid: client_msg.xid.clone(),
            options: reply_options,
        })
    } else {
        unreachable!("DHCPv6 Message::find_option returned wrong type.");
    }
}

// Process a DHCPv6 message from the a client.
fn process_client_message<'a>(
    action: &'a Dhcpv6Action,
    _meta: &'a PacketHeaders2,
    client_msg: &'a Message<'a>,
) -> Option<Message<'a>> {
    match client_msg.typ {
        MessageType::Solicit => process_solicit_message(action, client_msg),
        MessageType::Request => process_request_message(action, client_msg),
        MessageType::Confirm => process_confirm_message(action, client_msg),
        // TODO-completeness: Handle other message types.
        //
        // This is pretty low-priority right now. Conforming clients must use
        // the lifetimes we provide in leased addresses, which are currently
        // infinite. However, if we change that, or find some client
        // implementations don't adhere to the standard, we should add that
        // support here.
        _ => None,
    }
}

// Construct a reply packet from the action, given the provided metadata from
// the request and the actual DHCPv6 message to send out.
fn generate_packet<'a>(
    action: &Dhcpv6Action,
    meta: &PacketHeaders2,
    msg: &'a Message<'a>,
) -> GenPacketResult {
    let eth = EtherMeta {
        dst: action.client_mac,
        src: action.server_mac,
        ether_type: EtherType::Ipv6,
    };

    let ip = Ipv6Meta {
        src: Ipv6Addr::from_eui64(&action.server_mac),
        // Safety: We're only here if the predicates match, one of which is
        // IPv6.
        dst: meta.inner_ip6().unwrap().source().octets().into(),
        proto: Protocol::UDP,
        next_hdr: IpProtocol::Udp,
        pay_len: (UdpHdr::SIZE + msg.buffer_len()) as u16,
        ..Default::default()
    };

    let mut udp = UdpMeta {
        src: SERVER_PORT,
        dst: CLIENT_PORT,
        len: (UdpHdr::SIZE + msg.buffer_len()) as u16,
        ..Default::default()
    };

    // Allocate a segment into which we'll write the packet.
    let reply_len =
        msg.buffer_len() + UdpHdr::SIZE + Ipv6Hdr::BASE_SIZE + EtherHdr::SIZE;
    let mut pkt = Packet::alloc_and_expand(reply_len);
    let mut wtr = pkt.seg0_wtr();

    eth.emit(wtr.slice_mut(EtherHdr::SIZE).unwrap());
    ip.emit(wtr.slice_mut(ip.hdr_len()).unwrap());

    // Create the buffer to contain the DHCP message so that we may
    // compute the UDP checksum.
    let mut msg_buf = vec![0; msg.buffer_len()];
    msg.copy_into(&mut msg_buf).unwrap();

    // Compute the UDP checksum. Write the UDP header and DHCP message
    // to the segment.
    let mut udp_buf = [0u8; UdpHdr::SIZE];
    udp.emit(&mut udp_buf);
    let csum = ip.compute_ulp_csum(UlpCsumOpt::Full, &udp_buf, &msg_buf);
    udp.csum = HeaderChecksum::from(csum).bytes();
    udp.emit(wtr.slice_mut(udp.hdr_len()).unwrap());
    wtr.write(&msg_buf).unwrap();
    Ok(AllowOrDeny::Allow(
        unsafe { MsgBlk::wrap_mblk(pkt.unwrap_mblk()) }.expect("known valid"),
    ))
}

impl HairpinAction for Dhcpv6Action {
    fn implicit_preds(&self) -> (Vec<Predicate>, Vec<DataPredicate>) {
        let hdr_preds = dhcpv6_server_predicates(&self.client_mac);
        (hdr_preds, vec![])
    }

    // This does all the heavy lifting for processing DHCPv6 messages from
    // clients. The main reason we don't have an action per-reply is that we can
    // get different replies from the same request type, depending on the data
    // within them (the options).
    //
    // Specifically, a Solicit message can result in either an Advertise or a
    // Request from the server. The former is emitted if the Rapid Commit option
    // is _not_ set, the latter if it is. That Request is the same as if the
    // client had instead submitted a Request message, rather than Solicit
    //
    // Rather than put this logic into DataPredicates, we just parse the packet
    // here and reply accordingly. So the `Dhcpv6Action` is really a full
    // server, to the extent we emulate one.
    fn gen_packet(&self, meta: &PacketHeaders2) -> GenPacketResult {
        let body = meta.copy_remaining();
        if let Some(client_msg) = Message::from_bytes(&body) {
            if let Some(reply) = process_client_message(self, meta, &client_msg)
            {
                generate_packet(self, meta, &reply)
            } else {
                Ok(AllowOrDeny::Deny)
            }
        } else {
            Ok(AllowOrDeny::Deny)
        }
    }
}

#[cfg(test)]
mod test {
    use super::dhcpv6_server_predicates;
    use super::Dhcpv6Option;
    use super::MacAddr;
    use super::Message;
    use super::MessageType;
    use super::OptionCode;
    use super::Packet;
    use crate::engine::dhcpv6::test_data;
    use crate::engine::port::meta::ActionMeta;
    use crate::engine::GenericUlp;
    use opte_api::Direction::*;

    // Test that we correctly parse out the entire Solicit message from a
    // snooped packet.
    //
    // Most of the expected data here was verified with Wireshark.
    #[test]
    fn test_parse_snooped_solicit_message() {
        let msg = Message::from_bytes(
            test_data::test_solicit_packet_solicit_message(),
        )
        .unwrap();
        assert_eq!(msg.typ, MessageType::Solicit);
        assert_eq!(msg.xid.0.as_ref(), test_data::test_solicit_packet_xid());
        if let Dhcpv6Option::ClientId(opt) =
            msg.find_option(OptionCode::ClientId).unwrap()
        {
            assert_eq!(opt.0, test_data::test_solicit_packet_client_duid());
        } else {
            panic!("Expected a Client ID option");
        }
        assert_eq!(msg.options.len(), 4);
        assert!(msg.has_option(OptionCode::ElapsedTime));
        assert!(msg.has_option(OptionCode::OptionRequest));
        assert!(msg.has_option(OptionCode::IaNa));
    }

    #[test]
    fn test_predicates_match_snooped_solicit_message() {
        let pkt = Packet::copy(test_data::TEST_SOLICIT_PACKET)
            .parse(Out, GenericUlp {})
            .unwrap();
        let pmeta = pkt.meta();
        let ameta = ActionMeta::new();
        let client_mac =
            MacAddr::from_const([0xa8, 0x40, 0x25, 0xfa, 0xdd, 0x0b]);
        for pred in dhcpv6_server_predicates(&client_mac) {
            assert!(
                pred.is_match(pmeta, &ameta),
                "Expected predicate to match snooped Solicit test packet: {}",
                pred
            );
        }
    }
}
