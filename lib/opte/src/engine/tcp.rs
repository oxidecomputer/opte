// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! TCP headers.

use super::flow_table::Ttl;
use core::fmt;
use core::fmt::Display;
use serde::Deserialize;
use serde::Serialize;

pub const TCP_HDR_OFFSET_MASK: u8 = 0xF0;
pub const TCP_HDR_OFFSET_SHIFT: u8 = 4;

pub const TCP_PORT_RDP: u16 = 3389;
pub const TCP_PORT_SSH: u16 = 22;

/// The duration after which a connection in TIME-WAIT should be
/// considered free for either side to reuse.
///
/// This value is chosen by Windows and MacOS, which is larger
/// than Linux's default 60s. Allowances for tuned servers and/or
/// more aggressive reuse via RFCs 1323/7323 and/or 6191 are made in
/// `tcp_state`.
pub const TIME_WAIT_EXPIRE_SECS: u64 = 120;
/// The duration after which otherwise healthy TCP flows should be pruned.
///
/// Currently, this is tuned to be 2.5 hours: higher than the default behaviour
/// for SO_KEEPALIVE on linux/illumos. Each will wait 2 hours before sending a
/// keepalive, when interval + probe count will result in a timeout after
/// 8mins (illumos) / 11mins (linux).
pub const KEEPALIVE_EXPIRE_SECS: u64 = 8_000;
pub const TIME_WAIT_EXPIRE_TTL: Ttl = Ttl::new_seconds(TIME_WAIT_EXPIRE_SECS);
pub const KEEPALIVE_EXPIRE_TTL: Ttl = Ttl::new_seconds(KEEPALIVE_EXPIRE_SECS);

// The standard TCP states.
//
// See Figure 13-8 of TCP/IP Illustrated Vol. 1 Ed. 2
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynRcvd,
    Established,
    CloseWait,
    LastAck,
    FinWait1,
    FinWait2,
    TimeWait,
}

impl Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            TcpState::Closed => "CLOSED",
            TcpState::Listen => "LISTEN",
            TcpState::SynSent => "SYN_SENT",
            TcpState::SynRcvd => "SYN_RCVD",
            TcpState::Established => "ESTABLISHED",
            TcpState::CloseWait => "CLOSE_WAIT",
            TcpState::LastAck => "LAST_ACK",
            TcpState::FinWait1 => "FIN_WAIT_1",
            TcpState::FinWait2 => "FIN_WAIT_2",
            TcpState::TimeWait => "TIME_WAIT",
        };
        write!(f, "{}", s)
    }
}

#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Deserialize,
    Eq,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
pub struct TcpPush {
    pub src: u16,
    pub dst: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TcpMod {
    src: Option<u16>,
    dst: Option<u16>,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::engine::packet::Packet;

    #[test]
    fn emit_no_opts() {
        let tcp = TcpMeta {
            src: 49154,
            dst: 80,
            seq: 2511121667,
            ack: 754208397,
            flags: TcpFlags::ACK,
            window_size: 64436,
            options_bytes: None,
            options_len: 0,
            csum: [0; 2],
        };

        let len = tcp.hdr_len();
        let mut pkt = Packet::alloc_and_expand(len);
        let mut wtr = pkt.seg0_wtr();
        tcp.emit(wtr.slice_mut(tcp.hdr_len()).unwrap());
        assert_eq!(len, pkt.len());
        #[rustfmt::skip]
        let expected_bytes = vec![
            // source
            0xC0, 0x02,
            // dest
            0x00, 0x50,
            // seq
            0x95, 0xAC, 0xAD, 0x03,
            // ack
            0x2C, 0xF4, 0x4E, 0x8D,
            // offset + flags
            0x50, 0x10,
            // window
            0xFB, 0xB4,
            // checksum
            0x00, 0x00,
            // URG pointer
            0x00, 0x00,
        ];
        assert_eq!(&expected_bytes, pkt.seg_bytes(0));
    }

    #[test]
    fn emit_opts() {
        let mut opts = [0x00; TcpHdr::MAX_OPTION_SIZE];
        let bytes = [
            0x02, 0x04, 0x05, 0xB4, 0x04, 0x02, 0x08, 0x0A, 0x09, 0xB4, 0x2A,
            0xA9, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x01,
        ];
        opts[0..bytes.len()].copy_from_slice(&bytes);

        let tcp = TcpMeta {
            src: 49154,
            dst: 80,
            seq: 2511121590,
            ack: 0,
            flags: TcpFlags::SYN,
            window_size: 64240,
            options_bytes: Some(opts),
            options_len: bytes.len(),
            csum: [0; 2],
        };

        let len = tcp.hdr_len();
        assert_eq!(40, len);
        let mut pkt = Packet::alloc_and_expand(len);
        let mut wtr = pkt.seg0_wtr();
        tcp.emit(wtr.slice_mut(tcp.hdr_len()).unwrap());
        assert_eq!(len, pkt.len());

        #[rustfmt::skip]
        let expected_bytes = vec![
            // source
            0xC0, 0x02,
            // dest
            0x00, 0x50,
            // seq
            0x95, 0xAC, 0xAC, 0xB6,
            // ack
            0x00, 0x00, 0x00, 0x00,
            // offset + flags
            0xA0, 0x02,
            // window
            0xFA, 0xF0,
            // checksum
            0x00, 0x00,
            // URG pointer
            0x00, 0x00,
            // MSS
            0x02, 0x04, 0x05, 0xB4,
            // SACK permitted
            0x04, 0x02,
            // Timestamps
            0x08, 0x0A, 0x09, 0xB4, 0x2A, 0xA9, 0x00, 0x00, 0x00, 0x00,
            // No-op
            0x01,
            // Window Scale
            0x03, 0x03, 0x01,

        ];
        assert_eq!(&expected_bytes, pkt.seg_bytes(0));
    }

    #[test]
    fn parse_no_opts() {
        let hdr_len = TcpHdr::BASE_SIZE;
        #[rustfmt::skip]
        let base_bytes = vec![
            // source
            0xC0, 0x02,
            // dest
            0x00, 0x50,
            // seq
            0x95, 0xAC, 0xAC, 0xB6,
            // ack
            0x00, 0x00, 0x00, 0x00,
            // offset
            ((hdr_len / 4) as u8) << TCP_HDR_OFFSET_SHIFT,
            // flags
            0x02,
            // window
            0xFA, 0xF0,
            // checksum
            0x00, 0x00,
            // URG pointer
            0x00, 0x00,
        ];
        assert_eq!(base_bytes.len(), TcpHdr::BASE_SIZE);

        let mut pkt = Packet::copy(&base_bytes);
        let mut rdr = pkt.get_rdr_mut();
        let tcp_hdr = TcpHdr::parse(&mut rdr).unwrap();

        assert_eq!(tcp_hdr.base_bytes(), &base_bytes);
        assert_eq!(tcp_hdr.options_bytes(), None);
    }

    #[test]
    fn parse_max_opts() {
        #[rustfmt::skip]
        let option_bytes = [
            // MSS
            0x02, 0x04, 0x05, 0xB4,
            // SACK permitted
            0x04, 0x02,
            // Timestamps
            0x08, 0x0A, 0x09, 0xB4, 0x2A, 0xA9, 0x00, 0x00, 0x00, 0x00,
            // No-op
            0x01,
            // Window Scale
            0x03, 0x03, 0x01,
            // No-ops
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        ];

        let hdr_len = TcpHdr::BASE_SIZE + option_bytes.len();
        #[rustfmt::skip]
        let base_bytes = [
            // source
            0xC0, 0x02,
            // dest
            0x00, 0x50,
            // seq
            0x95, 0xAC, 0xAC, 0xB6,
            // ack
            0x00, 0x00, 0x00, 0x00,
            // offset
            ((hdr_len / 4) as u8) << TCP_HDR_OFFSET_SHIFT,
            // flags
            0x02,
            // window
            0xFA, 0xF0,
            // checksum
            0x00, 0x00,
            // URG pointer
            0x00, 0x00,
        ];
        assert_eq!(base_bytes.len(), TcpHdr::BASE_SIZE);

        let pkt_bytes = base_bytes
            .iter()
            .copied()
            .chain(option_bytes.iter().copied())
            .collect::<Vec<_>>();

        let mut pkt = Packet::copy(&pkt_bytes);
        let mut rdr = pkt.get_rdr_mut();
        let tcp_hdr = TcpHdr::parse(&mut rdr).unwrap();

        assert_eq!(tcp_hdr.base_bytes(), &base_bytes);
        assert_eq!(tcp_hdr.options_bytes(), Some(&option_bytes[..]));
    }

    #[test]
    fn parse_opts_truncated() {
        #[rustfmt::skip]
        let option_bytes = [
            // MSS
            0x02, 0x04, 0x05, 0xB4,
            // SACK permitted
            0x04, 0x02,
            // Timestamps
            0x08, 0x0A, 0x09, 0xB4, 0x2A, 0xA9, 0x00, 0x00, 0x00, 0x00,
            // No-op
            0x01,
            // Window Scale
            0x03, 0x03, 0x01,
        ];

        let hdr_len = TcpHdr::BASE_SIZE
            + option_bytes.len()
            // Indicate there's an extra 32-bit word of options
            + 4;

        #[rustfmt::skip]
        let base_bytes = [
            // source
            0xC0, 0x02,
            // dest
            0x00, 0x50,
            // seq
            0x95, 0xAC, 0xAC, 0xB6,
            // ack
            0x00, 0x00, 0x00, 0x00,
            // offset
            ((hdr_len / 4) as u8) << TCP_HDR_OFFSET_SHIFT,
            // flags
            0x02,
            // window
            0xFA, 0xF0,
            // checksum
            0x00, 0x00,
            // URG pointer
            0x00, 0x00,
        ];
        assert_eq!(base_bytes.len(), TcpHdr::BASE_SIZE);

        let pkt_bytes = base_bytes
            .iter()
            .copied()
            .chain(option_bytes.iter().copied())
            .collect::<Vec<_>>();

        let mut pkt = Packet::copy(&pkt_bytes);
        let mut rdr = pkt.get_rdr_mut();
        let tcp_hdr_err = TcpHdr::parse(&mut rdr)
            .expect_err("expected to fail parsing malformed TCP header");

        assert_eq!(
            tcp_hdr_err,
            TcpHdrError::TruncatedOptions(ReadErr::NotEnoughBytes)
        );
    }
}
