// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! UDP headers.

use serde::Deserialize;
use serde::Serialize;

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
pub struct UdpPush {
    pub src: u16,
    pub dst: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UdpMod {
    src: Option<u16>,
    dst: Option<u16>,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::engine::packet::Packet;

    #[test]
    fn emit() {
        let udp = UdpMeta { src: 5353, dst: 5353, len: 142, csum: [0; 2] };
        let len = udp.hdr_len();
        let mut pkt = Packet::alloc_and_expand(len);
        let mut wtr = pkt.seg0_wtr();
        udp.emit(wtr.slice_mut(udp.hdr_len()).unwrap());
        assert_eq!(len, pkt.len());

        #[rustfmt::skip]
        let expected_bytes = [
            // source port + dest port
            0x14, 0xE9, 0x14, 0xE9,
            // length + checksum
            0x00, 0x8E, 0x00, 0x00,
        ];
        assert_eq!(&expected_bytes, pkt.seg_bytes(0));
    }
}
