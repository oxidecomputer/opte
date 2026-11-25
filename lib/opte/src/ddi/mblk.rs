// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! `MsgBlk` and friends now live in `illumos::mblk`; they are
//! re-exported here so existing paths keep working.

pub use illumos::mblk::*;

#[cfg(test)]
mod test {
    use super::*;
    use crate::engine::GenericUlp;
    use crate::engine::packet::Packet;
    use crate::engine::packet::ParseError;
    use ingot::types::ParseError as IngotParseError;

    #[test]
    fn zero_byte_packet() {
        let mut pkt = MsgBlk::new(0);
        assert_eq!(pkt.len(), 0);
        assert_eq!(pkt.seg_len(), 1);
        assert_eq!(pkt.tail_capacity(), 16);

        let res = Packet::parse_outbound(pkt.iter_mut(), GenericUlp {});
        match res {
            Err(ParseError::IngotError(err)) => {
                assert_eq!(err.header().as_str(), "inner_eth");
                assert_eq!(err.error(), &IngotParseError::TooSmall);
            }

            Err(e) => panic!("expected read error, got: {e:?}"),
            _ => panic!("expected failure, accidentally succeeded at parsing"),
        }

        let pkt2 = MsgBlk::copy([]);
        assert_eq!(pkt2.len(), 0);
        assert_eq!(pkt2.seg_len(), 1);
        assert_eq!(pkt2.tail_capacity(), 16);
        let res = Packet::parse_outbound(pkt.iter_mut(), GenericUlp {});
        match res {
            Err(ParseError::IngotError(err)) => {
                assert_eq!(err.header().as_str(), "inner_eth");
                assert_eq!(err.error(), &IngotParseError::TooSmall);
            }

            Err(e) => panic!("expected read error, got: {e:?}"),
            _ => panic!("expected failure, accidentally succeeded at parsing"),
        }
    }
}
