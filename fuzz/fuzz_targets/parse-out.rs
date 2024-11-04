#![no_main]

use libfuzzer_sys::fuzz_target;
use opte::ddi::mblk::MsgBlk;
use opte::engine::packet::Packet;
use oxide_vpc::engine::VpcParser;

fuzz_target!(|data: &[u8]| {
    let mut pkt_m = MsgBlk::copy(data);
    let _ = Packet::parse_outbound(pkt_m.iter_mut(), VpcParser {});
});
