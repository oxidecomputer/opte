#![no_main]

use libfuzzer_sys::fuzz_target;
use opte::engine::packet::Packet;
use oxide_vpc::api::Direction;
use oxide_vpc::engine::VpcParser;

fuzz_target!(|data: &[u8]| {
    let mut pkt = Packet::alloc_and_expand(data.len());
    let mut wtr = pkt.seg0_wtr();
    wtr.write(data).unwrap();
    pkt.parse(Direction::In, VpcParser {});
});
