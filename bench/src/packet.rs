use opte::engine::packet::Initialized;
use opte::engine::packet::Packet;
use opte::engine::Direction;

use opte::engine::dhcpv6::MessageType;

use super::alloc::*;
use super::MeasurementInfo;
use criterion::criterion_group;
use criterion::criterion_main;
use criterion::Criterion;
use opte_test_utils::dhcp::dhcpv6_with_reasonable_defaults;
use opte_test_utils::dhcp::packet_from_client_dhcpv6_message_unparsed;
use opte_test_utils::icmp::gen_icmp_echo_req;
use opte_test_utils::*;
use std::fmt::Debug;
use std::hint::black_box;
use std::vec;

// XXX: elements to keep in mind -- pkt dir, client config (may live in PARAMETER?)

///
pub trait BenchPacket {
    /// Label the output packet type in a human-friendly manner.
    fn packet_label(&self) -> String;

    /// Return a list of discrete scenarios
    fn test_cases(&self) -> Vec<Box<dyn BenchPacketInstance>>;
}

pub trait BenchPacketInstance {
    /// Label the experiment instance à la Bencher.
    fn instance_name(&self) -> String;

    /// Generate a single test packet according to `params`.
    fn generate(&self) -> (Packet<Initialized>, Direction);
}

#[derive(Copy, Clone, Debug)]
pub enum Dhcp6Instance {
    Solicit,
    Request,
}

impl BenchPacketInstance for Dhcp6Instance {
    fn instance_name(&self) -> String {
        format!("{self:?}")
    }

    fn generate(&self) -> (Packet<Initialized>, Direction) {
        let cfg = g1_cfg();
        let class = match self {
            Dhcp6Instance::Solicit => MessageType::Solicit,
            Dhcp6Instance::Request => MessageType::Request,
        };
        let repr = dhcpv6_with_reasonable_defaults(class, false, &cfg);

        (
            packet_from_client_dhcpv6_message_unparsed(&cfg, &repr),
            Direction::Out,
        )
    }
}

pub struct Dhcp6 {}

impl BenchPacket for Dhcp6 {
    fn packet_label(&self) -> String {
        "DHCPv6".into()
    }

    fn test_cases(&self) -> Vec<Box<dyn BenchPacketInstance>> {
        [Dhcp6Instance::Solicit, Dhcp6Instance::Request]
            .into_iter()
            .map(|v| Box::new(v) as Box<dyn BenchPacketInstance>)
            .collect()
    }
}
