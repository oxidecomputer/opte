use opte::engine::dhcpv6::MessageType;
use opte::engine::packet::Initialized;
use opte::engine::packet::Packet;
use opte::engine::Direction;
use opte_test_utils::dhcp::dhcpv6_with_reasonable_defaults;
use opte_test_utils::dhcp::packet_from_client_dhcpv6_message_unparsed;
use opte_test_utils::icmp::gen_icmp_echo_unparsed;
use opte_test_utils::*;

// XXX: elements to keep in mind -- pkt dir, client config (may live in PARAMETER?)

/// A family of related parse/process testcases to benchmark.
pub trait BenchPacket {
    /// Label the output packet type in a human-friendly manner.
    fn packet_label(&self) -> String;

    /// Return a list of discrete scenarios
    fn test_cases(&self) -> Vec<Box<dyn BenchPacketInstance>>;
}

/// An individual packet to time the parse/process timing of.
pub trait BenchPacketInstance {
    /// Label for the experiment instance via BencherId.
    fn instance_name(&self) -> String;

    // XXX: We probably want this to take the cfg of one or more nodes
    /// Generate a single test packet.
    fn generate(&self) -> (Packet<Initialized>, Direction);
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

pub struct Icmp4 {}

impl BenchPacket for Icmp4 {
    fn packet_label(&self) -> String {
        "ICMPv4".into()
    }

    fn test_cases(&self) -> Vec<Box<dyn BenchPacketInstance>> {
        [Dhcp6Instance::Solicit, Dhcp6Instance::Request]
            .into_iter()
            .map(|v| Box::new(v) as Box<dyn BenchPacketInstance>)
            .collect()
    }
}

impl BenchPacketInstance for Icmp4 {
    fn instance_name(&self) -> String {
        "EchoRequest".into()
    }

    fn generate(&self) -> (Packet<Initialized>, Direction) {
        let cfg = g1_cfg();
        let ident = 7;
        let seq_no = 777;
        let data = b"reunion\0";

        let pkt = gen_icmp_echo_unparsed(
            icmp::IcmpEchoType::Req,
            cfg.guest_mac,
            cfg.gateway_mac,
            cfg.ipv4_cfg().unwrap().private_ip,
            cfg.ipv4_cfg().unwrap().gateway_ip,
            ident,
            seq_no,
            &data[..],
            1,
        );

        (pkt, Direction::Out)
    }
}
