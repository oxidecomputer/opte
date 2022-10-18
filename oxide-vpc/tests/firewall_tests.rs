mod common;

use common::*;
use opte::engine::layer::DenyReason;
use opte::engine::port::DropReason;

#[test]
fn firewall_replace_rules() {
    let g1_cfg = g1_cfg();
    let g2_cfg = g2_cfg();
    let mut ameta = ActionMeta::new();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None);
    g1.port.start();
    set!(g1, "port_state=running");

    let mut g2 = oxide_net_setup("g2_port", &g2_cfg, Some(g1.vpc_map.clone()));
    g2.port.start();
    set!(g2, "port_state=running");

    // Allow incoming TCP connection on g2 from anyone.
    let rule = "dir=in action=allow priority=10 protocol=TCP";
    firewall::add_fw_rule(
        &g2.port,
        &AddFwRuleReq {
            port_name: g2.port.name().to_string(),
            rule: rule.parse().unwrap(),
        },
    )
    .unwrap();
    incr!(g2, "epoch, firewall.rules.in");

    // ================================================================
    // Run the telnet SYN packet through g1's port in the outbound
    // direction and verify if passes the firewall.
    // ================================================================
    let mut pkt1 = http_tcp_syn(&g1_cfg, &g2_cfg);
    let res = g1.port.process(Out, &mut pkt1, &mut ameta);
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, "firewall.flows.out, firewall.flows.in, uft.out");

    // ================================================================
    // Modify the outgoing ruleset, but still allow the traffic to
    // pass. This test makes sure that flow table entries are updated
    // without issue and everything still works.
    //
    // XXX It would be nice if tests could verify that a probe fires
    // (in this case uft-invalidated) without using dtrace.
    // ================================================================
    let any_out = "dir=out action=deny priority=65535 protocol=any";
    let tcp_out = "dir=out action=allow priority=1000 protocol=TCP";
    firewall::set_fw_rules(
        &g1.port,
        &SetFwRulesReq {
            port_name: g1.port.name().to_string(),
            rules: vec![any_out.parse().unwrap(), tcp_out.parse().unwrap()],
        },
    )
    .unwrap();
    update!(
        g1,
        [
            "incr:epoch",
            "set:firewall.flows.in=0, firewall.flows.out=0",
            "set:firewall.rules.out=2, firewall.rules.in=0",
        ]
    );

    let mut pkt2 = http_tcp_syn(&g1_cfg, &g2_cfg);
    let res = g1.port.process(Out, &mut pkt2, &mut ameta);
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, "firewall.flows.in, firewall.flows.out");

    // ================================================================
    // Now that the packet has been encap'd let's play the role of
    // router and send this inbound to g2's port. For maximum fidelity
    // of the real process we first dump the raw bytes of g1's
    // outgoing packet and then reparse it.
    // ================================================================
    let mblk = pkt2.unwrap();
    let mut pkt3 =
        unsafe { Packet::<Initialized>::wrap(mblk).parse().unwrap() };
    let mut pkt3_copy =
        Packet::<Initialized>::copy(&pkt3.all_bytes()).parse().unwrap();
    let res = g2.port.process(In, &mut pkt3, &mut ameta);
    assert!(matches!(res, Ok(Modified)));
    incr!(g2, "firewall.flows.in, firewall.flows.out, uft.in");

    // ================================================================
    // Replace g2's firewall rule set to deny all inbound TCP traffic.
    // Verify the rules have been replaced and retry processing of the
    // g2_pkt, but this time it should be dropped.
    // ================================================================
    let new_rule = "dir=in action=deny priority=1000 protocol=TCP";
    firewall::set_fw_rules(
        &g2.port,
        &SetFwRulesReq {
            port_name: g2.port.name().to_string(),
            rules: vec![new_rule.parse().unwrap()],
        },
    )
    .unwrap();
    update!(
        g2,
        [
            "incr:epoch",
            "set:firewall.flows.in=0, firewall.flows.out=0",
            "set:firewall.rules.in=1, firewall.rules.out=0",
        ]
    );

    // Verify the packet is dropped and that the firewall flow table
    // entry (along with its dual) was invalidated.
    let res = g2.port.process(In, &mut pkt3_copy, &mut ameta);
    match res {
        Ok(ProcessResult::Drop {
            reason: DropReason::Layer { name, reason: lreason },
        }) => {
            assert_eq!("firewall", name);
            assert_eq!(DenyReason::Rule, lreason);
        }

        _ => panic!("expected layer drop but got: {:?}", res),
    }
    update!(g2, ["set:uft.in=0"]);
}

// Verify that the VNI host filter works for the inbound direction.
#[test]
fn firewall_vni_inbound() {
    // ================================================================
    // Setup g1 as usual.
    // ================================================================
    let mut g1_cfg = g1_cfg();
    // TODO the ext ip is no longer part of the test, but this pattern
    // could prove useful in other tests.
    let g1_ext_ip = "10.77.78.9".parse().unwrap();
    g1_cfg.set_ext_ipv4(g1_ext_ip);
    let mut ameta = ActionMeta::new();
    let custom = ["set:nat.rules.in=1", "set:nat.rules.out=3"];
    let mut g1 = oxide_net_setup2("g1_port", &g1_cfg, None, Some(&custom));
    g1.port.start();
    set!(g1, "port_state=running");

    // ================================================================
    // Setup g2 on a different VPC.
    // ================================================================
    let mut g2_cfg = g2_cfg();
    g2_cfg.vni = Vni::new(1234u32).unwrap();

    // ================================================================
    // Create a packet that is leaving g2 with g1 as its destination.
    // ================================================================
    let phys_src = TestIpPhys { ip: g2_cfg.phys_ip, mac: g2_cfg.guest_mac };
    let phys_dst = TestIpPhys { ip: g1_cfg.phys_ip, mac: g1_cfg.guest_mac };
    let mut pkt1 = http_tcp_syn2(
        g2_cfg.guest_mac,
        g2_cfg.ipv4().private_ip,
        g1_cfg.guest_mac,
        g1_cfg.ipv4().private_ip,
    );
    pkt1 = encap(pkt1, phys_src, phys_dst, g2_cfg.vni);

    // ================================================================
    // Verify that g1's firewall rejects this packet, as the default
    // VPC firewall rules dictate that only inbound traffic from the
    // same VPC should be allowed.
    // ================================================================
    let res = g1.port.process(In, &mut pkt1, &mut ameta);
    match res {
        Ok(ProcessResult::Drop {
            reason: DropReason::Layer { name, reason: lreason },
        }) => {
            assert_eq!("firewall", name);
            assert_eq!(DenyReason::Default, lreason);
        }

        _ => panic!("expected layer drop but got: {:?}", res),
    }

    // ================================================================
    // Setup g2 as normal and process the packet again. This time it should
    // pass.
    // ================================================================
    let g2_cfg = common::g2_cfg();
    let phys_src = TestIpPhys { ip: g2_cfg.phys_ip, mac: g2_cfg.guest_mac };
    let phys_dst = TestIpPhys { ip: g1_cfg.phys_ip, mac: g1_cfg.guest_mac };
    let mut pkt2 = http_tcp_syn2(
        g2_cfg.guest_mac,
        g2_cfg.ipv4().private_ip,
        g1_cfg.guest_mac,
        g1_cfg.ipv4().private_ip,
    );
    pkt2 = encap(pkt2, phys_src, phys_dst, g2_cfg.vni);
    ameta.clear();
    let res = g1.port.process(In, &mut pkt2, &mut ameta);
    assert!(matches!(res, Ok(Modified)));
    incr!(g1, "firewall.flows.in, firewall.flows.out, uft.in");
}

// Verify the VNI address filter works for the outbound direction.
#[test]
fn firewall_vni_outbound() {
    // ================================================================
    // Setup g1 as usual.
    // ================================================================
    let g1_cfg = g1_cfg();
    let mut g1 = oxide_net_setup("g1_port", &g1_cfg, None);
    let mut ameta = ActionMeta::new();
    g1.port.start();
    set!(g1, "port_state=running");

    // ================================================================
    // Setup g2 on a different VPC.
    // ================================================================
    let mut g2_cfg = g2_cfg();
    g2_cfg.vni = Vni::new(1234u32).unwrap();
    g1.vpc_map.add(g2_cfg.ipv4().private_ip.into(), g2_cfg.phys_addr());

    // ================================================================
    // Alter g1's firewall to allow outbound traffic ONLY if its
    // destined for the same VPC that it lives on. With this set of
    // outbound rules in place g1 should not be able to reach g2.
    // ================================================================
    let any_out = "dir=out action=deny priority=65535 protocol=any";
    let vni_out =
        format!("dir=out action=allow priority=1000 hosts=vni={}", g1_cfg.vni);
    firewall::set_fw_rules(
        &g1.port,
        &SetFwRulesReq {
            port_name: g1.port.name().to_string(),
            rules: vec![any_out.parse().unwrap(), vni_out.parse().unwrap()],
        },
    )
    .unwrap();
    update!(
        g1,
        ["incr:epoch", "set:firewall.rules.out=2, firewall.rules.in=0",]
    );

    // ================================================================
    // Create a packet that is leaving g1 with g2 as its destination.
    // ================================================================
    let phys_src = TestIpPhys { ip: g1_cfg.phys_ip, mac: g1_cfg.guest_mac };
    let phys_dst = TestIpPhys { ip: g2_cfg.phys_ip, mac: g2_cfg.guest_mac };
    let mut pkt1 = http_tcp_syn2(
        g1_cfg.guest_mac,
        g1_cfg.ipv4().private_ip,
        g1_cfg.guest_mac,
        g2_cfg.ipv4().private_ip,
    );
    pkt1 = encap(pkt1, phys_src, phys_dst, g2_cfg.vni);

    // ================================================================
    // Try to send the packet and verify the firewall does not allow it.
    // ================================================================
    let res = g1.port.process(Out, &mut pkt1, &mut ameta);
    match res {
        Ok(ProcessResult::Drop {
            reason: DropReason::Layer { name, reason: lreason },
        }) => {
            assert_eq!("firewall", name);
            assert_eq!(DenyReason::Rule, lreason);
        }

        _ => panic!("expected layer drop but got: {:?}", res),
    }
    assert_port!(g1);
}
