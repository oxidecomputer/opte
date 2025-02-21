// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Client<->Server communications for measuring XDE performance
//! over physical links.

use super::*;
#[cfg(target_os = "illumos")]
use std::collections::HashSet;
use std::io::Read;
use std::io::Write;
use std::net::Ipv6Addr;
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;
#[cfg(target_os = "illumos")]
use xde_tests::RouteV6;

#[derive(Debug)]
pub struct Routes {
    pub lls: Vec<Ipv6Addr>,
    pub underlay: Ipv6Addr,
}

#[cfg_attr(not(target_os = "illumos"), allow(unused))]
pub fn server_session(
    mut stream: TcpStream,
    route: Arc<Routes>,
    underlay_nics: Arc<Vec<String>>,
    kill_switch: Arc<AtomicBool>,
) {
    #[cfg(target_os = "illumos")]
    let _rx_routes =
        exchange_routes(&route, &mut stream, &underlay_nics).unwrap();

    stream.set_nonblocking(true).unwrap();

    let mut buf = [0u8; 16];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                break;
            }
            Ok(_) => {
                eprintln!("received extra data from {:?}", stream.peer_addr());
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => {
                break;
            }
        }

        if kill_switch.load(Ordering::Relaxed) {
            break;
        }

        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(target_os = "illumos")]
pub fn send_routes_client(
    route: &Routes,
    host: &str,
    port: u16,
    underlay_nics: &[String],
) -> Result<(TcpStream, Vec<RouteV6>)> {
    println!("Connecting to {host}...");
    let mut client = TcpStream::connect((host, port))?;
    println!("Connected!");
    client.set_nodelay(true)?;

    let v6_routes = exchange_routes(route, &mut client, underlay_nics)?;
    Ok((client, v6_routes))
}

#[cfg(target_os = "illumos")]
pub fn exchange_routes(
    route: &Routes,
    client: &mut TcpStream,
    underlay_nics: &[String],
) -> Result<Vec<RouteV6>> {
    send_routes(route, client)?;
    let new_routes = recv_routes(client)?;

    println!("peer owns connected lls {:?}", new_routes.lls);

    // ping the received link locals over our underlay and prime NDP.
    for nic in underlay_nics {
        for ip in &new_routes.lls {
            // attempt to ping each ll over each NIC: failure is okay,
            // but we need to do this to set up our NDP entries for route
            // insertion.
            // e.g., ping -Ainet6 -n -i igb1 -c 1 fe80::a236:9fff:fe0c:25b7 1
            Command::new("ping")
                .args(["-Ainet6", "-n", "-i", nic.as_str(), "-c", "1"])
                .arg(ip.to_string())
                .arg("1")
                .output()?;
        }
    }

    // Leave ample time to also *be* pinged if necessary.
    // I'm finding that the server can be caught with entries
    // in state DELAYED, otherwise.
    println!("lls pinged, awating ndp stabilising...");
    std::thread::sleep(Duration::from_secs(10));

    let ndp_data = Command::new("ndp").arg("-an").output()?;

    let ndp_parse = std::str::from_utf8(&ndp_data.stdout)?;

    let mut routes = vec![];
    let mut nics_used = HashSet::new();
    for line in ndp_parse.lines() {
        let mut els = line.split_whitespace();

        let Some(nic) = els.next() else {
            continue;
        };
        let nic = nic.to_string();

        let Some(_mac) = els.next() else {
            continue;
        };

        let Some(_type) = els.next() else {
            continue;
        };

        let Some(status) = els.next() else {
            continue;
        };

        let Some(addr) = els.next() else {
            continue;
        };

        if !underlay_nics.contains(&nic) {
            continue;
        }

        if status != "REACHABLE" {
            continue;
        }

        let Ok(gw_ip) = addr.parse::<Ipv6Addr>() else {
            continue;
        };

        if new_routes.lls.contains(&gw_ip) {
            println!(
                "installing {}/64->{gw_ip} via {nic}",
                new_routes.underlay
            );
            routes.push(RouteV6::new(
                new_routes.underlay,
                64,
                gw_ip,
                Some(nic.to_string()),
            )?);
            nics_used.insert(nic.to_string());
        }
    }

    if nics_used.len() < 2 {
        eprintln!(
            "only found routes to other side over {nics_used:?}. multipath may be degraded."
        )
    }

    Ok(routes)
}

pub fn send_routes(route: &Routes, client: &mut TcpStream) -> Result<()> {
    client.write_all(&(route.lls.len() as u64).to_be_bytes())?;
    for ll in &route.lls {
        client.write_all(&ll.octets())?;
    }
    client.write_all(&route.underlay.octets())?;

    Ok(())
}

pub fn recv_routes(client: &mut TcpStream) -> Result<Routes> {
    let mut buf = [0u8; std::mem::size_of::<Ipv6Addr>()];

    client.read_exact(&mut buf[..8])?;
    let len = u64::from_be_bytes(buf[..8].try_into()?);
    let mut lls = Vec::with_capacity(len.try_into()?);
    for _ in 0..len {
        client.read_exact(&mut buf[..])?;
        lls.push(Ipv6Addr::from(buf));
    }
    client.read_exact(&mut buf[..])?;
    let underlay = Ipv6Addr::from(buf);

    Ok(Routes { lls, underlay })
}
