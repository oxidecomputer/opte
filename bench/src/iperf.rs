// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Utilities for parsing iPerf JSON output.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::net::IpAddr;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Output {
    pub start: StartSession,
    pub intervals: Vec<Interval>,
    pub end: EndSession,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StartSession {
    pub connected: Vec<Session>,
    pub version: String,
    pub system_info: String,
    pub timestamp: Time,
    pub connecting_to: Host,
    pub cookie: String,
    pub tcp_mss_default: Option<u64>,
    pub target_bitrate: Option<u64>,
    pub fq_rate: Option<u64>,
    pub sock_bufsize: Option<u64>,
    pub sndbuf_actual: Option<u64>,
    pub rcvbuf_actual: Option<u64>,
    pub test_start: TestStart,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Session {
    pub socket: u64,
    pub local_host: IpAddr,
    pub local_port: u16,
    pub remote_host: IpAddr,
    pub remote_port: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Host {
    pub host: IpAddr,
    pub port: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Time {
    pub time: String,
    pub timesecs: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TestStart {
    pub protocol: Protocol,
    pub num_streams: u64,
    pub blksize: u64,
    pub omit: u64,
    pub duration: u64,
    pub bytes: u64,
    pub blocks: u64,
    pub reverse: u64,
    pub tos: Option<u64>,
    pub target_bitrate: Option<u64>,
    pub bidir: Option<u64>,
    pub fqrate: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Protocol {
    Tcp,
    Udp,
    Sctp,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Interval {
    pub streams: Vec<StreamStat>,
    pub sum: Stat,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StreamStat {
    pub socket: u64,
    #[serde(flatten)]
    pub stat: Stat,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Stat {
    pub start: f64,
    pub end: f64,
    pub seconds: f64,
    pub bytes: u64,
    pub bits_per_second: f64,
    pub jitter_ms: Option<f64>,
    pub lost_packets: Option<u64>,
    pub packets: Option<u64>,
    pub lost_percent: Option<f64>,
    #[serde(default)]
    pub omitted: bool,
    pub sender: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CpuStat {
    pub host_total: f64,
    pub host_user: f64,
    pub host_system: f64,
    pub remote_total: f64,
    pub remote_user: f64,
    pub remote_system: f64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EndSession {
    pub streams: Vec<BTreeMap<String, StreamStat>>,
    pub sum_sent: Stat,
    pub sum_received: Stat,
    pub cpu_utilization_percent: CpuStat,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn iperf_output_parse() {
        let _val: Output =
            serde_json::from_str(include_str!("test/mac-iperf-sender.json"))
                .unwrap();

        let _val2: Output =
            serde_json::from_str(include_str!("test/mac-iperf-receiver.json"))
                .unwrap();
    }
}
