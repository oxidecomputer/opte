// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use super::*;
use measurement::Instrumentation;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum IperfMode {
    ClientSend,
    ServerSend,
    // TODO: need an updated illumos package.
    //       we can build and install locally and just call
    //       /usr/local/iperf3 if need be.
    BiDir,
}

impl std::fmt::Display for IperfMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            IperfMode::ClientSend => "Client->Server",
            IperfMode::ServerSend => "Server->Client",
            IperfMode::BiDir => "Bidirectional",
        })
    }
}

impl Default for IperfMode {
    fn default() -> Self {
        Self::ClientSend
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum IperfProto {
    Tcp,
    Udp {
        /// Target bandwidth in MiB/s.
        bw: f64,
        /// Size of the UDP send buffer.
        ///
        /// Should be under 1500 due to dont_fragment.
        pkt_sz: usize,
    },
}

impl std::fmt::Display for IperfProto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IperfProto::Tcp => f.write_str("TCP"),
            IperfProto::Udp { bw, pkt_sz } => {
                write!(f, "UDP({pkt_sz}B, {bw}MiB/s)")
            }
        }
    }
}

impl Default for IperfProto {
    fn default() -> Self {
        Self::Tcp
    }
}

#[derive(Debug, Clone)]
pub struct IperfConfig {
    pub instrumentation: Instrumentation,
    pub n_iters: usize,
    pub mode: IperfMode,
    pub proto: IperfProto,
    pub expt_name: String,
    pub n_streams: Option<usize>,
}

impl Default for IperfConfig {
    fn default() -> Self {
        Self {
            instrumentation: Instrumentation::Dtrace,
            n_iters: 10,
            mode: IperfMode::default(),
            proto: IperfProto::default(),
            expt_name: "unspec".into(),
            n_streams: None,
        }
    }
}

impl IperfConfig {
    /// Return the command
    pub fn cmd_str(&self, target_ip: &str) -> String {
        let proto_str;
        let proto_segment = match self.proto {
            IperfProto::Tcp => "",
            IperfProto::Udp { bw, pkt_sz } => {
                proto_str = format!("-u --length {pkt_sz} -b {bw}M");
                proto_str.as_str()
            }
        };
        let dir_segment = match self.mode {
            IperfMode::ClientSend => "",
            IperfMode::ServerSend => "-R",
            IperfMode::BiDir => "--bidir",
        };

        let n_streams = self.n_streams.unwrap_or(8);

        // XXX: Setting several parallel streams because we don't
        //      really have packet-wise ECMP yet from ddm -- the
        //      P-values won't change, so the flowkey remains the same.
        // XXX: At higher rates -P instead of n x iPerf servers will
        //      bottleneck us. This is fine at ~2Gbps, but will need
        //      rework in future.
        format!(
            "iperf -c {target_ip} -J -P {n_streams} {proto_segment} {dir_segment}"
        )
    }

    /// Name of an experiment, used for storing different workloads
    /// and measurement types in distinct directories.
    pub fn benchmark_group(&self) -> String {
        format!(
            "iperf-{}/{}/{}",
            match self.proto {
                IperfProto::Tcp => "tcp",
                IperfProto::Udp { .. } => "udp",
            },
            self.expt_name,
            match self.mode {
                IperfMode::ClientSend => "c2s",
                IperfMode::ServerSend => "s2c",
                IperfMode::BiDir => "bidir",
            }
        )
    }

    /// Title to use in a flamegraph built from a set of measurements.
    pub fn title(&self) -> String {
        format!("iperf3 ({}) -- {}", self.mode, self.proto)
    }
}

// TODO: want these as json somewhere, with command line options
//       to choose which are run.
pub fn base_experiments(expt_name: &str) -> Vec<IperfConfig> {
    let base =
        IperfConfig { expt_name: expt_name.to_string(), ..Default::default() };
    vec![
        // lockstat: (almost) raw speeds.
        IperfConfig {
            instrumentation: Instrumentation::Lockstat,
            n_iters: 5,
            mode: IperfMode::ClientSend,
            ..base.clone()
        },
        IperfConfig {
            instrumentation: Instrumentation::Lockstat,
            n_iters: 5,
            mode: IperfMode::ServerSend,
            ..base.clone()
        },
        // dtrace: collect all the stats!
        IperfConfig { mode: IperfMode::ClientSend, ..base.clone() },
        IperfConfig { mode: IperfMode::ServerSend, ..base.clone() },
    ]
}
