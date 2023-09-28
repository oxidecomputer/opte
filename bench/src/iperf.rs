// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

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
    pub target_bitrate: u64,
    pub fq_rate: u64,
    pub sock_bufsize: u64,
    pub sndbuf_actual: u64,
    pub rcvbuf_actual: u64,
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
    pub tos: u64,
    pub target_bitrate: u64,
    pub bidir: u64,
    pub fqrate: u64,
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
    pub sender: bool,
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

    const SENDER_OUTPUT: &'static str = r#"{
	"start":	{
		"connected":	[{
				"socket":	5,
				"local_host":	"192.168.1.173",
				"local_port":	50634,
				"remote_host":	"192.168.1.253",
				"remote_port":	5201
			}],
		"version":	"iperf 3.14",
		"system_info":	"Darwin KyleOxide.local 23.0.0 Darwin Kernel Version 23.0.0: Fri Sep 15 14:43:05 PDT 2023; root:xnu-10002.1.13~1/RELEASE_ARM64_T6020 arm64",
		"timestamp":	{
			"time":	"Thu, 28 Sep 2023 10:24:21 UTC",
			"timesecs":	1695896661
		},
		"connecting_to":	{
			"host":	"192.168.1.253",
			"port":	5201
		},
		"cookie":	"pzvjhuvhefyzeyfa42slydgnwwqpiqzczdim",
		"tcp_mss_default":	1448,
		"target_bitrate":	0,
		"fq_rate":	0,
		"sock_bufsize":	0,
		"sndbuf_actual":	131072,
		"rcvbuf_actual":	131072,
		"test_start":	{
			"protocol":	"TCP",
			"num_streams":	1,
			"blksize":	131072,
			"omit":	0,
			"duration":	10,
			"bytes":	0,
			"blocks":	0,
			"reverse":	0,
			"tos":	0,
			"target_bitrate":	0,
			"bidir":	0,
			"fqrate":	0
		}
	},
	"intervals":	[{
			"streams":	[{
					"socket":	5,
					"start":	0,
					"end":	1.000984,
					"seconds":	1.0009839534759521,
					"bytes":	25934304,
					"bits_per_second":	207270487.48337844,
					"omitted":	false,
					"sender":	true
				}],
			"sum":	{
				"start":	0,
				"end":	1.000984,
				"seconds":	1.0009839534759521,
				"bytes":	25934304,
				"bits_per_second":	207270487.48337844,
				"omitted":	false,
				"sender":	true
			}
		}, {
			"streams":	[{
					"socket":	5,
					"start":	1.000984,
					"end":	2.000029,
					"seconds":	0.99904501438140869,
					"bytes":	25394648,
					"bits_per_second":	203351381.64499164,
					"omitted":	false,
					"sender":	true
				}],
			"sum":	{
				"start":	1.000984,
				"end":	2.000029,
				"seconds":	0.99904501438140869,
				"bytes":	25394648,
				"bits_per_second":	203351381.64499164,
				"omitted":	false,
				"sender":	true
			}
		}, {
			"streams":	[{
					"socket":	5,
					"start":	2.000029,
					"end":	3.000054,
					"seconds":	1.0000250339508057,
					"bytes":	25513560,
					"bits_per_second":	204103370.486264,
					"omitted":	false,
					"sender":	true
				}],
			"sum":	{
				"start":	2.000029,
				"end":	3.000054,
				"seconds":	1.0000250339508057,
				"bytes":	25513560,
				"bits_per_second":	204103370.486264,
				"omitted":	false,
				"sender":	true
			}
		}, {
			"streams":	[{
					"socket":	5,
					"start":	3.000054,
					"end":	4.000885,
					"seconds":	1.0008310079574585,
					"bytes":	25838392,
					"bits_per_second":	206535503.35321578,
					"omitted":	false,
					"sender":	true
				}],
			"sum":	{
				"start":	3.000054,
				"end":	4.000885,
				"seconds":	1.0008310079574585,
				"bytes":	25838392,
				"bits_per_second":	206535503.35321578,
				"omitted":	false,
				"sender":	true
			}
		}, {
			"streams":	[{
					"socket":	5,
					"start":	4.000885,
					"end":	5.000486,
					"seconds":	0.99960100650787354,
					"bytes":	25541296,
					"bits_per_second":	204411927.02859744,
					"omitted":	false,
					"sender":	true
				}],
			"sum":	{
				"start":	4.000885,
				"end":	5.000486,
				"seconds":	0.99960100650787354,
				"bytes":	25541296,
				"bits_per_second":	204411927.02859744,
				"omitted":	false,
				"sender":	true
			}
		}, {
			"streams":	[{
					"socket":	5,
					"start":	5.000486,
					"end":	6.000909,
					"seconds":	1.0004229545593262,
					"bytes":	25435272,
					"bits_per_second":	203396148.67157,
					"omitted":	false,
					"sender":	true
				}],
			"sum":	{
				"start":	5.000486,
				"end":	6.000909,
				"seconds":	1.0004229545593262,
				"bytes":	25435272,
				"bits_per_second":	203396148.67157,
				"omitted":	false,
				"sender":	true
			}
		}, {
			"streams":	[{
					"socket":	5,
					"start":	6.000909,
					"end":	7.000442,
					"seconds":	0.99953299760818481,
					"bytes":	25707320,
					"bits_per_second":	205754647.91270232,
					"omitted":	false,
					"sender":	true
				}],
			"sum":	{
				"start":	6.000909,
				"end":	7.000442,
				"seconds":	0.99953299760818481,
				"bytes":	25707320,
				"bits_per_second":	205754647.91270232,
				"omitted":	false,
				"sender":	true
			}
		}, {
			"streams":	[{
					"socket":	5,
					"start":	7.000442,
					"end":	8.000105,
					"seconds":	0.99966299533844,
					"bytes":	26097680,
					"bits_per_second":	208851824.03827623,
					"omitted":	false,
					"sender":	true
				}],
			"sum":	{
				"start":	7.000442,
				"end":	8.000105,
				"seconds":	0.99966299533844,
				"bytes":	26097680,
				"bits_per_second":	208851824.03827623,
				"omitted":	false,
				"sender":	true
			}
		}, {
			"streams":	[{
					"socket":	5,
					"start":	8.000105,
					"end":	9.000149,
					"seconds":	1.0000439882278442,
					"bytes":	25703152,
					"bits_per_second":	205616171.309008,
					"omitted":	false,
					"sender":	true
				}],
			"sum":	{
				"start":	8.000105,
				"end":	9.000149,
				"seconds":	1.0000439882278442,
				"bytes":	25703152,
				"bits_per_second":	205616171.309008,
				"omitted":	false,
				"sender":	true
			}
		}, {
			"streams":	[{
					"socket":	5,
					"start":	9.000149,
					"end":	10.000371,
					"seconds":	1.0002219676971436,
					"bytes":	24801344,
					"bits_per_second":	198366720.99575067,
					"omitted":	false,
					"sender":	true
				}],
			"sum":	{
				"start":	9.000149,
				"end":	10.000371,
				"seconds":	1.0002219676971436,
				"bytes":	24801344,
				"bits_per_second":	198366720.99575067,
				"omitted":	false,
				"sender":	true
			}
		}],
	"end":	{
		"streams":	[{
				"sender":	{
					"socket":	5,
					"start":	0,
					"end":	10.000371,
					"seconds":	10.000371,
					"bytes":	255966968,
					"bits_per_second":	204765977.5822317,
					"sender":	true
				},
				"receiver":	{
					"socket":	5,
					"start":	0,
					"end":	10.000371,
					"seconds":	10.000371,
					"bytes":	255931304,
					"bits_per_second":	204737447.4407,
					"sender":	true
				}
			}],
		"sum_sent":	{
			"start":	0,
			"end":	10.000371,
			"seconds":	10.000371,
			"bytes":	255966968,
			"bits_per_second":	204765977.5822317,
			"sender":	true
		},
		"sum_received":	{
			"start":	0,
			"end":	10.000371,
			"seconds":	10.000371,
			"bytes":	255931304,
			"bits_per_second":	204737447.4407,
			"sender":	true
		},
		"cpu_utilization_percent":	{
			"host_total":	5.9062073832984519,
			"host_user":	0.975993300855477,
			"host_system":	4.93020409683523,
			"remote_total":	0.731671,
			"remote_user":	0.236322,
			"remote_system":	0.494949
		}
	}
}"#;

    const RECEIVER_WITH_FLAGS_OUTPUT: &'static str = r#"{
	"start":	{
		"connected":	[{
				"socket":	5,
				"local_host":	"192.168.1.173",
				"local_port":	61289,
				"remote_host":	"192.168.1.253",
				"remote_port":	5201
			}],
		"version":	"iperf 3.14",
		"system_info":	"Darwin KyleOxide.local 23.0.0 Darwin Kernel Version 23.0.0: Fri Sep 15 14:43:05 PDT 2023; root:xnu-10002.1.13~1/RELEASE_ARM64_T6020 arm64",
		"timestamp":	{
			"time":	"Thu, 28 Sep 2023 11:07:43 UTC",
			"timesecs":	1695899263
		},
		"connecting_to":	{
			"host":	"192.168.1.253",
			"port":	5201
		},
		"cookie":	"if75onrrtbiyiwvcd5ffn5wowkit37oxr7qz",
		"target_bitrate":	32299999,
		"fq_rate":	0,
		"sock_bufsize":	0,
		"sndbuf_actual":	9216,
		"rcvbuf_actual":	786896,
		"test_start":	{
			"protocol":	"UDP",
			"num_streams":	1,
			"blksize":	1448,
			"omit":	0,
			"duration":	11,
			"bytes":	0,
			"blocks":	0,
			"reverse":	1,
			"tos":	0,
			"target_bitrate":	32299999,
			"bidir":	0,
			"fqrate":	0
		}
	},
	"intervals":	[{
			"streams":	[{
					"socket":	5,
					"start":	0,
					"end":	1.000588,
					"seconds":	1.000588059425354,
					"bytes":	3641720,
					"bits_per_second":	29116637.686773676,
					"jitter_ms":	0.33695417070836736,
					"lost_packets":	1,
					"packets":	2516,
					"lost_percent":	0.0397456279809221,
					"omitted":	false,
					"sender":	false
				}],
			"sum":	{
				"start":	0,
				"end":	1.000588,
				"seconds":	1.000588059425354,
				"bytes":	3641720,
				"bits_per_second":	29116637.686773676,
				"jitter_ms":	0.33695417070836736,
				"lost_packets":	1,
				"packets":	2516,
				"lost_percent":	0.0397456279809221,
				"omitted":	false,
				"sender":	false
			}
		}, {
			"streams":	[{
					"socket":	5,
					"start":	1.000588,
					"end":	2.000219,
					"seconds":	0.99963098764419556,
					"bytes":	4035576,
					"bits_per_second":	32296525.817076057,
					"jitter_ms":	0.037919253129174157,
					"lost_packets":	0,
					"packets":	2787,
					"lost_percent":	0,
					"omitted":	false,
					"sender":	false
				}],
			"sum":	{
				"start":	1.000588,
				"end":	2.000219,
				"seconds":	0.99963098764419556,
				"bytes":	4035576,
				"bits_per_second":	32296525.817076057,
				"jitter_ms":	0.037919253129174157,
				"lost_packets":	0,
				"packets":	2787,
				"lost_percent":	0,
				"omitted":	false,
				"sender":	false
			}
		}, {
			"streams":	[{
					"socket":	5,
					"start":	2.000219,
					"end":	3.00076,
					"seconds":	1.0005409717559814,
					"bytes":	4039920,
					"bits_per_second":	32301885.592229661,
					"jitter_ms":	0.251761229598896,
					"lost_packets":	0,
					"packets":	2790,
					"lost_percent":	0,
					"omitted":	false,
					"sender":	false
				}],
			"sum":	{
				"start":	2.000219,
				"end":	3.00076,
				"seconds":	1.0005409717559814,
				"bytes":	4039920,
				"bits_per_second":	32301885.592229661,
				"jitter_ms":	0.251761229598896,
				"lost_packets":	0,
				"packets":	2790,
				"lost_percent":	0,
				"omitted":	false,
				"sender":	false
			}
		}, {
			"streams":	[{
					"socket":	5,
					"start":	3.00076,
					"end":	4.000337,
					"seconds":	0.999576985836029,
					"bytes":	4035576,
					"bits_per_second":	32298270.62594654,
					"jitter_ms":	0.43255482040059762,
					"lost_packets":	0,
					"packets":	2787,
					"lost_percent":	0,
					"omitted":	false,
					"sender":	false
				}],
			"sum":	{
				"start":	3.00076,
				"end":	4.000337,
				"seconds":	0.999576985836029,
				"bytes":	4035576,
				"bits_per_second":	32298270.62594654,
				"jitter_ms":	0.43255482040059762,
				"lost_packets":	0,
				"packets":	2787,
				"lost_percent":	0,
				"omitted":	false,
				"sender":	false
			}
		}, {
			"streams":	[{
					"socket":	5,
					"start":	4.000337,
					"end":	5.00048,
					"seconds":	1.0001430511474609,
					"bytes":	4037024,
					"bits_per_second":	32291572.6534786,
					"jitter_ms":	0.21710363724983747,
					"lost_packets":	0,
					"packets":	2788,
					"lost_percent":	0,
					"omitted":	false,
					"sender":	false
				}],
			"sum":	{
				"start":	4.000337,
				"end":	5.00048,
				"seconds":	1.0001430511474609,
				"bytes":	4037024,
				"bits_per_second":	32291572.6534786,
				"jitter_ms":	0.21710363724983747,
				"lost_packets":	0,
				"packets":	2788,
				"lost_percent":	0,
				"omitted":	false,
				"sender":	false
			}
		}, {
			"streams":	[{
					"socket":	5,
					"start":	5.00048,
					"end":	6.000523,
					"seconds":	1.0000430345535278,
					"bytes":	4042816,
					"bits_per_second":	32341136.213642463,
					"jitter_ms":	0.19845086523864577,
					"lost_packets":	0,
					"packets":	2792,
					"lost_percent":	0,
					"omitted":	false,
					"sender":	false
				}],
			"sum":	{
				"start":	5.00048,
				"end":	6.000523,
				"seconds":	1.0000430345535278,
				"bytes":	4042816,
				"bits_per_second":	32341136.213642463,
				"jitter_ms":	0.19845086523864577,
				"lost_packets":	0,
				"packets":	2792,
				"lost_percent":	0,
				"omitted":	false,
				"sender":	false
			}
		}, {
			"streams":	[{
					"socket":	5,
					"start":	6.000523,
					"end":	7.000207,
					"seconds":	0.999683976173401,
					"bytes":	4038472,
					"bits_per_second":	32317989.254632238,
					"jitter_ms":	0.26149104489455832,
					"lost_packets":	0,
					"packets":	2789,
					"lost_percent":	0,
					"omitted":	false,
					"sender":	false
				}],
			"sum":	{
				"start":	6.000523,
				"end":	7.000207,
				"seconds":	0.999683976173401,
				"bytes":	4038472,
				"bits_per_second":	32317989.254632238,
				"jitter_ms":	0.26149104489455832,
				"lost_packets":	0,
				"packets":	2789,
				"lost_percent":	0,
				"omitted":	false,
				"sender":	false
			}
		}, {
			"streams":	[{
					"socket":	5,
					"start":	7.000207,
					"end":	8.000037,
					"seconds":	0.99983000755310059,
					"bytes":	4076120,
					"bits_per_second":	32614504.219376665,
					"jitter_ms":	0.037503541026566035,
					"lost_packets":	0,
					"packets":	2815,
					"lost_percent":	0,
					"omitted":	false,
					"sender":	false
				}],
			"sum":	{
				"start":	7.000207,
				"end":	8.000037,
				"seconds":	0.99983000755310059,
				"bytes":	4076120,
				"bits_per_second":	32614504.219376665,
				"jitter_ms":	0.037503541026566035,
				"lost_packets":	0,
				"packets":	2815,
				"lost_percent":	0,
				"omitted":	false,
				"sender":	false
			}
		}, {
			"streams":	[{
					"socket":	5,
					"start":	8.000037,
					"end":	9.000032,
					"seconds":	0.999994993209839,
					"bytes":	4038472,
					"bits_per_second":	32307937.7590649,
					"jitter_ms":	0.056393457509878911,
					"lost_packets":	0,
					"packets":	2789,
					"lost_percent":	0,
					"omitted":	false,
					"sender":	false
				}],
			"sum":	{
				"start":	8.000037,
				"end":	9.000032,
				"seconds":	0.999994993209839,
				"bytes":	4038472,
				"bits_per_second":	32307937.7590649,
				"jitter_ms":	0.056393457509878911,
				"lost_packets":	0,
				"packets":	2789,
				"lost_percent":	0,
				"omitted":	false,
				"sender":	false
			}
		}, {
			"streams":	[{
					"socket":	5,
					"start":	9.000032,
					"end":	10.000063,
					"seconds":	1.0000309944152832,
					"bytes":	3992136,
					"bits_per_second":	31936098.159311127,
					"jitter_ms":	0.16860492499751656,
					"lost_packets":	0,
					"packets":	2757,
					"lost_percent":	0,
					"omitted":	false,
					"sender":	false
				}],
			"sum":	{
				"start":	9.000032,
				"end":	10.000063,
				"seconds":	1.0000309944152832,
				"bytes":	3992136,
				"bits_per_second":	31936098.159311127,
				"jitter_ms":	0.16860492499751656,
				"lost_packets":	0,
				"packets":	2757,
				"lost_percent":	0,
				"omitted":	false,
				"sender":	false
			}
		}, {
			"streams":	[{
					"socket":	5,
					"start":	10.000063,
					"end":	11.000015,
					"seconds":	0.99995201826095581,
					"bytes":	4070328,
					"bits_per_second":	32564186.486298174,
					"jitter_ms":	0.068292653230841,
					"lost_packets":	0,
					"packets":	2811,
					"lost_percent":	0,
					"omitted":	false,
					"sender":	false
				}],
			"sum":	{
				"start":	10.000063,
				"end":	11.000015,
				"seconds":	0.99995201826095581,
				"bytes":	4070328,
				"bits_per_second":	32564186.486298174,
				"jitter_ms":	0.068292653230841,
				"lost_packets":	0,
				"packets":	2811,
				"lost_percent":	0,
				"omitted":	false,
				"sender":	false
			}
		}],
	"end":	{
		"streams":	[{
				"udp":	{
					"socket":	5,
					"start":	0,
					"end":	11.000015,
					"seconds":	11.000015,
					"bytes":	44420296,
					"bits_per_second":	32305625.765055776,
					"jitter_ms":	0.068292653230841,
					"lost_packets":	1,
					"packets":	30421,
					"lost_percent":	0,
					"out_of_order":	0,
					"sender":	false
				}
			}],
		"sum":	{
			"start":	0,
			"end":	11.000015,
			"seconds":	11.000015,
			"bytes":	44420296,
			"bits_per_second":	32305625.765055776,
			"jitter_ms":	0.068292653230841,
			"lost_packets":	1,
			"packets":	30421,
			"lost_percent":	0.0032872029190361921,
			"sender":	false
		},
		"sum_sent":	{
			"start":	0,
			"end":	11.000015,
			"seconds":	11.000015,
			"bytes":	44420296,
			"bits_per_second":	32305625.765055776,
			"jitter_ms":	0,
			"lost_packets":	0,
			"packets":	0,
			"lost_percent":	0,
			"sender":	true
		},
		"sum_received":	{
			"start":	0,
			"end":	11.000015,
			"seconds":	11.000015,
			"bytes":	44048160,
			"bits_per_second":	32034981.770479407,
			"jitter_ms":	0.068292653230841,
			"lost_packets":	1,
			"packets":	30421,
			"lost_percent":	0.0032872029190361921,
			"sender":	false
		},
		"cpu_utilization_percent":	{
			"host_total":	1.5869042751396987,
			"host_user":	0.37181801288843169,
			"host_system":	1.2151135089851555,
			"remote_total":	0.587058,
			"remote_user":	0.222501,
			"remote_system":	0.363386
		}
	}
}"#;
    #[test]
    fn iperf_output_parse() {
        let _val: Output = serde_json::from_str(SENDER_OUTPUT).unwrap();

        let _val2: Output =
            serde_json::from_str(RECEIVER_WITH_FLAGS_OUTPUT).unwrap();
    }
}
