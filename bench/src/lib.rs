// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Utilites and tools for performing, recording, and processing
//! benchmarks from local runners or DTrace output into `criterion`.

use criterion::measurement::Measurement;
use criterion::measurement::WallTime;

#[cfg(feature = "alloc")]
pub mod alloc;
pub mod dtrace;
pub mod iperf;
pub mod kbench;
pub mod packet;

/// Additional labelling information for [`Measurement`]s for
/// pretty-printing and grouping.
pub trait MeasurementInfo: Measurement {
    fn label() -> &'static str;
}

impl MeasurementInfo for WallTime {
    fn label() -> &'static str {
        "wallclock"
    }
}
