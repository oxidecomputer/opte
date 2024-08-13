// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Moments, periodics, etc.

/// The number of milliseconds in a second.
pub const MILLIS: u64 = 1_000;
/// The number of nanoseconds in a second.
pub const NANOS: u64 = 1_000_000_000;
/// The conversion from nanoseconds to milliseconds.
pub const NANOS_TO_MILLIS: u64 = NANOS / MILLIS;

#[cfg(all(not(feature = "std"), not(test)))]
pub use illumos::time::*;

#[cfg(any(feature = "std", test))]
pub use std::time::Instant;
