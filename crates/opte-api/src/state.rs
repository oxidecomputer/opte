// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! The state of an OPTE port.

use alloc::string::String;
use core::fmt;
use core::str::FromStr;
use serde::Deserialize;
use serde::Serialize;

/// The current state of the `Port`.
///
/// The sequence diagram below gives an overview of how the port
/// transitions between states. A port is first either created or
/// restored via the `PortBuilder` methods. At that point you have a
/// `Port` which can then transition between various states via its
/// own methods. The digram uses the template `<current_state> --
/// <method> --> <new state>`.
///
///
/// ```text
/// PortBuilder::create() --> Ready
/// PortBuilder::restore() --> Restored
///
/// Ready -- Port::start() --> Running
/// Ready -- Port::reset() --> Ready
///
/// Restored -- Port::start() --> Running
///
/// Running -- Port::pause() --> Paused
/// Running -- Port::reset() --> Ready
///
/// Paused -- Port::start() --> Running
/// Paused -- Port::reset() --> Ready
/// ```
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PortState {
    /// The port is configured with layers and rules, but has no flow
    /// state. It is ready to enter the [`Self::Running`] state to
    /// start handling traffic.
    ///
    /// This state may be entered from:
    ///
    /// * `PortBuilder::create()`
    /// * `Self::Running`: The transition wipes the flow state.
    /// * `Self::Paused`: The transition wipes the flow state.
    Ready,

    /// The port is running and packets are free to travel across the
    /// port. Rules may be added or removed while running.
    ///
    /// This state may be entered from:
    ///
    /// * `Self::Ready`
    /// * `Self::Paused`
    /// * `Self::Restored`
    Running,

    /// The port is paused. The layers and rules are intact as well as
    /// the flow state. However, any inbound or outbound packets are
    /// dropped.
    ///
    /// This state may be entered from:
    ///
    /// * `Self::Running`
    Paused,

    /// The port has been restored from a saved state. This includes
    /// layers and rules as well as the flow state.
    ///
    /// XXX This state isn't used yet.
    ///
    /// This state may be entered from:
    ///
    /// XXX This interface doesn't exist yet, use doc syntax to link
    /// to it once it does.
    ///
    /// * PortBuilder::restore()
    Restored,
}

impl fmt::Display for PortState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use PortState::*;

        let s = match self {
            Ready => "ready",
            Running => "running",
            Paused => "paused",
            Restored => "restored",
        };
        write!(f, "{s}")
    }
}

impl FromStr for PortState {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ready" => Ok(Self::Ready),
            "running" => Ok(Self::Running),
            "paused" => Ok(Self::Paused),
            "restored" => Ok(Self::Restored),
            _ => Err(format!("Bad PortState string: {s}")),
        }
    }
}
