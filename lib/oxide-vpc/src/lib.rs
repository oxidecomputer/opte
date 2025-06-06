// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! The Oxide VPC Network.
//!
//! This module contains configuration that is specific to the "Oxide
//! VPC Network"; the guest overlay network that we implement on an
//! Oxide Rack. OPTE itself is a generic engine for performing packet
//! transformations in a flow-centric manner. While it does provide
//! primitve building blocks for implementing network functions, like
//! rules and header transpositions, it does not dictate a specific
//! network configuration. This module configures OPTE in a manner
//! consistent with the definition of The Oxide VPC Network in [RFD
//! 21] (User Networking API) and [RFD 63] (Network Architecture).
//!
//! [rfd21]: https://rfd.shared.oxide.computer/rfd/0021
//!
//! [rfd63]: https://rfd.shared.oxide.computer/rfd/0063
#![no_std]

// NOTE: Things get weird if you move the extern crate into cfg_if!.
#[cfg(any(feature = "std", test))]
#[macro_use]
extern crate std;

#[macro_use]
extern crate alloc;

// TODO: move to own crate?
#[cfg(any(feature = "api", test))]
pub mod api;

#[cfg(any(feature = "engine", test))]
pub mod engine;

#[cfg(any(feature = "engine", test))]
pub mod cfg;

#[cfg(any(feature = "std", test))]
pub mod print;
