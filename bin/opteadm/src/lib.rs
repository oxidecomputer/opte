// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! OPTE driver administration library

use opte_ioctl::Error;
use opte_ioctl::OpteHdl;
use std::ops::Deref;

include!(concat!(env!("OUT_DIR"), "/gen.rs"));

/// The handle used to send administration commands to the OPTE
/// control node.
#[derive(Debug)]
pub struct OpteAdm(OpteHdl);

impl Deref for OpteAdm {
    type Target = OpteHdl;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl OpteAdm {
    /// Create a new handle to the OPTE control node.
    pub fn open() -> Result<Self, Error> {
        OpteHdl::open().map(Self)
    }
}
