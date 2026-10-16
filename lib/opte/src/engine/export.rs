// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! Types for exporting Port information

pub use crate::api::LayerExport;
pub use crate::api::LftPairExport;
pub use crate::api::PortLftExport;
use crate::engine::port::PortState;
use crate::engine::rule::ImportError;
pub use opte_api::ActionDescKind;
use alloc::boxed::Box;

/// Error importing the full LFT state of a port.
#[derive(Debug)]
pub enum PortImportError {
    BadState(PortState),
    NotEmpty(String),
    UnknownLayer(String),
    Layer { layer: String, error: Box<ImportError> },
}

impl PortImportError {
    pub fn report_str(&self) -> String {
        match self {
            PortImportError::BadState(state) => {
                format!("Cannot import into a port in state '{state}'")
            }
            PortImportError::NotEmpty(layer) => {
                format!("Cannot import while layer '{layer}' is not empty")
            }
            PortImportError::UnknownLayer(layer) => {
                format!("Cannot import into unknown layer '{layer}'")
            }
            PortImportError::Layer { layer, error } => {
                format!(
                    "Layer '{layer}' could not import: {}",
                    error.report_str()
                )
            }
        }
    }
}
