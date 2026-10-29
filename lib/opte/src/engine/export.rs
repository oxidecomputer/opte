//! Types for exporting Port information

pub use crate::api::LayerExport;
pub use crate::api::LftPairExport;
pub use crate::api::PortLftExport;
use crate::engine::port::PortState;
use crate::engine::rule::ImportError;
pub use opte_api::ActionDescKind;

/// Error importing the full LFT state of a port.
#[derive(Debug)]
pub enum PortImportError {
    BadState(PortState),
    NotEmpty(String),
    UnknownLayer(String),
    Layer { layer: String, error: ImportError },
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
