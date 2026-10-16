//! Types for exporting Port information

use crate::api::InnerFlowId;
use crate::engine::port::PortState;
use crate::engine::rule::ImportError;
use core::time::Duration;
use serde::Deserialize;
use serde::Serialize;

/// The kind of an exported LFT pair.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub enum ActionDescKind {
    /// There is no real action, its existence indicates an LFT entry.
    ///
    /// This is used for firewall rules, which only need to insert an entry into
    /// the in / out flow tables, but don't have any real action associated
    /// with them.
    NoOp,
    /// An SNAT action, translating a private to public IP within a specific
    /// port range.
    SNat,
    /// An SNAT-based echo action, using the echo identifier as the port
    /// number.
    SNatIcmpEcho,
    /// A NAT action, translating a private to public IP.
    Nat,
}

/// A single in-out pair exported by an LFT.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LftPairExport {
    /// Flow ID on the inbound LFT.
    pub flow_in: InnerFlowId,
    /// Flow ID on the outbound LFT.
    pub flow_out: InnerFlowId,
    /// Age of the flow.
    pub age: Duration,
    /// The number of inbound hits for this flow at `age`.
    pub hits_in: u64,
    /// The number of outbound hits for this flow at `age`.
    pub hits_out: u64,
    /// The kind of action this pair represents.
    pub kind: ActionDescKind,
}

/// The exported data from a single Layer in a port.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LayerExport {
    pub layer: String,
    pub pairs: Vec<LftPairExport>,
}

/// A full LFT exported for all layers in a port.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PortLftExport {
    pub layers: Vec<LayerExport>,
}

/// Error importing the full LFT state of a port.
#[derive(Debug)]
pub enum PortImportError {
    BadState(PortState),
    NotEmpty(String),
    UnknownLayer(String),
    Layer { layer: String, error: ImportError },
}
