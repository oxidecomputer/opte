//! Types for exporting Port information

use crate::api::InnerFlowId;
use crate::engine::nat::NatDesc;
use crate::engine::port::PortState;
use crate::engine::rule::ActionDesc;
use crate::engine::rule::ExportableDesc as _;
use crate::engine::rule::ImportError;
use crate::engine::rule::ImportResources;
use crate::engine::snat::SNatDesc;
use crate::engine::snat::SNatIcmpEchoDesc;
use alloc::sync::Arc;
use opte_api::IpAddr;
use opte_api::Ipv4Addr;
use opte_api::Ipv6Addr;
use serde::Deserialize;
use serde::Serialize;

/// Data exported by an `SNatDesc`.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub struct SNatSpec {
    pub private_ip: IpAddr,
    pub private_port: u16,
    pub external_ip: IpAddr,
    pub external_port: u16,
}

/// Data exported by an `SNatIcmpEchoDesc`.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub struct SNatIcmpEchoSpec {
    pub private_ip: IpAddr,
    pub external_ip: IpAddr,
    pub external_ident: u16,
    pub private_ident: u16,
}

/// Data exported by a `NatDesc`.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub struct NatSpec {
    pub private_ip: IpAddr,
    pub external_ip: IpAddr,
}

/// All exportable descriptors.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub enum ActionDescExport {
    SNat(SNatSpec),
    SNatIcmpEcho(SNatIcmpEchoSpec),
    Nat(NatSpec),
}

impl From<SNatSpec> for ActionDescExport {
    fn from(value: SNatSpec) -> Self {
        Self::SNat(value)
    }
}

impl From<SNatIcmpEchoSpec> for ActionDescExport {
    fn from(value: SNatIcmpEchoSpec) -> Self {
        Self::SNatIcmpEcho(value)
    }
}

impl From<NatSpec> for ActionDescExport {
    fn from(value: NatSpec) -> Self {
        Self::Nat(value)
    }
}

/// A single in-out pair exported by an LFT.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LftPairExport {
    /// Flow ID on the inbound LFT.
    pub flow_in: InnerFlowId,
    /// Flow ID on the outbound LFT.
    pub flow_out: InnerFlowId,
    /// Age of the flow, i.e., milliseconds since the last hit.
    pub age_ms: u64,
    /// The action descriptor.
    ///
    /// If this is `None`, that means the action should deserialize as a
    /// "no-op", i.e., just a stateful in-out pair in the LFTs without any
    /// action. This is used for stateful firewalls.
    pub descriptor: Option<ActionDescExport>,
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

/// Attempt to import a serialized spec for an action descriptor, back into the
/// descriptor itself.
pub fn import_descriptor_from_spec(
    spec: ActionDescExport,
    flow: &InnerFlowId,
    resources: &ImportResources,
) -> Result<Arc<dyn ActionDesc>, ImportError> {
    match spec {
        // TODO(ben): Could make the decision about resources here, and pass the
        // pool or verififier into the `from_spec` implementation. That would
        // need to be another associated type, which I think is fine.
        ActionDescExport::SNat(snat) => match snat.private_ip {
            IpAddr::Ip4(_) => Ok(Arc::new(SNatDesc::<Ipv4Addr>::from_spec(
                snat, flow, resources,
            )?)),
            IpAddr::Ip6(_) => Ok(Arc::new(SNatDesc::<Ipv6Addr>::from_spec(
                snat, flow, resources,
            )?)),
        },
        ActionDescExport::SNatIcmpEcho(echo) => match echo.private_ip {
            IpAddr::Ip4(_) => Ok(Arc::new(
                SNatIcmpEchoDesc::<Ipv4Addr>::from_spec(echo, flow, resources)?,
            )),
            IpAddr::Ip6(_) => Ok(Arc::new(
                SNatIcmpEchoDesc::<Ipv6Addr>::from_spec(echo, flow, resources)?,
            )),
        },
        ActionDescExport::Nat(nat) => {
            Ok(Arc::new(NatDesc::from_spec(nat, flow, resources)?))
        }
    }
}
