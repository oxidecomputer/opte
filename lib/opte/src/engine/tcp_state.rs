// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Basic TCP state machine.

use super::packet::InnerFlowId;
use super::tcp::TcpFlags;
use super::tcp::TcpMeta;
use super::tcp::TcpState;
use core::ffi::CStr;
use core::fmt;
use core::fmt::Display;
use opte_api::Direction;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use illumos_sys_hdrs::uintptr_t;
        use super::rule::flow_id_sdt_arg;
    }
}

/// An error processing a TCP flow.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TcpFlowStateError {
    /// Encountered an unexpected TCP segment.
    ///
    /// We have either mishandled state based on reordered/duplicate packets,
    /// or hosts are exhbiting behaviour not accounted for. Such packets should
    /// be logged and allowed to progress.
    UnexpectedSegment {
        direction: Direction,
        flow_id: InnerFlowId,
        state: TcpState,
        flags: u8,
    },
    /// Either side has chosen to send a SYN-carrying packet and establish
    /// a new flow.
    ///
    /// Handlers should clear any flow-specific stats and establish a new
    /// state machine.
    NewFlow {
        direction: Direction,
        flow_id: InnerFlowId,
        state: TcpState,
        flags: u8,
    },
}

impl fmt::Display for TcpFlowStateError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TcpFlowStateError::UnexpectedSegment {
                direction,
                flow_id,
                state,
                flags,
            } => {
                write!(
                    f,
                    "Unexpected TCP segment, \
                    direction: {}, flow: {}, state: {}, \
                    flags: 0x{:x}",
                    direction, flow_id, state, flags,
                )
            }
            TcpFlowStateError::NewFlow { direction, flow_id, state, flags } => {
                write!(
                    f,
                    "Flow was reopened early by endpoint, \
                    direction: {}, flow: {}, state: {}, \
                    flags: 0x{:x}",
                    direction, flow_id, state, flags,
                )
            }
        }
    }
}

/// Tracks TCP-specific flow state. Specifically it tracks which TCP
/// state the flow is currently in as well as the seq/ack values in
/// each direction.
///
/// The choice of wrapping the seq/ack numbers in `Option` might seem
/// odd. The idea is to prevent bugs as much as possible. When a new
/// connection starts, the SYN will contain the ISN for the side that
/// sent the initial segment. For the other side's ISN we could use 0
/// as a sentinel value, and that would probably be fine, but 0 is
/// also a valid sequence number. Using `Option` means we know for
/// sure if a seq/ack number has actually been set.
#[derive(Clone, Copy, Debug)]
pub struct TcpFlowState {
    tcp_state: TcpState,
    guest_seq: Option<u32>,
    guest_ack: Option<u32>,
    remote_seq: Option<u32>,
    remote_ack: Option<u32>,
}

impl From<TcpFlowState> for super::ioctl::TcpFlowStateDump {
    fn from(tfs: TcpFlowState) -> Self {
        Self {
            tcp_state: tfs.tcp_state,
            guest_seq: tfs.guest_seq,
            guest_ack: tfs.guest_ack,
            remote_seq: tfs.remote_seq,
            remote_ack: tfs.remote_ack,
        }
    }
}

impl Display for TcpFlowState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} {:?} {:?} {:?} {:?}",
            self.tcp_state,
            self.guest_seq,
            self.guest_ack,
            self.remote_seq,
            self.remote_ack
        )
    }
}

impl Default for TcpFlowState {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpFlowState {
    /// Transition the TCP state machine based on the inbound packet
    /// metadata and the current TCP state. If an unexpected
    /// transition occurs, then an error is returned.
    ///
    /// You might notice that we could remove all of the instances of
    /// `return None` and replace them with a single `None` value at
    /// the end of the function; but the author finds it useful to be
    /// explicit for each case.
    fn flow_in(&mut self, tcp: &TcpMeta) -> Option<TcpState> {
        use TcpState::*;

        if tcp.has_flag(TcpFlags::RST) {
            return Some(Closed);
        }

        match self.tcp_state {
            Closed => {
                // We have a new inbound SYN. We assume for now the
                // guest is listening on the given port by moving to
                // the LISTEN state.
                if tcp.has_flag(TcpFlags::SYN) {
                    return Some(Listen);
                }

                // We pontentially have a legitimate inbound data
                // segment for an ESTABLISHED connection that
                // previously expired in OPTE but is still active in
                // the guest. We immeidately move this to the
                // ESTABLISHED state even though that might be a lie.
                // We rely on the fact that the guest will immediately
                // respond with an ACK or RST. In the future we could
                // instead keep this in some type of probationary
                // state (or separate table).
                if tcp.has_flag(TcpFlags::ACK) {
                    return Some(Established);
                }

                None
            }

            Listen => {
                // If the guest doesn't respond to the first SYN, or
                // the sender never sees the guest's ACK, then the
                // sender may send more SYNs.
                if tcp.has_flag(TcpFlags::SYN) {
                    return Some(Listen);
                }

                None
            }

            // The guest is in active open and waiting for the
            // remote's SYN+ACK.
            SynSent => {
                if tcp.has_flag(TcpFlags::SYN) && tcp.has_flag(TcpFlags::ACK) {
                    Some(Established)
                } else {
                    // Could be simultaneous open, but not worrying
                    // about that for now.
                    None
                }
            }

            // The guest is in passive open and waiting for the
            // remote's ACK.
            SynRcvd => {
                if tcp.has_flag(TcpFlags::ACK) {
                    return Some(Established);
                }

                // In this case the client is retransmitting its SYN;
                // probably because the guest's SYN+ACK reply got lost
                // or stuck in a buffer somewhere.
                if tcp.has_flag(TcpFlags::SYN) {
                    return Some(SynRcvd);
                }

                // TODO I imagine we could see a retrans of the
                // remote's SYN here.
                None
            }

            Established => {
                if tcp.has_flag(TcpFlags::FIN) {
                    // In this case remote end has initiated the close
                    // and the guest is entering passive close.
                    return Some(CloseWait);
                }

                // Normal traffic on an ESTABLISHED connection.
                Some(Established)
            }

            // The guest is in passive close.
            CloseWait => {
                // In this case the guest sent an ACK for the remote's
                // FIN, but for some reason the remote didn't get it
                // and did a retransmit. Allow this packet to pass to
                // the guest can know to send another ACK.
                //
                // We could also see an ACK for previous data sent
                // from the guest.
                if tcp.has_flag(TcpFlags::FIN) || tcp.has_flag(TcpFlags::ACK) {
                    return Some(CloseWait);
                }

                None
            }

            // The guest is in passive close.
            LastAck => {
                // There are two potential reasons for this ACK:
                //
                //  1. The remote side is acknowledging our FIN and
                //     this connection should now be considered
                //     CLOSED. This is the case if the remote's ack
                //     covers the guest's seq.
                //
                //  2. We are seeing an ACK from the remote for a
                //     previous data segment. Pass it up to the guest
                //     so it can log the duplicate ACK.
                if tcp.has_flag(TcpFlags::ACK) {
                    if tcp.ack == self.guest_seq.unwrap() + 1 {
                        return Some(Closed);
                    }

                    return Some(LastAck);
                }

                None
            }

            // The guest is in active close.
            FinWait1 => {
                // The remote sent its FIN+ACK together, go straight
                // to TIME_WAIT. The connection is essentially CLOSED
                // at this point.
                //
                // TODO Verify ack number.
                if tcp.has_flag(TcpFlags::FIN) && tcp.has_flag(TcpFlags::ACK) {
                    return Some(TimeWait);
                }

                // The remote sent its ACK for out active FIN. We now
                // need to wait for the remote to passive close and
                // send its FIN.
                if tcp.has_flag(TcpFlags::ACK)
                    && tcp.ack == self.guest_seq.unwrap() + 1
                {
                    return Some(FinWait2);
                }

                // Presumably an ACK for some previous data. Let the
                // guest decide.
                if tcp.has_flag(TcpFlags::ACK) {
                    return Some(FinWait1);
                }

                // TODO This could be a simultaneous close.
                None
            }

            // The guest is in active close.
            FinWait2 => {
                if tcp.has_flag(TcpFlags::FIN)
                    && tcp.ack == self.guest_seq.unwrap() + 1
                {
                    // In this case the guest was the active closer,
                    // has sent its FIN, and has seen an ACK for that
                    // FIN from the passive side. This is the passive
                    // side's FIN. In this case the connection is
                    // officially closed and we enter TIME_WAIT.
                    return Some(TimeWait);
                }

                if tcp.has_flag(TcpFlags::ACK) {
                    return Some(FinWait2);
                }

                None
            }

            // The guest is in active close.
            TimeWait => {
                // The guest is receiving additional copies of FIN for
                // remote's passive close.
                if tcp.has_flag(TcpFlags::FIN) {
                    return Some(TimeWait);
                }

                // TODO We haven't implemented simultaneous close yet,
                // so I'm not sure why we would get an ACK in the
                // TIME_WAIT state. But for now I allow it to make
                // progress.
                if tcp.has_flag(TcpFlags::ACK) {
                    return Some(TimeWait);
                }

                None
            }
        }
    }

    /// You might notice that we could remove all of the instances of
    /// `return None` and replace them with a single `None` value at
    /// the end of the function; but the author finds it useful to be
    /// explicit for each case.
    fn flow_out(&mut self, tcp: &TcpMeta) -> Option<TcpState> {
        use TcpState::*;

        if tcp.has_flag(TcpFlags::RST) {
            return Some(Closed);
        }

        match self.tcp_state {
            Closed => {
                // The guest is trying to create a new outbound
                // connection.
                if tcp.has_flag(TcpFlags::SYN) {
                    return Some(SynSent);
                }

                // The guest is responding to a data segment,
                // immediately move to established.
                if tcp.has_flag(TcpFlags::ACK) {
                    return Some(Established);
                }

                None
            }

            // This is our initial state for a potential passive open.
            // In this case the guest process is responding to the
            // remote client with SYN+ACK.
            Listen => {
                if tcp.has_flag(TcpFlags::SYN) && tcp.has_flag(TcpFlags::ACK) {
                    return Some(SynRcvd);
                }

                None
            }

            SynSent => {
                // In this case we are retransmitting the SYN packet.
                if tcp.has_flag(TcpFlags::SYN) {
                    return Some(SynSent);
                }

                None
            }

            SynRcvd => {
                // In this case the guest is retransmitting the
                // SYN+ACK from its SYN_RCVD state.
                if tcp.has_flag(TcpFlags::SYN) && tcp.has_flag(TcpFlags::ACK) {
                    return Some(SynRcvd);
                }

                None
            }

            // TODO passive close
            Established => {
                if tcp.has_flag(TcpFlags::FIN) {
                    return Some(FinWait1);
                }

                Some(Established)
            }

            // The guest is in active close.
            FinWait1 => {
                // The guest is resending its FIN to the remote to
                // indicate its active close.
                if tcp.has_flag(TcpFlags::FIN) {
                    return Some(FinWait1);
                }

                if tcp.has_flag(TcpFlags::ACK) {
                    return Some(FinWait1);
                }

                None
            }

            // The guest in in active close.
            FinWait2 => {
                // The guest has closed its side but the remote might
                // still be sending data, make sure to allow ACKs get
                // out.
                if tcp.has_flag(TcpFlags::ACK) {
                    return Some(FinWait2);
                }

                None
            }

            // The guest is in active close.
            TimeWait => {
                // As far was the guest is concerned this connection
                // is CLOSED. However, while in this state the guest
                // will send ACKs to let the remote know we got its
                // passive FIN. Eventually this connection will time
                // out on the guest and in that case an RST reply is
                // sent. Or this flow will expire.
                if tcp.has_flag(TcpFlags::ACK) {
                    return Some(TimeWait);
                }

                None
            }

            // The guest is in a passive close state.
            CloseWait => {
                // The guest is performing its half of the passive
                // close now.
                if tcp.has_flag(TcpFlags::FIN) {
                    return Some(LastAck);
                }

                // The guest could be sending ACKs or data here while
                // it finishes up its half of the connection. I'm not
                // sure there's anything else to really check for
                // explicitly.
                Some(CloseWait)
            }

            // The guest is in a passive close state.
            LastAck => {
                // The guest is either reacknowledging the remote's
                // FIN or resending its own FIN to the remote.
                if tcp.has_flag(TcpFlags::FIN) || tcp.has_flag(TcpFlags::ACK) {
                    return Some(LastAck);
                }

                None
            }
        }
    }

    pub fn new() -> Self {
        Self {
            tcp_state: TcpState::Closed,
            guest_seq: None,
            guest_ack: None,
            remote_seq: None,
            remote_ack: None,
        }
    }

    pub fn process(
        &mut self,
        port: &CStr,
        dir: Direction,
        flow_id: &InnerFlowId,
        tcp: &TcpMeta,
    ) -> Result<TcpState, TcpFlowStateError> {
        let curr_state = self.tcp_state;

        // Run the segment through the corresponding side of the TCP
        // state machine. A successful transition should return
        // `Some(new_state)` where `new_state` may be the same as the
        // current state. A return value of `None` indicates an
        // unexpected transition.
        let res = match dir {
            Direction::In => {
                let res = self.flow_in(tcp);
                self.remote_seq = Some(tcp.seq);
                if tcp.has_flag(TcpFlags::ACK) {
                    self.remote_ack = Some(tcp.ack);
                }
                res
            }

            Direction::Out => {
                let res = self.flow_out(tcp);
                self.guest_seq = Some(tcp.seq);
                if tcp.has_flag(TcpFlags::ACK) {
                    self.guest_ack = Some(tcp.ack);
                }
                res
            }
        };

        let new_state = match res {
            Some(new_state) => new_state,

            // The guest/other endpoint has determined it's safe to reuse
            // a port combination for a new flow before OPTE did.
            // This can come from several sources:
            // - Linux / Illumos default the TIME-WAIT state to 60s
            //   vs. our/Win/Mac's (conservative) 120s. This could
            //   be tuned lower still by users.
            // - Application code in the guest sets SO_REUSEADDR.
            // - `tcp_tw_reuse`, or other timestamp-based checks
            //   recommended in RFC 6191.
            // We could theoretically parse and replicate timestamp
            // based logic, but we can't predict how a guest
            // will behave with regard to a static timer.
            // We don't care about direction because any guest-initiated
            // close (active or simul) will leave a flow in TIME-WAIT, which
            // is the most common case. If the guest is not yet ready, we expect
            // it will send its own RST in response.
            None if tcp.has_flag(TcpFlags::SYN) => {
                return Err(TcpFlowStateError::NewFlow {
                    direction: dir,
                    flow_id: *flow_id,
                    state: curr_state,
                    flags: tcp.flags,
                });
            }

            None => {
                self.tcp_flow_drop_probe(port, flow_id, dir, tcp.flags);
                return Err(TcpFlowStateError::UnexpectedSegment {
                    direction: dir,
                    flow_id: *flow_id,
                    state: curr_state,
                    flags: tcp.flags,
                });
            }
        };

        // Make sure to transition the state if it has changed and
        // fire the SDT probe.
        if new_state != curr_state {
            self.tcp_flow_state_probe(port, flow_id, new_state);
            self.tcp_state = new_state;
        }

        Ok(new_state)
    }

    // This probe fires anytime the TCP state machine determines a
    // packet should be dropped.
    pub fn tcp_flow_drop_probe(
        &self,
        port: &CStr,
        flow_id: &InnerFlowId,
        dir: Direction,
        flags: u8,
    ) {
        cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                let flow_id = flow_id_sdt_arg::from(flow_id);
                let state = tcp_flow_state_sdt_arg::from(self);

                unsafe {
                    __dtrace_probe_tcp__flow__drop(
                        port.as_ptr() as uintptr_t,
                        &flow_id as *const flow_id_sdt_arg as uintptr_t,
                        &state as *const tcp_flow_state_sdt_arg as uintptr_t,
                        dir as uintptr_t,
                        flags as uintptr_t,
                    );
                }
            } else if #[cfg(feature = "usdt")] {
                use std::string::ToString;

                let port_s = port.to_str().unwrap();
                let flow_s = flow_id.to_string();
                let state_s = self.to_string();
                let dir_s = dir.to_string();
                let flags_s = flags.to_string();

                crate::opte_provider::tcp__flow__state!(
                    || (port_s, flow_s, state_s, dir_s, flags_s)
                );
            } else {
                let (..) = (port, flow_id, dir, flags);
            }
        }
    }

    // This probe fires anytime the TCP flow changes state.
    fn tcp_flow_state_probe(
        &self,
        port: &CStr,
        flow_id: &InnerFlowId,
        new_state: TcpState,
    ) {
        cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                let flow_id = flow_id_sdt_arg::from(flow_id);
                unsafe {
                    __dtrace_probe_tcp__flow__state(
                        port.as_ptr() as uintptr_t,
                        &flow_id as *const flow_id_sdt_arg as uintptr_t,
                        self.tcp_state as uintptr_t,
                        new_state as uintptr_t,
                    );
                }
            } else if #[cfg(feature = "usdt")] {
                use std::string::ToString;

                let port_s = port.to_str().unwrap();
                let flow_s = flow_id.to_string();
                let curr_s = self.tcp_state.to_string();
                let new_s = new_state.to_string();
                crate::opte_provider::tcp__flow__state!(
                    || (port_s, flow_s, curr_s, new_s)
                );
            } else {
                let (..) = (port, flow_id, new_state);
            }
        }
    }

    pub fn tcp_state(&self) -> TcpState {
        self.tcp_state
    }
}

#[repr(C)]
struct tcp_flow_state_sdt_arg {
    pub tcp_state: u8,
    pub guest_seq: u32,
    pub guest_ack: u32,
    pub remote_seq: u32,
    pub remote_ack: u32,
}

impl From<&TcpFlowState> for tcp_flow_state_sdt_arg {
    fn from(state: &TcpFlowState) -> Self {
        tcp_flow_state_sdt_arg {
            tcp_state: state.tcp_state as u8,
            guest_seq: state.guest_seq.unwrap_or(0),
            guest_ack: state.guest_ack.unwrap_or(0),
            remote_seq: state.remote_seq.unwrap_or(0),
            remote_ack: state.remote_ack.unwrap_or(0),
        }
    }
}

#[cfg(all(not(feature = "std"), not(test)))]
extern "C" {
    pub fn __dtrace_probe_tcp__flow__state(
        port: uintptr_t,
        flow_id: uintptr_t,
        prev_state: uintptr_t,
        curr_state: uintptr_t,
    );

    pub fn __dtrace_probe_tcp__flow__drop(
        port: uintptr_t,
        flow_id: uintptr_t,
        flow_state: uintptr_t,
        dir: uintptr_t,
        flags: uintptr_t,
    );
}
