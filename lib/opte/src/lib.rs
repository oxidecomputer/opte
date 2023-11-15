// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::len_without_is_empty)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![deny(unreachable_patterns)]
#![deny(unused_must_use)]
// Enable features needed for USDT, if needed.
#![cfg_attr(all(feature = "usdt", not(usdt_stable_asm)), feature(asm))]
#![cfg_attr(
    all(feature = "usdt", target_os = "macos", not(usdt_stable_asm_sym)),
    feature(asm_sym)
)]

#[cfg_attr(feature = "engine", macro_use)]
extern crate alloc;

#[macro_use]
extern crate cfg_if;

// This is needed so that the kstat-macro (`#[derive(KStatProvider)]`)
// can use fully-qualified type paths.
extern crate self as opte;

use alloc::boxed::Box;
use core::fmt;
use core::fmt::Display;

#[cfg(any(feature = "api", test))]
pub mod api {
    pub use opte_api::*;
}

#[cfg(any(feature = "engine", test))]
pub mod ddi;

#[cfg(any(feature = "engine", test))]
pub mod engine;

#[cfg(any(feature = "engine", test))]
pub mod resource;

/// Return value with `bit` set.
///
/// TODO Make generic and take any unsigned integer.
pub const fn bit_on(bit: u8) -> u8 {
    // TODO Uncomment when `const_panic` feature is stable.
    // assert!(bit < 16);
    0x1 << bit
}

// ================================================================
// DTrace USDT Provider
//
// Allowing us to use USDT to trace the opte-core SDT probes when
// running in std/test.
// ================================================================
#[cfg(feature = "usdt")]
#[usdt::provider]
mod opte_provider {
    use opte_api::Direction;

    fn uft__hit(dir: Direction, port: &str, flow: &str, epoch: u64) {}
    fn uft__invalidate(dir: Direction, port: &str, flow: &str, epoch: u64) {}
    fn uft__tcp__closed(dir: Direction, port: &str, flow: &str) {}
    fn flow__expired(port: &str, ft_name: &str, flow: &str) {}
    fn gen__desc__fail(
        port: &str,
        layer: &str,
        dir: Direction,
        flow: &str,
        err: &str,
    ) {
    }
    fn gen__ht__fail(
        port: &str,
        layer: &str,
        dir: Direction,
        flow: &str,
        err: &str,
    ) {
    }
    fn ht__run(
        port: &str,
        loc: &str,
        dir: Direction,
        before: &str,
        after: &str,
    ) {
    }
    fn layer__process__entry(
        dir: Direction,
        port: &str,
        name: &str,
        flow: &str,
    ) {
    }
    fn layer__process__return(
        dir_port: (Direction, &str),
        name: &str,
        flow_before: &str,
        flow_after: &str,
        res: &str,
    ) {
    }
    fn port__process__entry(
        dir: Direction,
        name: &str,
        ifid: &str,
        epoch: u64,
        pkt: &illumos_sys_hdrs::uintptr_t,
    ) {
    }
    // XXX USDT (at least on mac/ARM) only allows up to 6 args.
    // Furthemore, there is a bug on mac/ARM that causes arg5 to
    // always come back NULL -- effectively limiting us to 5 args. For
    // this reason we merge some of the arguments.
    //
    // https://github.com/oxidecomputer/usdt/issues/62
    pub fn port__process__return(
        dir_port: (Direction, &str),
        ifid_before_after: (&str, &str),
        epoch: u64,
        pkt: &illumos_sys_hdrs::uintptr_t,
        res: &str,
    ) {
    }
    fn rule__deny(port: &str, layer: &str, dir: Direction, flow: &str) {}
    fn rule__match(
        port: &str,
        layer: &str,
        dir: Direction,
        flow: &str,
        action: &str,
    ) {
    }
    fn rule__no__match(port: &str, layer: &str, dir: Direction, flow: &str) {}
    fn tcp__err(
        dir: Direction,
        port: &str,
        flow: &str,
        pkt: &illumos_sys_hdrs::uintptr_t,
        msg: &str,
    ) {
    }
    fn tcp__flow__state(
        port: &str,
        flow: &str,
        curr_state: &str,
        new_state: &str,
    ) {
    }
}

// ================================================================
// Providers
//
// Providers allow opte-core to work in different contexts (in theory)
// by allowing various implementations of core services to be plugged
// into the engine. For example, logging and stats can both be done as
// providers; providing implementations fit for in-kernel execution
// versus unit testing execution. Ideally we could get to a point
// where OPTE could also easily be stood up in userland (not that it
// is explicitly a goal, but only that the flexibility gives us better
// options for testing or unique production situations). However, this
// is the type of abstraction that can quickly grow out of control. If
// it doesn't serve an obvious purpose with at least two obvious
// implmentations, then it probably doesn't need to be a provider.
//
// XXX For now we stash providers here. This should probably move to
// dedicated module.
// ================================================================

/// A logging provider provides the means to log messages to some
/// destination based on the context in which OPTE is running. For
/// example, in a unit test this could map to `println!`. In the
/// illumos kernel it would map to `cmn_err(9F)`.
///
/// Logging levels are provided by [`LogLevel`]. These levels will map
/// to the underlying provider with varying degrees of success.
pub trait LogProvider {
    /// Log a message at the specified level.
    fn log(&self, level: LogLevel, msg: &str);
}

#[derive(Clone, Copy, Debug)]
pub enum LogLevel {
    Note,
    Warn,
    Error,
}

impl Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let level_s = match self {
            Self::Note => "[NOTE]",
            Self::Warn => "[WARN]",
            Self::Error => "[ERROR]",
        };
        write!(f, "{}", level_s)
    }
}

#[cfg(any(feature = "std", test))]
#[derive(Clone, Copy)]
pub struct PrintlnLog {}

#[cfg(any(feature = "std", test))]
impl LogProvider for PrintlnLog {
    fn log(&self, level: LogLevel, msg: &str) {
        println!("{} {}", level, msg);
    }
}

#[cfg(all(feature = "kernel", not(feature = "std"), not(test)))]
pub struct KernelLog {}

#[cfg(all(feature = "kernel", not(feature = "std"), not(test)))]
impl LogProvider for KernelLog {
    fn log(&self, level: LogLevel, msg: &str) {
        use illumos_sys_hdrs as ddi;

        let cmn_level = match level {
            LogLevel::Note => ddi::CE_NOTE,
            LogLevel::Warn => ddi::CE_WARN,
            LogLevel::Error => ddi::CE_WARN,
        };

        let msg_arg = alloc::ffi::CString::new(msg).unwrap();
        unsafe { ddi::cmn_err(cmn_level, msg_arg.as_ptr()) }
    }
}

pub struct ExecCtx {
    pub log: Box<dyn LogProvider>,
}
