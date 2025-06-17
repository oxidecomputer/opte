// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

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

#[cfg(any(feature = "engine", feature = "kernel"))]
#[macro_use]
extern crate cfg_if;

// This is needed so that the kstat-macro (`#[derive(KStatProvider)]`)
// can use fully-qualified type paths.
extern crate self as opte;

pub use ingot;

#[cfg(any(feature = "api", test))]
pub mod api;
#[cfg(any(feature = "engine", test))]
pub mod d_error;
#[cfg(any(feature = "engine", test))]
pub mod ddi;
#[cfg(any(feature = "engine", test))]
pub mod dynamic;
#[cfg(any(feature = "engine", test))]
pub mod engine;
#[cfg(any(feature = "std", test))]
pub mod print;
#[cfg(any(feature = "engine", test))]
pub mod provider;

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

    fn uft__hit(
        dir: Direction,
        port: &str,
        flow: &str,
        epoch: u64,
        last_hit: u64,
    ) {
    }
    fn uft__invalidate(dir: Direction, port: &str, flow: &str, epoch: u64) {}
    fn uft__tcp__closed(dir: Direction, port: &str, flow: &str) {}
    fn flow__expired(
        port: &str,
        ft_name: &str,
        flow: &str,
        last_hit: u64,
        now: u64,
    ) {
    }
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
