// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! Providers allow opte-core to work in different contexts (in theory)
//! by allowing various implementations of core services to be plugged
//! into the engine. For example, logging and stats can both be done as
//! providers; providing implementations fit for in-kernel execution
//! versus unit testing execution. Ideally we could get to a point
//! where OPTE could also easily be stood up in userland (not that it
//! is explicitly a goal, but only that the flexibility gives us better
//! options for testing or unique production situations). However, this
//! is the type of abstraction that can quickly grow out of control. If
//! it doesn't serve an obvious purpose with at least two obvious
//! implmentations, then it probably doesn't need to be a provider.

use alloc::boxed::Box;
use core::fmt;
use core::fmt::Display;

/// The set of all platform-specific providers required by a port.
pub struct Providers {
    pub log: Box<dyn LogProvider>,
}

/// A logging provider provides the means to log messages to some
/// destination based on the context in which OPTE is running.
///
/// For example, in a unit test this could map to `println!`. In the
/// illumos kernel it would map to `cmn_err(9F)`.
///
/// Logging levels are provided by [`LogLevel`]. These levels will map
/// to the underlying provider with varying degrees of success.
pub trait LogProvider: Send + Sync {
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
        write!(f, "{level_s}")
    }
}

#[cfg(any(feature = "std", test))]
#[derive(Clone, Copy)]
pub struct PrintlnLog;

#[cfg(any(feature = "std", test))]
impl LogProvider for PrintlnLog {
    fn log(&self, level: LogLevel, msg: &str) {
        println!("{level} {msg}");
    }
}

#[cfg(all(feature = "kernel", not(feature = "std"), not(test)))]
pub struct KernelLog;

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
