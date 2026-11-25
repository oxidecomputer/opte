// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! These definitions now live in `illumos::sys_hdrs`; this crate
//! re-exports them so existing paths keep working.

#![no_std]

pub use illumos::sys_hdrs::*;
