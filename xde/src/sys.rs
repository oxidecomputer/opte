// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

// stuff we need from common/sys

use crate::ip::processorid_t;

pub const VLAN_TAGSZ: u32 = 4;
pub const ALL_ZONES: i32 = -1;

unsafe extern "C" {
    safe fn curcpup() -> *mut crate::ip::cpu;
}

/// Return the current number of CPUs reported by illumos.
#[inline]
pub fn ncpus() -> usize {
    usize::try_from(unsafe { crate::ip::ncpus })
        .expect("CPU count is non-negative, and usize is >=32b")
}

/// Return information on the currently executing CPU.
#[inline]
pub fn current_cpu() -> CurrentCpu {
    // struct cpu contains a lot more than this, but these are the only
    // fields we need.
    #[repr(C)]
    #[derive(Copy, Clone)]
    struct partial_cpu {
        cpu_id: processorid_t,
        cpu_seqid: processorid_t,
    }

    let cpu = unsafe {
        let cpu_ptr = curcpup() as *mut partial_cpu;
        *cpu_ptr
    };

    CurrentCpu {
        id: usize::try_from(cpu.cpu_id)
            .expect("CPU count is non-negative, and usize is >=32b"),
        seq_id: usize::try_from(cpu.cpu_seqid)
            .expect("CPU count is non-negative, and usize is >=32b"),
    }
}

/// Information about the currently executing CPU.
pub struct CurrentCpu {
    /// ID of the current CPU.
    pub id: usize,

    /// Index of the current CPU in the range `0..ncpus()`.
    pub seq_id: usize,
}
