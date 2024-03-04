// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Counting allocator used to track bytes allocated and the discrete
//! number of allocations made during benchmark cases, with `criterion`
//! integration.

use super::MeasurementInfo;
use criterion::measurement::Measurement;
use criterion::measurement::ValueFormatter;
use criterion::Criterion;
use std::alloc::GlobalAlloc;
use std::alloc::Layout;
use std::alloc::System;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

#[global_allocator]
static BENCH_ALLOC: TrackedAlloc = TrackedAlloc::new();

// Key simplifying assumption here: Criterion will only run one benchmark
// at a time, so we can ignore per-tid tracking.
struct TrackedAlloc {
    inner: System,
    alloc_count: AtomicU64,
    alloc_byte_count: AtomicU64,
    dealloc_count: AtomicU64,
    dealloc_byte_count: AtomicU64,
}

impl TrackedAlloc {
    pub const fn new() -> Self {
        Self {
            inner: System,
            alloc_count: AtomicU64::new(0),
            alloc_byte_count: AtomicU64::new(0),
            dealloc_count: AtomicU64::new(0),
            dealloc_byte_count: AtomicU64::new(0),
        }
    }
}

unsafe impl GlobalAlloc for TrackedAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.alloc_count.fetch_add(1, Ordering::Relaxed);
        self.alloc_byte_count
            .fetch_add(layout.size() as u64, Ordering::Relaxed);

        self.inner.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.dealloc_count.fetch_add(1, Ordering::Relaxed);
        self.dealloc_byte_count
            .fetch_add(layout.size() as u64, Ordering::Relaxed);

        self.inner.dealloc(ptr, layout);
    }
}

pub trait MemMeasure {
    fn read() -> u64;
    fn formatter() -> &'static dyn ValueFormatter;
    fn label() -> &'static str;
}

pub struct Allocs;
pub struct BytesAlloced;
pub struct Deallocs;
pub struct BytesDealloced;

impl MemMeasure for Allocs {
    fn read() -> u64 {
        BENCH_ALLOC.alloc_count.load(Ordering::Relaxed)
    }

    fn formatter() -> &'static dyn ValueFormatter {
        &CountFormatter
    }

    fn label() -> &'static str {
        "alloc_ct"
    }
}

impl MemMeasure for BytesAlloced {
    fn read() -> u64 {
        BENCH_ALLOC.alloc_byte_count.load(Ordering::Relaxed)
    }

    fn formatter() -> &'static dyn ValueFormatter {
        &BytesFormatter
    }

    fn label() -> &'static str {
        "alloc_sz"
    }
}

impl MemMeasure for Deallocs {
    fn read() -> u64 {
        BENCH_ALLOC.dealloc_count.load(Ordering::Relaxed)
    }

    fn formatter() -> &'static dyn ValueFormatter {
        &CountFormatter
    }

    fn label() -> &'static str {
        "dealloc_ct"
    }
}

impl MemMeasure for BytesDealloced {
    fn read() -> u64 {
        BENCH_ALLOC.dealloc_byte_count.load(Ordering::Relaxed)
    }
    fn formatter() -> &'static dyn ValueFormatter {
        &BytesFormatter
    }

    fn label() -> &'static str {
        "dealloc_sz"
    }
}

struct CountFormatter;
struct BytesFormatter;

// These values should be reasonable enough that we don't need to concern ourselves
// with scaling, at least on a per-packet basis.
impl ValueFormatter for CountFormatter {
    fn scale_values(&self, _count: f64, _values: &mut [f64]) -> &'static str {
        ""
    }

    fn scale_throughputs(
        &self,
        _count: f64,
        _throughput: &criterion::Throughput,
        _values: &mut [f64],
    ) -> &'static str {
        ""
    }

    fn scale_for_machines(&self, _values: &mut [f64]) -> &'static str {
        ""
    }
}

impl ValueFormatter for BytesFormatter {
    fn scale_values(&self, _bytes: f64, _values: &mut [f64]) -> &'static str {
        "B"
    }

    fn scale_throughputs(
        &self,
        _bytes: f64,
        _throughput: &criterion::Throughput,
        _values: &mut [f64],
    ) -> &'static str {
        "B"
    }

    fn scale_for_machines(&self, _values: &mut [f64]) -> &'static str {
        "B"
    }
}

/// Newtype used to mass-impl [`MemMeasure`] -> [`Measurement`].
pub struct Local<T>(T);

impl<T> From<T> for Local<T> {
    fn from(value: T) -> Self {
        Local(value)
    }
}

impl<T: MemMeasure> Measurement for Local<T> {
    type Intermediate = u64;
    type Value = u64;

    fn start(&self) -> Self::Intermediate {
        T::read()
    }

    fn end(&self, i: Self::Intermediate) -> Self::Value {
        T::read() - i
    }

    fn add(&self, v1: &Self::Value, v2: &Self::Value) -> Self::Value {
        v1 + v2
    }

    fn zero(&self) -> Self::Value {
        0
    }

    fn to_f64(&self, value: &Self::Value) -> f64 {
        *value as f64
    }

    fn formatter(&self) -> &dyn ValueFormatter {
        T::formatter()
    }
}

impl<T: MemMeasure> MeasurementInfo for Local<T> {
    fn label() -> &'static str {
        T::label()
    }
}

/// Create a new [`Criterion`] instance tuned for measuring allocation
/// info.
pub fn new_crit<T: MemMeasure>(val: T) -> Criterion<Local<T>> {
    Criterion::default()
        .with_measurement(Local(val))
        .sample_size(10)
        .warm_up_time(Duration::from_nanos(1))
        .measurement_time(Duration::from_micros(10))
        .nresamples(1)
        // There seems to be a bug when all samples have the same value.
        // Equally, all t_tests are getting bogged down between calls...
        .without_plots()
}
