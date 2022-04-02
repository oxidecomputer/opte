//! Moments, periodics, etc.
use core::ops::Add;
use core::time::Duration;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {

        use alloc::boxed::Box;
        use illumos_ddi_dki as ddi;
        use crate::CString;
    } else {
        use std::time::Instant;
    }
}

/// The number of milliseconds in a second.
pub const MILLIS: u64 = 1_000;
/// The number of nanoseconds in a second.
pub const NANOS: u64 = 1_000_000_000;
/// The conversion from nanoseconds to milliseconds.
pub const NANOS_TO_MILLIS: u64 = 1_000_000;

/// A moment in time.
#[derive(Clone, Copy, Debug)]
pub struct Moment {
    #[cfg(all(not(feature = "std"), not(test)))]
    inner: ddi::hrtime_t,

    #[cfg(any(feature = "std", test))]
    inner: Instant,
}

impl Add<Duration> for Moment {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self::Output {
        cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                let new = self.inner + (rhs.as_secs() * NANOS) as i64 +
                    rhs.subsec_nanos() as i64;
                Moment { inner: new }
            } else {
                let new = self.inner + rhs;
                Moment { inner: new }
            }
        }
    }
}

impl Moment {
    /// Compute the delta between `now - self` and return as
    /// milliseconds.
    pub fn delta_as_millis(&self, earlier: Moment) -> u64 {
        cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                (self.inner as u64 - earlier.inner as u64) / NANOS_TO_MILLIS
            } else {
                let delta = self.inner.duration_since(earlier.inner);
                delta.as_secs() * MILLIS + delta.subsec_millis() as u64
            }
        }
    }

    pub fn now() -> Self {
        cfg_if! {
            if #[cfg(all(not(feature = "std"), not(test)))] {
                Self { inner: unsafe { ddi::gethrtime() } }
            } else {
                Self { inner: Instant::now() }
            }
        }
    }
}

impl Default for Moment {
    fn default() -> Self {
        Self::now()
    }
}

/// Execute a callback periodically.
///
/// NOTE: We could provide a user context impl using the timer_create
/// POSIX API, but as there is no reason to actually have a periodic
/// in testing we do not bother. The reason we do not need a periodic
/// in testing is because it would only be testing the periodic impl,
/// and in our case we only care about the kernel context periodic,
/// which means we must be running in kernel context to actually test
/// it.
///
/// NOTE: A periodic **cannot** implement `Clone` as it represents a
/// unique resource on the system.
#[cfg(all(not(feature = "std"), not(test)))]
#[derive(Debug)]
pub struct Periodic<T: 'static> {
    // The following three fields are not needed for the
    // implementation, but they may prove useful in debugging.
    #[allow(dead_code)]
    name: CString,
    #[allow(dead_code)]
    interval: i64,
    #[allow(dead_code)]
    system_cb: unsafe extern "C" fn(*mut ddi::c_void),

    // The opaque handle returned by ddi_periodic_add(9F); needed to
    // later delete the periodic during Drop.
    periodic: *const ddi::ddi_periodic,

    // Technically we are lying here. While the periodic is alive both
    // the system and this value hold a copy of the raw pointer to the
    // context value: so we actually have an aliased (*const) pointer.
    // However, the system treats this as an opaque pointer and does
    // nothing with it except give the value to the callback. The API
    // provided to the user is such that they are considered the sole
    // owner of the boxed T, and thus the callback should receive an
    // `&mut T`. We provide this safely by holding the following
    // property:
    //
    // While the periodic is alive only the `_periodic_cb` is allowed
    // to access the `raw_ctx` pointer.
    //
    // When the Periodic is dropped we first delete the system's
    // periodic via `ddi_periodic_delete(9F)`, returning the sole
    // ownership of `raw_ctx` back to `Peridioc`. This allows us to
    // safely put the context back in its `Box` and drop it.
    raw_ctx: *mut PeriodicCtx<T>,
}

#[cfg(all(not(feature = "std"), not(test)))]
struct PeriodicCtx<T: 'static> {
    arg: Box<T>,
    cb: fn(&mut T),
}

#[cfg(all(not(feature = "std"), not(test)))]
impl<T: 'static> PeriodicCtx<T> {
    pub fn call(&mut self) {
        (self.cb)(&mut self.arg);
    }
}

// Safety: We know the arg is non-null because the periodic ctor
// always builds a PeriodicCtx to pas to this callback.
#[cfg(all(not(feature = "std"), not(test)))]
pub unsafe extern "C" fn _periodic_cb<T: 'static>(arg: *mut ddi::c_void) {
    assert!(!arg.is_null());
    let ctx = &mut *(arg as *mut PeriodicCtx<T>);
    ctx.call();
}

#[cfg(all(not(feature = "std"), not(test)))]
impl<T: 'static> Periodic<T> {
    /// Create a new periodic.
    ///
    /// The `Box<T>` is owned by the periodic itself and the callback
    /// is passed an `&mut T`.
    pub fn new(
        name: CString,
        cb: fn(&mut T),
        arg: Box<T>,
        interval: Interval,
    ) -> Self {
        let pctx = Box::new(PeriodicCtx::<T> { arg, cb });
        let raw_ctx = Box::into_raw(pctx);
        let interval = interval.as_nanos() as i64;

        let periodic = unsafe {
            ddi::ddi_periodic_add(
                _periodic_cb::<T>,
                raw_ctx as *mut ddi::c_void,
                interval,
                0,
            )
        };

        Self { name, interval, system_cb: _periodic_cb::<T>, periodic, raw_ctx }
    }
}

#[cfg(all(not(feature = "std"), not(test)))]
impl<T: 'static> Drop for Periodic<T> {
    fn drop(&mut self) {
        // Safety: We know that `self.periodic` was created via a
        // corresponding call to `ddi_periodic_add(9F)`.
        unsafe { ddi::ddi_periodic_delete(self.periodic) };

        // Safety: Now that the system's periodic is deleted we know
        // `self.raw_ctx` is the last pointer and we can once again
        // own it to allow the memory to be deallocated.
        unsafe {
            let _ = Box::from_raw(self.raw_ctx);
        }
    }
}

// Currently the `ddi_periodic_add(9F)` contract dictates the
// following about the internval value.
//
// > The caller must specify interval as an even, non-zero multiple of
// > 10ms. No other values are supported at this time. The interval
// > specified is a lower bound on the interval between executions of
// > the callback.
//
// The system will implicitly round up the value if it doesn't meet
// this contract. However, we use PerioidicInterval to enforce this
// contract at compile-time so that it's clear to the developer when
// they are using an internval that cannot be met by the system.
const SYSTEM_PERIODIC_RESOLUTION_IN_NANOS: u64 = 10_000_000;

/// An interval designed specifically for a [`Periodic`].
///
/// Ensures that an interval value is always a multiple of 10ms as
/// dictated by the `ddi_periodic_add(9F)` API this abstraction is
/// built upon.
pub struct Interval(u64);

impl Interval {
    pub const fn as_nanos(&self) -> u64 {
        self.0
    }

    pub const fn from_duration(dur: Duration) -> Self {
        let secs = dur.as_secs();
        let nanos = dur.subsec_nanos() as u64;

        assert!(
            nanos % SYSTEM_PERIODIC_RESOLUTION_IN_NANOS == 0,
            "interval is not multiple of 10ms"
        );

        Self((secs * NANOS) + nanos)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[should_panic]
    fn bad_interval() {
        let ms1 = 1 * NANOS_TO_MILLIS as u32;
        let ms9 = 9 * NANOS_TO_MILLIS as u32;
        let ms99 = 99 * NANOS_TO_MILLIS as u32;
        let ms101 = 101 * NANOS_TO_MILLIS as u32;

        let _x = Interval::from_duration(Duration::new(1, ms1));
        let _x = Interval::from_duration(Duration::new(1, ms9));
        let _x = Interval::from_duration(Duration::new(1, ms99));
        let _x = Interval::from_duration(Duration::new(1, ms101));
    }

    #[test]
    fn good_interval() {
        let ms10 = 10 * NANOS_TO_MILLIS as u32;
        let ms100 = 100 * NANOS_TO_MILLIS as u32;
        let ms200 = 200 * NANOS_TO_MILLIS as u32;
        let ms500 = 500 * NANOS_TO_MILLIS as u32;

        // We write the nanoseconds out by hand in case there are bugs
        // in the conversion constants.
        let mut x = Interval::from_duration(Duration::new(0, ms10));
        assert_eq!(x.as_nanos(), 10_000_000);
        x = Interval::from_duration(Duration::new(1, ms10));
        assert_eq!(x.as_nanos(), 1_010_000_000);
        x = Interval::from_duration(Duration::new(1, ms100));
        assert_eq!(x.as_nanos(), 1_100_000_000);
        x = Interval::from_duration(Duration::new(1, ms200));
        assert_eq!(x.as_nanos(), 1_200_000_000);
        x = Interval::from_duration(Duration::new(1, ms500));
        assert_eq!(x.as_nanos(), 1_500_000_000);
    }
}
