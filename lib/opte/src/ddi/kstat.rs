// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! Export Rust structs as illumos kstats.
//!
//! See `kstat_create(9F)`.
use alloc::boxed::Box;
use alloc::string::String;
use core::fmt;
use core::fmt::Display;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

pub use kstat_macro::KStatProvider;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::ffi::CString;
        use alloc::string::ToString;
        use illumos_sys_hdrs::{
            c_void, kstat_t, kstat_create, kstat_delete, kstat_install,
            kstat_named_init, kstat_named_t, KSTAT_STRLEN, KSTAT_TYPE_NAMED,
        };
    }
}

/// A provider of named kstats.
///
/// An implementation of this trait acts as a provider of "named"
/// kstats (i.e. `KSTAT_TYPE_NAMED` in `kstat_create(9F)`). The kstats
/// are always virtual (`KSTAT_FLAG_VIRTUAL`), meaning that the
/// allocation of the kstat data is performed by the caller (Rust).
///
/// Rather than implementing this trait manually, the kstat-macro
/// should be used.
///
/// # Example
///
/// To declare a new kstat provider simply define a struct of named
/// fields with type [`KStatU64`] and derive [`KStatProvider`].
///
/// ```
/// use opte::ddi::kstat::{self, KStatProvider, KStatU64};
///
/// #[derive(KStatProvider)]
/// struct SomeStats {
///     bytes_out: KStatU64,
///     bytes_in: KStatU64,
///     errors_out: KStatU64,
///     errors_in: KStatU64,
/// }
/// ```
///
/// To update the values use the `+=` operator.
///
/// ```ignore
/// some_val.stats.bytes_out += 54;
/// ```
///
/// To register a provider see [`KStatNamed`].
pub trait KStatProvider {
    const NUM_FIELDS: u32;
    type Snap;

    fn init(&mut self) -> Result<(), Error>;

    fn new() -> Self;

    fn num_fields(&self) -> u32 {
        Self::NUM_FIELDS
    }

    /// Return a snapshot of the stats. This is how you obtain a copy,
    /// as opposed to the traditional clone().
    fn snapshot(&self) -> Self::Snap;
}

/// Initialize and register a [`KStatProvider`].
///
/// To initialize, and register the provider, call
/// [`KStatNamed::new()`] as described below. This should be called
/// **exactly** once for a given provider. When this value is dropped
/// the provider is unregistered from the kstats list.
///
/// ```
/// use opte::ddi::kstat::{self, KStatNamed, KStatProvider, KStatU64};
///
/// #[derive(KStatProvider)]
/// pub struct StatProvider {
///     my_counter: KStatU64,
/// }
///
/// KStatNamed::new("module", "name", StatProvider::new());
/// ```
///
/// # std/test
///
/// For testing there is no kstats system to register with; we just
/// allocate the stats. This allows tests to verify that certain
/// statistics are incremented when expected.
pub struct KStatNamed<T: KStatProvider> {
    // The illumos kernel only reads this data, e.g. when someone
    // reads the stats from userland. We do not bother with setting
    // `kstat_t.ks_lock`. The practical implication of this choice is
    // that a userland consumer could see stats that are not
    // consistent *as a whole*; meaning that the individual stats will
    // contain uncorrupted values, but the values taken as a group may
    // present the results of a process that is only partially
    // completed.
    pub vals: Box<T>,

    #[cfg(all(not(feature = "std"), not(test)))]
    ksp: *mut kstat_t,
}

#[cfg(all(not(feature = "std"), not(test)))]
impl<T: KStatProvider> KStatNamed<T> {
    pub fn new(
        module: &str,
        name: &str,
        provider: T,
    ) -> Result<KStatNamed<T>, Error> {
        let mod_c = CString::new(module)?;
        let name_c = CString::new(name)?;
        let class_c = CString::new("net")?;
        let mut vals = Box::new(provider);

        // Safety: We know these are valid string pointers as we just
        // created them.
        let ksp = unsafe {
            kstat_create(
                mod_c.as_ptr(),
                0,
                name_c.as_ptr(),
                class_c.as_ptr(),
                KSTAT_TYPE_NAMED as u8,
                u64::from(T::NUM_FIELDS),
                illumos_sys_hdrs::KSTAT_FLAG_VIRTUAL as u8,
            )
        };

        if let Err(e) = vals.init() {
            // Safety: We just created this above with kstat_create(9F).
            unsafe { kstat_delete(ksp) };
            return Err(e);
        }

        // Safety: We know ksp is legit because we allocated it with
        // kstat_create(9F).
        unsafe {
            (*ksp).ks_data = vals.as_mut() as *mut T as *mut c_void;
        }

        // Safety: We know the ksp is a valid kstat_t because it came
        // from kstat_create(9F).
        unsafe { kstat_install(ksp) };
        Ok(Self { vals, ksp })
    }
}

#[cfg(all(not(feature = "std"), not(test)))]
impl<T: KStatProvider> Drop for KStatNamed<T> {
    fn drop(&mut self) {
        // Safety: We know the ksp is a valid kstat_t because it came
        // from kstat_create(9F).
        unsafe { kstat_delete(self.ksp) };
    }
}

#[cfg(any(feature = "std", test))]
impl<T: KStatProvider> KStatNamed<T> {
    // This cannot fail in std/test environment.
    pub fn new(
        _module: &str,
        _name: &str,
        provider: T,
    ) -> Result<KStatNamed<T>, Error> {
        Ok(Self { vals: Box::new(provider) })
    }
}

/// A 64-bit unsigned named kstat.
///
/// # Illumos
///
/// * `kstat_named_init(9F)`
/// * `kstat_named(9S)`
#[cfg(all(not(feature = "std"), not(test)))]
#[repr(transparent)]
#[derive(Default)]
pub struct KStatU64 {
    inner: kstat_named_t,
}

#[cfg(all(not(feature = "std"), not(test)))]
impl KStatU64 {
    pub fn init(&mut self, name: &str) -> Result<(), Error> {
        let cstr = CString::new(name)?;

        // The underlying kstat system will automatically truncate,
        // but we opt to alert the consumer instead.
        if cstr.as_bytes_with_nul().len() > KSTAT_STRLEN {
            return Err(Error::NameTooLong(name.to_string()));
        }

        // Safety: We know that `&mut self` points to a
        // `kstat_named_t` because we let the `kstat_create(9F)`
        // routine allocate the `kstat_t.ks_data`.
        unsafe {
            kstat_named_init(
                &mut self.inner as *mut kstat_named_t,
                cstr.as_ptr(),
                illumos_sys_hdrs::KSTAT_DATA_UINT64 as u8,
            );
        }
        Ok(())
    }

    #[inline(always)]
    fn inner(&self) -> &AtomicU64 {
        // SAFETY: only `inner.as_u64` is called on this type, so mixed-width
        // reads/writes are disallowed.
        unsafe { self.inner.as_u64() }
    }
}

#[cfg(any(feature = "std", test))]
#[derive(Default)]
pub struct KStatU64 {
    value: AtomicU64,
}

#[cfg(any(feature = "std", test))]
impl KStatU64 {
    pub fn init(&mut self, _name: &str) -> Result<(), Error> {
        Ok(())
    }

    #[inline(always)]
    fn inner(&self) -> &AtomicU64 {
        &self.value
    }
}

impl KStatU64 {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, val: u64) {
        self.inner().store(val, Ordering::Relaxed)
    }

    pub fn val(&self) -> u64 {
        self.inner().load(Ordering::Relaxed)
    }

    pub fn incr(&self, val: u64) {
        self.inner().fetch_add(val, Ordering::Relaxed);
    }

    pub fn decr(&self, val: u64) {
        self.inner().fetch_sub(val, Ordering::Relaxed);
    }
}

impl core::ops::AddAssign<u64> for KStatU64 {
    #[inline]
    fn add_assign(&mut self, other: u64) {
        self.incr(other);
    }
}

impl core::ops::SubAssign<u64> for KStatU64 {
    #[inline]
    fn sub_assign(&mut self, other: u64) {
        self.decr(other);
    }
}

/// A kstat error.
#[derive(Clone, Debug)]
pub enum Error {
    NameTooLong(String),
    NulChar,
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::NameTooLong(name) => {
                write!(f, "kstat name too long: {name}")
            }

            Self::NulChar => write!(f, "kstat name contains NUL char"),
        }
    }
}

#[cfg(all(not(feature = "std"), not(test)))]
impl From<alloc::ffi::NulError> for Error {
    fn from(_e: alloc::ffi::NulError) -> Self {
        Self::NulChar
    }
}

// SAFETY: KStatNamed<T> is safe for Send + Sync under the following conditions:
//
// 1. Read-only sharing: After creation, the `ksp` pointer is never mutated - only
//    passed to kstat_delete() in Drop. Multiple threads can safely read the same
//    immutable pointer value.
//
// 2. Kernel manages concurrency: The kstat framework handles concurrent access to 
//    the underlying kernel structures via its own internal mechanisms.
//
// 3. Atomic statistics: Individual stats in `vals` use AtomicU64, ensuring each
//    counter update is atomic and thread-safe.
//
// 4. Intentional design trade-off: We explicitly do NOT set ks_lock (see struct
//    comment), accepting that different threads may see inconsistent snapshots
//    of the stats as a group, while individual values remain uncorrupted.
//
// 5. No shared mutable state: The raw pointer represents a kernel resource with
//    a clear lifecycle (create -> install -> delete) with no Rust-side mutation.
#[cfg(all(not(feature = "std"), not(test)))]
unsafe impl<T: KStatProvider> Send for KStatNamed<T> {}
#[cfg(all(not(feature = "std"), not(test)))]
unsafe impl<T: KStatProvider> Sync for KStatNamed<T> {}
