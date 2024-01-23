// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

//! Safe abstractions for synchronization primitives.
//!
//! TODO: This should be in its own crate, wrapping the illumos-ddi-dki
//! crate. But for now just let it live here.
use core::ops::Deref;
use core::ops::DerefMut;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use core::cell::UnsafeCell;
        use core::ptr;
        use illumos_sys_hdrs::{
            kmutex_t, krw_t, krwlock_t, mutex_enter, mutex_exit,
            mutex_init, rw_enter, rw_exit, rw_init,
        };
    } else {
        use std::sync::Mutex;
    }
}

use illumos_sys_hdrs::kmutex_type_t;
use illumos_sys_hdrs::krw_type_t;

/// Exposes the illumos mutex(9F) API in a safe manner. We name it
/// `KMutex` (Kernel Mutex) on purpose. The API for a kernel mutex
/// isn't quite the same as a userland `Mutex`, and there's no reason
/// that we have to use that exact name. Using `KMutex` makes it
/// obvious that we are using a mutex, but not the one that comes from
/// std.
///
/// Our `kmutex_t` implementation has no self referential pointers, so
/// there is no reason it needs to pin to a location. This allows us to
/// have an API that looks more Rust-like: returning a `KMutex` value
/// that is initialized and can be placed anywhere. This is in contrast
/// to the typical illumos API where you have a `kmutex_t` embedded in
/// your structure (or as a global) and pass a pointer to
/// `mutex_init(9F)` to initialize it in place.
///
/// For now we assume only `Sized` types are protected by a mutex. For
/// some reason, rust-for-linux adds a `?Sized` bound for the type
/// definition as well as various impl blocks, minus the one that deals
/// with creating a new mutex. I'm not sure why they do this,
/// esepcially if the impl prevents you from creating a mutex holding a
/// DST. I'm not sure if a mutex should ever hold a DST, because a DST
/// is necessairly a pointer, and we would need to make sure that if a
/// shared reference was passed in that it's the only one outstanindg.
///
/// It seems the std Mutex also does this, but once against I'm not
/// sure why.
#[cfg(all(not(feature = "std"), not(test)))]
pub struct KMutex<T> {
    // The mutex(9F) structure.
    mutex: UnsafeCell<kmutex_t>,

    // The data this mutex protects.
    data: UnsafeCell<T>,
}

pub enum KMutexType {
    Adaptive = kmutex_type_t::MUTEX_ADAPTIVE as isize,
    Spin = kmutex_type_t::MUTEX_SPIN as isize,
    Driver = kmutex_type_t::MUTEX_DRIVER as isize,
    Default = kmutex_type_t::MUTEX_DEFAULT as isize,
}

impl From<KMutexType> for kmutex_type_t {
    fn from(mtype: KMutexType) -> Self {
        match mtype {
            KMutexType::Adaptive => kmutex_type_t::MUTEX_ADAPTIVE,
            KMutexType::Spin => kmutex_type_t::MUTEX_SPIN,
            KMutexType::Driver => kmutex_type_t::MUTEX_DRIVER,
            KMutexType::Default => kmutex_type_t::MUTEX_DEFAULT,
        }
    }
}

// TODO understand:
//
// o Why does rust-for-linux use `T: ?Sized` for struct def.
#[cfg(all(not(feature = "std"), not(test)))]
impl<T> KMutex<T> {
    pub fn into_inner(self) -> T
    where
        T: Sized,
    {
        self.data.into_inner()
    }

    /// Create, initialize, and return a new kernel mutex (mutex(9F))
    /// of type `mtype`, and wrap it around `val`. The returned
    /// `KMutex` is the new owner of `val`. All access from here on out
    /// must be done by acquiring a `KMutexGuard` via the `lock()`
    /// method.
    pub fn new(val: T, mtype: KMutexType) -> Self {
        let mut kmutex = kmutex_t { _opaque: 0 };
        // TODO This assumes the mutex is never used in interrupt
        // context. Need to pass 4th arg to set priority.
        //
        // We never use the mutex name argument.
        //
        // Safety: ???.
        unsafe {
            mutex_init(&mut kmutex, ptr::null(), mtype.into(), ptr::null());
        }

        KMutex { mutex: UnsafeCell::new(kmutex), data: UnsafeCell::new(val) }
    }

    /// Try to acquire the mutex guard to gain access to the underlying
    /// value. If the guard is currently held, then this call will
    /// block. The mutex is released when the guard is dropped.
    pub fn lock(&self) -> KMutexGuard<T> {
        // Safety: ???.
        unsafe { mutex_enter(self.mutex.get()) };
        KMutexGuard { lock: self }
    }
}

unsafe impl<T: Send> Send for KMutex<T> {}
unsafe impl<T: Sync> Sync for KMutex<T> {}

#[cfg(all(not(feature = "std"), not(test)))]
pub struct KMutexGuard<'a, T: 'a> {
    lock: &'a KMutex<T>,
}

#[cfg(all(not(feature = "std"), not(test)))]
impl<T> Drop for KMutexGuard<'_, T> {
    fn drop(&mut self) {
        // Safety: ???.
        unsafe { mutex_exit(self.lock.mutex.get()) };
    }
}

#[cfg(all(not(feature = "std"), not(test)))]
impl<T> Deref for KMutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

#[cfg(all(not(feature = "std"), not(test)))]
impl<T> DerefMut for KMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

// In a std environment we just wrap `Mutex`.
#[cfg(any(feature = "std", test))]
pub struct KMutex<T> {
    inner: Mutex<T>,
}

#[cfg(any(feature = "std", test))]
pub struct KMutexGuard<'a, T: 'a> {
    guard: std::sync::MutexGuard<'a, T>,
}

#[cfg(any(feature = "std", test))]
impl<T> Deref for KMutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.guard.deref()
    }
}

#[cfg(any(feature = "std", test))]
impl<T> DerefMut for KMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.guard.deref_mut()
    }
}

#[cfg(any(feature = "std", test))]
impl<T> KMutex<T> {
    pub fn into_inner(self) -> T
    where
        T: Sized,
    {
        self.inner.into_inner().unwrap()
    }

    pub fn new(val: T, _mtype: KMutexType) -> Self {
        KMutex { inner: Mutex::new(val) }
    }

    pub fn lock(&self) -> KMutexGuard<T> {
        let guard = self.inner.lock().unwrap();
        KMutexGuard { guard }
    }
}

/// A wrapper around illumos rwlock(9F)
#[cfg(all(not(feature = "std"), not(test)))]
pub struct KRwLock<T> {
    rwl: UnsafeCell<krwlock_t>,
    data: UnsafeCell<T>,
}

pub enum KRwLockType {
    Driver = krw_type_t::RW_DRIVER as isize,
    Default = krw_type_t::RW_DEFAULT as isize,
}

impl From<KRwLockType> for krw_type_t {
    fn from(typ: KRwLockType) -> Self {
        match typ {
            KRwLockType::Driver => krw_type_t::RW_DRIVER,
            KRwLockType::Default => krw_type_t::RW_DEFAULT,
        }
    }
}

#[cfg(all(not(feature = "std"), not(test)))]
pub enum KRwEnterType {
    Writer = krw_t::RW_WRITER.0 as isize,
    Reader = krw_t::RW_READER.0 as isize,
    ReaderStarveWriter = krw_t::RW_READER_STARVEWRITER.0 as isize,
}

#[cfg(all(not(feature = "std"), not(test)))]
impl From<KRwEnterType> for krw_t {
    fn from(typ: KRwEnterType) -> Self {
        match typ {
            KRwEnterType::Writer => krw_t::RW_WRITER,
            KRwEnterType::Reader => krw_t::RW_READER,
            KRwEnterType::ReaderStarveWriter => krw_t::RW_READER_STARVEWRITER,
        }
    }
}

#[cfg(all(not(feature = "std"), not(test)))]
impl<T> KRwLock<T> {
    pub const fn new(val: T) -> Self {
        let rwl = krwlock_t { _opaque: 0 };
        KRwLock { rwl: UnsafeCell::new(rwl), data: UnsafeCell::new(val) }
    }

    pub fn init(&mut self, typ: KRwLockType) {
        unsafe {
            rw_init(self.rwl.get_mut(), ptr::null(), typ.into(), ptr::null());
        }
    }

    pub fn read(&self) -> KRwLockReadGuard<T> {
        unsafe { rw_enter(self.rwl.get(), krw_t::RW_READER) };
        KRwLockReadGuard { lock: self }
    }

    pub fn write(&self) -> KRwLockWriteGuard<T> {
        unsafe { rw_enter(self.rwl.get(), krw_t::RW_WRITER) };
        KRwLockWriteGuard { lock: self }
    }
}

unsafe impl<T: Send> Send for KRwLock<T> {}
unsafe impl<T: Send + Sync> Sync for KRwLock<T> {}

#[cfg(all(not(feature = "std"), not(test)))]
pub struct KRwLockReadGuard<'a, T: 'a> {
    lock: &'a KRwLock<T>,
}

#[cfg(all(not(feature = "std"), not(test)))]
impl<T> Deref for KRwLockReadGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

#[cfg(all(not(feature = "std"), not(test)))]
impl<T> Drop for KRwLockReadGuard<'_, T> {
    fn drop(&mut self) {
        unsafe { rw_exit(self.lock.rwl.get()) };
    }
}

#[cfg(all(not(feature = "std"), not(test)))]
pub struct KRwLockWriteGuard<'a, T: 'a> {
    lock: &'a KRwLock<T>,
}

#[cfg(all(not(feature = "std"), not(test)))]
impl<T> Deref for KRwLockWriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

#[cfg(all(not(feature = "std"), not(test)))]
impl<T> DerefMut for KRwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

#[cfg(all(not(feature = "std"), not(test)))]
impl<T> Drop for KRwLockWriteGuard<'_, T> {
    fn drop(&mut self) {
        unsafe { rw_exit(self.lock.rwl.get()) };
    }
}

// In a std environment we just wrap `RwLock`.
#[cfg(any(feature = "std", test))]
pub struct KRwLock<T> {
    inner: std::sync::RwLock<T>,
}

#[cfg(any(feature = "std", test))]
pub struct KRwLockReadGuard<'a, T: 'a> {
    guard: std::sync::RwLockReadGuard<'a, T>,
}

#[cfg(any(feature = "std", test))]
pub struct KRwLockWriteGuard<'a, T: 'a> {
    guard: std::sync::RwLockWriteGuard<'a, T>,
}

#[cfg(any(feature = "std", test))]
impl<T> Deref for KRwLockReadGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.guard.deref()
    }
}

#[cfg(any(feature = "std", test))]
impl<T> Deref for KRwLockWriteGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.guard.deref()
    }
}

#[cfg(any(feature = "std", test))]
impl<T> DerefMut for KRwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.guard.deref_mut()
    }
}

#[cfg(any(feature = "std", test))]
impl<T> KRwLock<T> {
    pub fn into_inner(self) -> T
    where
        T: Sized,
    {
        self.inner.into_inner().unwrap()
    }

    pub fn new(val: T) -> Self {
        KRwLock { inner: std::sync::RwLock::new(val) }
    }

    pub fn init(&mut self, _typ: KRwLockType) {}

    pub fn read(&self) -> KRwLockReadGuard<T> {
        let guard = self.inner.read().unwrap();
        KRwLockReadGuard { guard }
    }

    pub fn write(&self) -> KRwLockWriteGuard<T> {
        let guard = self.inner.write().unwrap();
        KRwLockWriteGuard { guard }
    }
}
