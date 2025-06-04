// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

//! Safe abstractions for synchronization primitives.
//!
//! TODO: This should be in its own crate, wrapping the illumos-ddi-dki
//! crate. But for now just let it live here.
use core::cell::UnsafeCell;
use core::fmt;
use core::ops::Deref;
use core::ops::DerefMut;
use core::time::Duration;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use core::ptr;
        use core::ptr::NonNull;
        use illumos_sys_hdrs::{
            clock_t, cv_broadcast, cv_destroy, cv_init, cv_signal,
            cv_reltimedwait, cv_reltimedwait_sig, cv_wait, cv_wait_sig,
            kcv_type_t, kcondvar_t, kmutex_t, krw_t, krwlock_t, kthread_t,
            mutex_enter, mutex_exit, mutex_destroy, mutex_init, mutex_tryenter,
            rw_enter, rw_exit, rw_init, rw_destroy, threadp, time_res_t
        };
    } else {
        use std::sync::Condvar;
        use std::sync::Mutex;
        use std::thread::ThreadId;
    }
}

use illumos_sys_hdrs::kmutex_type_t;
use illumos_sys_hdrs::krw_type_t;

/// Exposes the illumos mutex(9F) API in a safe manner.
///
/// We name it `KMutex` (Kernel Mutex) on purpose. The API for a kernel
/// mutex isn't quite the same as a userland `Mutex`, and there's no reason
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
    mutex: KMutexInner,

    // The data this mutex protects.
    data: UnsafeCell<T>,
}

#[cfg(all(not(feature = "std"), not(test)))]
struct KMutexInner(UnsafeCell<kmutex_t>);

#[cfg(all(not(feature = "std"), not(test)))]
impl Drop for KMutexInner {
    fn drop(&mut self) {
        unsafe { mutex_destroy(self.0.get()) }
    }
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
    pub fn new(val: T) -> Self {
        let mut kmutex = kmutex_t { _opaque: 0 };
        // TODO This assumes the mutex is never used in interrupt
        // context. Need to pass 4th arg to set priority.
        //
        // We never use the mutex name argument.
        //
        // Safety: ???.
        unsafe {
            // MUTEX_DRIVER is the only type currently sanctioned by the DDI
            // for use here. The priority argument, when we provide it, will
            // control whether we get adaptive/spin behaviour.
            mutex_init(
                &mut kmutex,
                ptr::null(),
                KMutexType::Driver.into(),
                ptr::null(),
            );
        }

        KMutex {
            mutex: KMutexInner(UnsafeCell::new(kmutex)),
            data: UnsafeCell::new(val),
        }
    }

    /// Try to acquire the mutex guard to gain access to the underlying
    /// value. If the guard is currently held, then this call will
    /// block. The mutex is released when the guard is dropped.
    pub fn lock(&self) -> KMutexGuard<T> {
        // Safety: ???.
        unsafe { mutex_enter(self.mutex.0.get()) };
        KMutexGuard { lock: self }
    }

    /// Try to acquire the mutex guard to gain access to the underlying
    /// value. If the guard is currently held, then this call will
    /// return the [`LockWouldBlock`] error.
    pub fn try_lock(&self) -> Result<KMutexGuard<T>, LockWouldBlock> {
        let try_lock = unsafe { mutex_tryenter(self.mutex.0.get()) };
        if try_lock != 0 {
            Ok(KMutexGuard { lock: self })
        } else {
            Err(LockWouldBlock)
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct LockWouldBlock;

impl core::error::Error for LockWouldBlock {}

impl fmt::Display for LockWouldBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "try_lock failed because the operation would block")
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
        unsafe { mutex_exit(self.lock.mutex.0.get()) };
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

    pub fn new(val: T) -> Self {
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

#[cfg(all(not(feature = "std"), not(test)))]
impl<T> Drop for KRwLock<T> {
    fn drop(&mut self) {
        unsafe { rw_destroy(self.rwl.get()) }
    }
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
    pub fn new(val: T) -> Self {
        let mut rwl = krwlock_t { _opaque: 0 };
        unsafe {
            rw_init(
                &mut rwl,
                ptr::null(),
                KRwLockType::Driver.into(),
                ptr::null(),
            );
        }
        KRwLock { rwl: UnsafeCell::new(rwl), data: UnsafeCell::new(val) }
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

    pub fn read(&self) -> KRwLockReadGuard<T> {
        let guard = self.inner.read().unwrap();
        KRwLockReadGuard { guard }
    }

    pub fn write(&self) -> KRwLockWriteGuard<T> {
        let guard = self.inner.write().unwrap();
        KRwLockWriteGuard { guard }
    }
}

unsafe impl Send for KCondvar {}
unsafe impl Sync for KCondvar {}

/// Exposes the illumos condvar(9F) API in a safe manner.
///
/// On `std`, this falls back to the platform default standard library
/// condition variable implementation.
pub struct KCondvar {
    #[cfg(all(not(feature = "std"), not(test)))]
    cv: UnsafeCell<kcondvar_t>,

    #[cfg(any(feature = "std", test))]
    cv: Condvar,
}

#[cfg(all(not(feature = "std"), not(test)))]
impl KCondvar {
    /// Create a new condition variable.
    pub fn new() -> Self {
        let mut cv = kcondvar_t { _opaque: 0 };

        unsafe {
            cv_init(
                &mut cv,
                ptr::null_mut(),
                kcv_type_t::CV_DRIVER,
                ptr::null_mut(),
            );
        }

        Self { cv: UnsafeCell::new(cv) }
    }

    /// Wake up one thread blocked on this condvar.
    pub fn notify_one(&self) {
        unsafe { cv_signal(self.cv.get()) }
    }

    /// Wake up all threads currently blocked on this condvar.
    pub fn notify_all(&self) {
        unsafe { cv_broadcast(self.cv.get()) }
    }

    /// Block the current thread until this condition variable is notified.
    ///
    /// This thread will temporarily release `lock`, and reacquire it
    /// when awoken. Wakeups may occur spuriously (i.e., without a call
    /// to `notify_one` or `notify_all`).
    pub fn wait<'a, T: 'a>(
        &self,
        lock: KMutexGuard<'a, T>,
    ) -> KMutexGuard<'a, T> {
        unsafe { cv_wait(self.cv.get(), lock.lock.mutex.0.get()) }
        lock
    }

    /// Block the current thread until this condition variable is notified,
    /// or the current thread receives a signal. Returns which of the two
    /// was responsible.
    ///
    /// This is necessary when the thread(s) capable of notifying this CV
    /// are susceptible to a SIGSTOP -- e.g., they do not hold a mutex/rwlock
    /// or have entered an upcall.
    ///
    /// On `std`, this function behaves identically to `.wait()`.
    pub fn wait_sig<'a, T: 'a>(
        &self,
        lock: KMutexGuard<'a, T>,
    ) -> (KMutexGuard<'a, T>, WaitSigCause) {
        let cause = match unsafe {
            cv_wait_sig(self.cv.get(), lock.lock.mutex.0.get())
        } {
            0 => WaitSigCause::Signal,
            a if a > 0 => WaitSigCause::Notify,
            _ => panic!("illegal return value for cv_wait_sig"),
        };
        (lock, cause)
    }

    /// Block the current thread until this condition variable is notified,
    /// or a given timeout elapses. Returns which of the two was responsible.
    pub fn wait_timeout<'a, T: 'a>(
        &self,
        lock: KMutexGuard<'a, T>,
        dur: Duration,
    ) -> (KMutexGuard<'a, T>, TimedWaitCause) {
        let cause = match unsafe {
            cv_reltimedwait(
                self.cv.get(),
                lock.lock.mutex.0.get(),
                dur.as_nanos() as clock_t,
                time_res_t::TR_NANOSEC,
            )
        } {
            -1 => TimedWaitCause::Timeout,
            a if a > 0 => TimedWaitCause::Notify,
            _ => panic!("illegal return value for cv_reltimedwait"),
        };
        (lock, cause)
    }

    /// Block the current thread until this condition variable is notified,
    /// a given timeout elapses, or the current thread receives a signal.
    /// Returns which of the three was responsible.
    ///
    /// On `std`, this function behaves identically to `.wait_timeout()`.
    pub fn wait_timeout_sig<'a, T: 'a>(
        &self,
        lock: KMutexGuard<'a, T>,
        dur: Duration,
    ) -> (KMutexGuard<'a, T>, TimedWaitSigCause) {
        let cause = match unsafe {
            cv_reltimedwait_sig(
                self.cv.get(),
                lock.lock.mutex.0.get(),
                dur.as_nanos() as clock_t,
                time_res_t::TR_NANOSEC,
            )
        } {
            -1 => TimedWaitSigCause::Timeout,
            0 => TimedWaitSigCause::Signal,
            a if a > 0 => TimedWaitSigCause::Notify,
            _ => panic!("illegal return value for cv_reltimedwait_sig"),
        };
        (lock, cause)
    }
}

#[cfg(any(feature = "std", test))]
impl KCondvar {
    /// Create a new condition variable.
    pub fn new() -> Self {
        Self { cv: Condvar::new() }
    }

    /// Wake up one thread blocked on this condvar.
    pub fn notify_one(&self) {
        self.cv.notify_one()
    }

    /// Wake up all threads currently blocked on this condvar.
    pub fn notify_all(&self) {
        self.cv.notify_all()
    }

    /// Block the current thread until this condition variable is notified.
    ///
    /// This thread will temporarily release `lock`, and reacquire it
    /// when awoken. Wakeups may occur spuriously (i.e., without a call
    /// to `notify_one` or `notify_all`).
    pub fn wait<'a, T: 'a>(
        &self,
        lock: KMutexGuard<'a, T>,
    ) -> KMutexGuard<'a, T> {
        KMutexGuard { guard: self.cv.wait(lock.guard).unwrap() }
    }

    /// Block the current thread until this condition variable is notified,
    /// or the current thread receives a signal. Returns which of the two
    /// was responsible.
    ///
    /// This is necessary when the thread(s) capable of notifying this CV
    /// are susceptible to a SIGSTOP -- e.g., they do not hold a mutex/rwlock
    /// or have entered an upcall.
    ///
    /// On `std`, this function behaves identically to `.wait()`.
    pub fn wait_sig<'a, T: 'a>(
        &self,
        lock: KMutexGuard<'a, T>,
    ) -> (KMutexGuard<'a, T>, WaitSigCause) {
        (self.wait(lock), WaitSigCause::Notify)
    }

    /// Block the current thread until this condition variable is notified,
    /// or a given timeout elapses. Returns which of the two was responsible.
    pub fn wait_timeout<'a, T: 'a>(
        &self,
        lock: KMutexGuard<'a, T>,
        dur: Duration,
    ) -> (KMutexGuard<'a, T>, TimedWaitCause) {
        let (guard, cause) = self.cv.wait_timeout(lock.guard, dur).unwrap();
        let cause = if !cause.timed_out() {
            TimedWaitCause::Notify
        } else {
            TimedWaitCause::Timeout
        };
        (KMutexGuard { guard }, cause)
    }

    /// Block the current thread until this condition variable is notified,
    /// a given timeout elapses, or the current thread receives a signal.
    /// Returns which of the three was responsible.
    ///
    /// On `std`, this function behaves identically to `.wait_timeout()`.
    pub fn wait_timeout_sig<'a, T: 'a>(
        &self,
        lock: KMutexGuard<'a, T>,
        dur: Duration,
    ) -> (KMutexGuard<'a, T>, TimedWaitSigCause) {
        let (lock, cause) = self.wait_timeout(lock, dur);

        let cause = match cause {
            TimedWaitCause::Notify => TimedWaitSigCause::Notify,
            TimedWaitCause::Timeout => TimedWaitSigCause::Timeout,
        };

        (lock, cause)
    }
}

impl Default for KCondvar {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(not(feature = "std"), not(test)))]
impl Drop for KCondvar {
    fn drop(&mut self) {
        unsafe { cv_destroy(self.cv.get()) };
    }
}

pub enum WaitSigCause {
    Notify,
    Signal,
}

pub enum TimedWaitCause {
    Notify,
    Timeout,
}

pub enum TimedWaitSigCause {
    Notify,
    Signal,
    Timeout,
}

/// A mutual exclusion mechanism which loans out access to a single
/// internal token. This is used to ensure at most one thread is present
/// in a critical section *without actively holding a [`KMutex`]*.
///
/// This is necessary for some kernel-level operations which will upcall or
/// enter some other context in which it is unsafe to hold a [`KMutex`] or
/// [`KRwLock`]. Any functions attached to the token `T` should denote whether
/// these restrictions apply.
pub struct TokenLock<T> {
    // In future, this could be arbitrary (i.e., taking user-held
    // context like a file descriptor). Similarly this could allow
    // for re-entrancy, but this is tricky to square with `&mut` access
    // to the inner `T`.
    #[cfg(all(not(feature = "std"), not(test)))]
    holder: KMutex<Option<NonNull<kthread_t>>>,
    #[cfg(any(feature = "std", test))]
    holder: KMutex<Option<ThreadId>>,
    cv: KCondvar,
    inner: UnsafeCell<T>,
}

impl<T> TokenLock<T> {
    pub fn new(token: T) -> Self {
        let holder = KMutex::new(None);
        let cv = KCondvar::new();

        Self { holder, cv, inner: UnsafeCell::new(token) }
    }

    pub fn lock(&self) -> TokenGuard<'_, T> {
        let mut thread_lock = self.holder.lock();

        while thread_lock.is_some() {
            // Here, we expect that there is a very real possibility
            // that the kthread in `thread_lock` is, itself, susceptible
            // to being `STOPPED` (and thus deadlocking us) if we cannot
            // also handle a SIGSTOP. We don't care whether we were awoken
            // by the signal or the CV, only that our thread can also stop
            // to allow a fork of the caller to complete.
            thread_lock = self.cv.wait_sig(thread_lock).0;
        }

        #[cfg(all(not(feature = "std"), not(test)))]
        let curthread = unsafe {
            NonNull::new(threadp())
                .expect("current thread *must* be a valid pointer")
        };

        #[cfg(any(feature = "std", test))]
        let curthread = std::thread::current().id();

        *thread_lock = Some(curthread);

        TokenGuard { lock: self }
    }
}

pub struct TokenGuard<'a, T> {
    lock: &'a TokenLock<T>,
}

impl<T> Deref for TokenGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: Only the thread indicated by `parent.holder`
        // can have a `Token`, thus we are safe to take a shared ref
        // (no other writers).
        unsafe { &*self.lock.inner.get() }
    }
}

impl<T> DerefMut for TokenGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: Only the thread indicated by `parent.holder`
        // can have a `Token`, thus there are no other writers.
        // Rust has also guaranteed this is the only &mut to the Token
        // itself, so no other readers.
        unsafe { &mut *self.lock.inner.get() }
    }
}

impl<T> Drop for TokenGuard<'_, T> {
    fn drop(&mut self) {
        let mut thread_lock = self.lock.holder.lock();
        let lock_thread = thread_lock.take();

        self.lock.cv.notify_all();

        // Sanity checking -- same thread at exit.
        #[cfg(all(not(feature = "std"), not(test)))]
        let curthread = unsafe {
            NonNull::new(threadp())
                .expect("current thread *must* be a valid pointer")
        };

        #[cfg(any(feature = "std", test))]
        let curthread = std::thread::current().id();
        assert_eq!(Some(curthread), lock_thread);
    }
}
