// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Safe abstractions for synchronization primitives.

#[cfg(all(not(feature = "std"), not(test)))]
pub use illumos::sync::*;

#[cfg(any(feature = "std", test))]
pub use wrapper::*;

#[cfg(any(feature = "std", test))]
mod wrapper {
    use core::ops::Deref;
    use core::ops::DerefMut;
    use std::sync::Mutex;

    // In a std environment we just wrap `Mutex`.
    pub struct KMutex<T> {
        inner: Mutex<T>,
    }

    pub struct KMutexGuard<'a, T: 'a> {
        guard: std::sync::MutexGuard<'a, T>,
    }

    impl<T> Deref for KMutexGuard<'_, T> {
        type Target = T;

        fn deref(&self) -> &T {
            self.guard.deref()
        }
    }

    impl<T> DerefMut for KMutexGuard<'_, T> {
        fn deref_mut(&mut self) -> &mut T {
            self.guard.deref_mut()
        }
    }

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

    // In a std environment we just wrap `RwLock`.
    pub struct KRwLock<T> {
        inner: std::sync::RwLock<T>,
    }

    pub struct KRwLockReadGuard<'a, T: 'a> {
        guard: std::sync::RwLockReadGuard<'a, T>,
    }

    pub struct KRwLockWriteGuard<'a, T: 'a> {
        guard: std::sync::RwLockWriteGuard<'a, T>,
    }

    impl<T> Deref for KRwLockReadGuard<'_, T> {
        type Target = T;

        fn deref(&self) -> &T {
            self.guard.deref()
        }
    }

    impl<T> Deref for KRwLockWriteGuard<'_, T> {
        type Target = T;

        fn deref(&self) -> &T {
            self.guard.deref()
        }
    }

    impl<T> DerefMut for KRwLockWriteGuard<'_, T> {
        fn deref_mut(&mut self) -> &mut T {
            self.guard.deref_mut()
        }
    }

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
}
