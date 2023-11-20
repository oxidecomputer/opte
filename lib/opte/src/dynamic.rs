// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! A KMutex-based wrapper for dynamically updateable resources (e.g., config),
//! and the outputs *generated* from

// TODO: may want to look into porting arc-swap for alloc and core,
//       which should allow us to do better than a mutex.

// TODO: Implement the generated outputs for e.g. DHCP responses.

use crate::ddi::sync::KRwLock;
use crate::ddi::sync::KRwLockType;
use alloc::sync::Arc;
use core::fmt::Debug;
use core::ops::Deref;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use core::write;

#[derive(Clone)]
pub struct Dynamic<T>(Arc<InnerDynamic<T>>);

struct InnerDynamic<T> {
    inner: KRwLock<Arc<T>>,
    epoch: AtomicU64,
}

#[derive(Debug)]
pub struct Snapshot<T> {
    pub value: Arc<T>,
    pub epoch: u64,
}

impl<T> From<T> for Dynamic<T> {
    fn from(value: T) -> Self {
        let mut inner = KRwLock::new(value.into());
        inner.init(KRwLockType::Driver);

        Self(InnerDynamic { inner, epoch: AtomicU64::default() }.into())
    }
}

impl<T> Dynamic<T> {
    pub fn store(&self, value: T) {
        let mut inner = self.0.inner.write();
        *inner = value.into();
        _ = self.0.epoch.fetch_add(1, Ordering::Relaxed);
    }

    pub fn load(&self) -> Snapshot<T> {
        let value_locked = self.0.inner.read();
        let value = Arc::clone(&*value_locked);
        let epoch = self.0.epoch.load(Ordering::Relaxed);

        Snapshot { epoch, value }
    }
}

impl<T: Debug> Debug for Dynamic<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let current_val = self.load();
        write!(f, "{current_val:?}")
    }
}

impl<T> Deref for Snapshot<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}
