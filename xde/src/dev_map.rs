// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

use crate::postbox::Postbox;
use crate::xde::XdeDev;
use alloc::collections::btree_map::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use opte::api::MacAddr;
use opte::api::Vni;
use opte::ddi::sync::KRwLock;
use opte::ddi::sync::KRwLockReadGuard;

/// A map/set lookup key for ports indexed on `(Vni, MacAddr)`.
///
/// From microbenchmarking (https://github.com/oxidecomputer/opte/issues/637)
/// it is apparent that we have *far* faster `Ord` and `Eq` implementations
/// on these wider integer types than (Vni, MacAddr).
#[derive(Copy, Clone, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct VniMac(u32, u64);

impl VniMac {
    #[inline]
    pub fn new(vni: Vni, mac: MacAddr) -> Self {
        VniMac(vni.as_u32(), mac_to_u64(mac))
    }
}

type Dev = Arc<XdeDev>;

/// `BTreeMap`-accelerated lookup of XDE ports.
///
/// `XdeDev`s are uniquely keyed on both their name, and their `(Vni, MacAddr)`
/// pair. The former is used mostly by the control plane, and the latter by the
/// data plane -- thus, querying by address provides a direct lookup. Any other
/// lookups (e.g., multicast listeners) should return `FastKey`s or `&[FastKey]`s.
#[derive(Clone)]
pub struct DevMap {
    devs: BTreeMap<VniMac, Dev>,
    names: BTreeMap<String, Dev>,
}

impl Default for DevMap {
    fn default() -> Self {
        Self::new()
    }
}

impl DevMap {
    pub const fn new() -> Self {
        Self { devs: BTreeMap::new(), names: BTreeMap::new() }
    }

    /// Insert an `XdeDev`.
    ///
    /// Returns an existing port, if one exists.
    pub fn insert(&mut self, val: Dev) -> Option<Dev> {
        let key = get_key(&val);
        _ = self.names.insert(val.devname.clone(), val.clone());
        self.devs.insert(key, val)
    }

    /// Remove an `XdeDev` using its name.
    pub fn remove(&mut self, name: &str) -> Option<Dev> {
        let key = get_key(&self.names.remove(name)?);
        self.devs.remove(&key)
    }

    /// Return a reference to an `XdeDev` using its address.
    #[inline]
    #[must_use]
    pub fn get_by_key(&self, key: VniMac) -> Option<&XdeDev> {
        self.devs.get(&key).map(Arc::as_ref)
    }

    /// Return a reference to an `XdeDev` using its name.
    #[inline]
    #[must_use]
    pub fn get_by_name(&self, name: &str) -> Option<&XdeDev> {
        self.names.get(name).map(Arc::as_ref)
    }

    /// Return an iterator over all `XdeDev`s, sorted by address.
    pub fn iter(&self) -> impl Iterator<Item = &XdeDev> {
        self.devs.values().map(Arc::as_ref)
    }

    /// Return an iterator over all `XdeDev`s, sorted by address.
    pub fn iter_keys(&self) -> impl Iterator<Item = &VniMac> {
        self.devs.keys()
    }

    /// Return whether any ports currently exist.
    pub fn is_empty(&self) -> bool {
        self.devs.is_empty()
    }

    /// Drains all `MsgBlk` chains in a given postbox and attempts to deliver
    /// them to a matching XDE port.
    ///
    /// Any chains without a matching port are dropped.
    #[inline]
    pub fn deliver_all(&self, postbox: Postbox) {
        for (k, v) in postbox.drain() {
            if let Some(port) = self.devs.get(&k) {
                port.deliver(v);
            }
        }
    }
}

#[inline(always)]
fn mac_to_u64(val: MacAddr) -> u64 {
    let val = val.bytes();
    u64::from_be_bytes([0, 0, val[0], val[1], val[2], val[3], val[4], val[5]])
}

#[inline(always)]
fn get_key(dev: &Dev) -> VniMac {
    VniMac::new(dev.vni, dev.port.mac_addr())
}

/// A read-only wrapper around a shared [`DevMap`], used to
/// limit write access to certain contexts.
pub struct ReadOnlyDevMap(Arc<KRwLock<DevMap>>);

impl ReadOnlyDevMap {
    pub fn new(rwl: Arc<KRwLock<DevMap>>) -> Self {
        Self(rwl)
    }

    pub fn read(&self) -> KRwLockReadGuard<'_, DevMap> {
        self.0.read()
    }
}
