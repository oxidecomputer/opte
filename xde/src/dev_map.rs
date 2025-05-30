// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

use crate::mailbox::Mailbox;
use crate::xde::XdeDev;
use alloc::collections::btree_map::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use opte::api::MacAddr;
use opte::api::Vni;

// From microbenchmarking (https://github.com/oxidecomputer/opte/issues/637)
// it is apparent that we have *far* faster `Ord` and `Eq` implementations
// on these wider integer types than (Vni, MacAddr).
type Key = (u32, u64);
type Val = Arc<XdeDev>;

/// `BTreeMap`-accelerated lookup of XDE ports.
///
/// `XdeDev`s are uniquely keyed on both their name, and their `(Vni, MacAddr)`
/// pair. The former is used mostly by the control plane, and the latter by the
/// data plane -- thus, querying by address provides a direct lookup. Any other
/// lookups (e.g., multicast listeners) should return `Key`s or `&[Key]`s.
#[derive(Clone)]
pub struct DevMap {
    devs: BTreeMap<Key, Val>,
    names: BTreeMap<String, Val>,
}

// NOTE: should we have a Weak variant?

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
    pub fn insert(&mut self, val: Val) -> Option<Val> {
        let key = get_key(&val);
        _ = self.names.insert(val.devname.clone(), val.clone());
        self.devs.insert(key, val)
    }

    /// Remove an `XdeDev` using its name.
    pub fn remove(&mut self, name: &str) -> Option<Val> {
        let key = get_key(&self.names.remove(name)?);
        self.devs.remove(&key)
    }

    /// Return a reference to an `XdeDev` using its address.
    #[inline]
    #[must_use]
    pub fn get(&self, vni: Vni, mac: MacAddr) -> Option<&Val> {
        self.devs.get(&(vni.as_u32(), mac_to_u64(mac)))
    }

    /// Return a reference to an `XdeDev` using its address, alongside its
    /// prebaked key.
    #[inline]
    #[must_use]
    pub fn get_key_value(&self, vni: Vni, mac: MacAddr) -> Option<(Key, &Val)> {
        let key = (vni.as_u32(), mac_to_u64(mac));
        self.devs.get(&key).map(|v| (key, v))
    }

    /// Return a reference to an `XdeDev` using its name.
    #[inline]
    #[must_use]
    pub fn get_by_name(&self, name: &str) -> Option<&Val> {
        self.names.get(name)
    }

    /// Return an iterator over all `XdeDev`s, sorted by address.
    pub fn iter(&self) -> impl Iterator<Item = &Val> {
        self.devs.values()
    }

    /// Return an iterator over all `XdeDev`s, sorted by address.
    pub fn iter_keys(&self) -> impl Iterator<Item = &Key> {
        self.devs.keys()
    }

    /// Return whether any ports currently exist.
    pub fn is_empty(&self) -> bool {
        self.devs.is_empty()
    }

    #[inline]
    pub fn deliver_all(&self, mailbox: &mut Mailbox) {
        for (k, v) in mailbox.drain() {
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
fn get_key(dev: &Val) -> Key {
    (dev.vni.as_u32(), mac_to_u64(dev.port.mac_addr()))
}
