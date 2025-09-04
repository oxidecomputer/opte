// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2025 Oxide Computer Company

use crate::postbox::Postbox;
use crate::xde::XdeDev;
use alloc::collections::btree_map::BTreeMap;
use alloc::collections::btree_map::Entry;
use alloc::collections::btree_set::BTreeSet;
use alloc::string::String;
use alloc::sync::Arc;
use opte::api::Ipv6Addr;
use opte::api::MacAddr;
use opte::api::OpteError;
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
    mcast_groups: BTreeMap<Ipv6Addr, BTreeSet<VniMac>>,
}

impl Default for DevMap {
    fn default() -> Self {
        Self::new()
    }
}

impl DevMap {
    pub const fn new() -> Self {
        Self {
            devs: BTreeMap::new(),
            names: BTreeMap::new(),
            mcast_groups: BTreeMap::new(),
        }
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

    /// Allow a port to receive on a given multicast group.
    ///
    /// This takes the overlay (outer v6) multicast group address.
    pub fn multicast_subscribe(
        &mut self,
        name: &str,
        mcast_ip: Ipv6Addr,
    ) -> Result<(), OpteError> {
        let port = self
            .get_by_name(name)
            .ok_or_else(|| OpteError::PortNotFound(name.into()))?;
        let key = get_key(port);

        // TODO: probably could store Arcs or Weaks here, but want to be safe for now.
        self.mcast_groups.entry(mcast_ip).or_default().insert(key);

        Ok(())
    }

    /// Rescind a port's ability to receive on a given multicast group.
    pub fn multicast_unsubscribe(
        &mut self,
        name: &str,
        mcast_ip: Ipv6Addr,
    ) -> Result<(), OpteError> {
        let port = self
            .get_by_name(name)
            .ok_or_else(|| OpteError::PortNotFound(name.into()))?;
        let key = get_key(port);

        // TODO: Do we need handling for a special VNI from rack-external traffic?
        if let Entry::Occupied(set) = self.mcast_groups.entry(mcast_ip) {
            set.into_mut().remove(&key);
        }

        Ok(())
    }

    /// Find the keys for all ports who want to receive a given multicast packet.
    pub fn multicast_listeners(
        &self,
        mcast_ip: &Ipv6Addr,
    ) -> Option<impl Iterator<Item = &VniMac>> {
        self.mcast_groups.get(mcast_ip).map(|v| v.iter())
    }

    /// Return a reference to an `XdeDev` using its address.
    #[inline]
    #[must_use]
    pub fn get_by_key(&self, key: VniMac) -> Option<&Dev> {
        self.devs.get(&key)
    }

    /// Return a reference to an `XdeDev` using its name.
    #[inline]
    #[must_use]
    pub fn get_by_name(&self, name: &str) -> Option<&Dev> {
        self.names.get(name)
    }

    /// Return an iterator over all `XdeDev`s, sorted by address.
    pub fn iter(&self) -> impl Iterator<Item = &Dev> {
        self.devs.values()
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
