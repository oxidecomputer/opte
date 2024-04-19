use crate::ip;
use crate::sys;
use crate::xde::xde_underlay_port;
use crate::xde::DropRef;
use crate::xde::XdeDev;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::ptr;
use core::time::Duration;
use illumos_sys_hdrs::*;
use opte::ddi::sync::KRwLock;
use opte::ddi::sync::KRwLockType;
use opte::ddi::time::Moment;
use opte::engine::ether::EtherAddr;
use opte::engine::ip6::Ipv6Addr;

// XXX: completely arbitrary timeout.
/// The duration a cached route remains valid for.
const MAX_ROUTE_LIFETIME: Duration = Duration::from_millis(100);

extern "C" {
    pub fn __dtrace_probe_next__hop(
        dst: uintptr_t,
        gw: uintptr_t,
        gw_ether_src: uintptr_t,
        gw_ether_dst: uintptr_t,
        msg: uintptr_t,
    );
}

fn next_hop_probe(
    dst: &Ipv6Addr,
    gw: Option<&Ipv6Addr>,
    gw_eth_src: EtherAddr,
    gw_eth_dst: EtherAddr,
    msg: &[u8],
) {
    let gw_bytes = gw.unwrap_or(&Ipv6Addr::from([0u8; 16])).bytes();

    unsafe {
        __dtrace_probe_next__hop(
            dst.bytes().as_ptr() as uintptr_t,
            gw_bytes.as_ptr() as uintptr_t,
            gw_eth_src.to_bytes().as_ptr() as uintptr_t,
            gw_eth_dst.to_bytes().as_ptr() as uintptr_t,
            msg.as_ptr() as uintptr_t,
        );
    }
}

// The following are wrappers for reference drop functions used in XDE.

fn ire_refrele(ire: *mut ip::ire_t) {
    unsafe { ip::ire_refrele(ire) }
}

fn nce_refrele(ire: *mut ip::nce_t) {
    unsafe { ip::nce_refrele(ire) }
}

fn netstack_rele(ns: *mut ip::netstack_t) {
    unsafe { ip::netstack_rele(ns) }
}

// At this point the core engine of OPTE has delivered a Geneve
// encapsulated guest Ethernet Frame (also simply referred to as "the
// packet") to xde to be sent to the specific outer IPv6 destination
// address. This packet includes the outer Ethernet Frame as well;
// however, the outer frame's destination and source addresses are set
// to zero. It is the job of this function to determine what those
// values should be.
//
// Adjacent to xde is the native IPv6 stack along with its routing
// table. This table is routinely updated to indicate the best path to
// any given IPv6 destination that may be specified in the outer IP
// header. As xde is not utilizing the native IPv6 stack to send out
// the packet, but rather is handing it directly to the mac module, it
// must somehow query the native routing table to determine which port
// this packet should egress and fill in the outer frame accordingly.
// This query is done via a private interface which allows a kernel
// module outside of IP to query the routing table.
//
// This process happens in a sequence of steps described below.
//
// 1. With an IPv6 destination in hand we need to determine the next
//    hop, also known as the gateway, for this address. That is, of
//    our neighbors (in this case one of the two switches, which are
//    also acting as routers), who should we forward this packet to in
//    order for it to arrive at its destination? We get this
//    information from the routing table, which contains Internet
//    Routing Entries, or IREs. Specifically, we query the native IPv6
//    routing table using the kernel function
//    `ire_ftable_lookup_simple_v6()`. This function returns an
//    `ire_t`, which includes the member `ire_u`, which contains the
//    address of the gateway as `ire6_gateway_addr`.
//
// 2. We have the gateway IPv6 address; but in the world of the Oxide
//    Network that is not enough to deliver the packet. In the Oxide
//    Network the router (switch) is not a member of the host's
//    network. Instead, we rely on link-local addresses to reach the
//    switches. The lookup in step (1) gave us that link-local address
//    of the gateway; now we need to figure out how to reach it. That
//    requires consulting the routing table a second time: this time
//    to find the IRE for the gateway's link-local address.
//
// 3. The IRE of the link-local address from step (2) allows us to
//    determine which interface this traffic should traverse.
//    Specifically it gives us access to the `ill_t` of the gateway's
//    link-local address. This structure contains the IP Lower Level
//    information. In particular it contains the `ill_phys_addr`
//    which gives us the source MAC address for our outer frame.
//
// 4. The final piece of information to obtain is the destination MAC
//    address. We have the link-local address of the switch port we
//    want to send to. To get the MAC address of this port it must
//    first be assumed that the host and its connected switches have
//    performed NDP in order to learn each other's IPv6 addresses and
//    corresponding MAC addresses. With that information in hand it is
//    a matter of querying the kernel's Neighbor Cache Entry Table
//    (NCE) for the mapping that belongs to our gateway's link-local
//    address. This is done via the `nce_lookup_v6()` kernel function.
//
// With those four steps we have obtained the source and destination
// MAC addresses and the packet can be sent to mac to be delivered to
// the underlying NIC. However, the careful reader may find themselves
// confused about how step (1) actually works.
//
//   If step (1) always returns a single gateway, then how do we
//   actually utilize both NICs/switches?
//
// This is where a bit of knowledge about routing tables comes into
// play along with our very own Delay Driven Multipath in-rack routing
// protocol. You might imagine the IPv6 routing table on an Oxide Sled
// looking something like this.
//
// Destination/Mask             Gateway                 Flags  If
// ----------------          -------------------------  ----- ---------
// default                   fe80::<sc1_p5>             UG     cxgbe0
// default                   fe80::<sc1_p6>             UG     cxgbe1
// fe80::/10                 fe80::<sc1_p5>             U      cxgbe0
// fe80::/10                 fe80::<sc1_p6>             U      cxgbe1
// fd00:<rack1_sled1>::/64   fe80::<sc1_p5>             U      cxgbe0
// fd00:<rack1_sled1>::/64   fe80::<sc1_p6>             U      cxgbe1
//
// Let's say this host (sled1) wants to send a packet to sled2. Our
// sled1 host lives on network `fd00:<rack1_sled1>::/64` while our
// sled2 host lives on `fd00:<rack1_seld2>::/64` -- the key point
// being they are two different networks and thus must be routed to
// talk to each other. For sled1 to send this packet it will attempt
// to look up destination `fd00:<rack1_sled2>::7777` (in this case
// `7777` is the IP of sled2) in the routing table above. The routing
// table will then perform a longest prefix match against the
// `Destination` field for all entries: the longest prefix that
// matches wins and that entry is returned. However, in this case, no
// destinations match except for the `default` ones. When more than
// one entry matches it is left to the system to decide which one to
// return; typically this just means the first one that matches. But
// not for us! This is where DDM comes into play.
//
// Let's reimagine the routing table again, this time with a
// probability added to each gateway entry.
//
// Destination/Mask             Gateway                 Flags  If      P
// ----------------          -------------------------  ----- ------- ----
// default                   fe80::<sc1_p5>             UG     cxgbe0  0.70
// default                   fe80::<sc1_p6>             UG     cxgbe1  0.30
// fe80::/10                 fe80::<sc1_p5>             U      cxgbe0
// fe80::/10                 fe80::<sc1_p6>             U      cxgbe1
// fd00:<rack1_sled1>::/64   fe80::<sc1_p5>             U      cxgbe0
// fd00:<rack1_sled1>::/64   fe80::<sc1_p6>             U      cxgbe1
//
// With these P values added we now have a new option for deciding
// which IRE to return when faced with two matches: give each a
// probability of return based on their P value. In this case, for any
// given gateway IRE lookup, there would be a 70% chance
// `fe80::<sc1_p5>` is returned and a 30% chance `fe80::<sc1_p6>` is
// returned.
//
// But wait, what determines those P values? That's the job of DDM.
// The full story of what DDM is and how it works is outside the scope
// of this already long block comment; but suffice to say it monitors
// the flow of the network based on precise latency measurements and
// with that data constantly refines the P values of all the hosts's
// routing tables to bias new packets towards one path or another.
#[no_mangle]
fn next_hop<'a>(
    key: &RouteKey,
    ustate: &'a XdeDev,
) -> Result<Route<'a>, &'a xde_underlay_port> {
    let RouteKey { dst: ip6_dst, l4_hash } = key;
    unsafe {
        // Use the GZ's routing table.
        let netstack =
            DropRef::new(netstack_rele, ip::netstack_find_by_zoneid(0));
        assert!(!netstack.inner().is_null());
        let ipst = (*netstack.inner()).netstack_u.nu_s.nu_ip;
        assert!(!ipst.is_null());

        let addr = ip::in6_addr_t {
            _S6_un: ip::in6_addr__bindgen_ty_1 { _S6_u8: key.dst.bytes() },
        };
        let xmit_hint = l4_hash.unwrap_or(0);
        let mut generation_op = 0u32;

        let mut underlay_dev = &*ustate.u1;

        // Step (1): Lookup the IRE for the destination. This is going
        // to return one of the default gateway entries.
        let ire = DropRef::new(
            ire_refrele,
            ip::ire_ftable_lookup_v6(
                &addr,
                ptr::null(),
                ptr::null(),
                0,
                ptr::null_mut(),
                sys::ALL_ZONES,
                ptr::null(),
                0,
                xmit_hint,
                ipst,
                &mut generation_op as *mut ip::uint_t,
            ),
        );

        // TODO If there is no entry should we return host
        // unreachable? I'm not sure since really the guest would map
        // that with its VPC network. That is, if a user saw host
        // unreachable they would be correct to think that their VPC
        // routing table is misconfigured, but in reality it would be
        // an underlay network issue. How do we convey this situation
        // to the user/operator?
        if ire.inner().is_null() {
            // Try without a pinned ill
            opte::engine::dbg!("no IRE for destination {:?}", ip6_dst);
            next_hop_probe(
                ip6_dst,
                None,
                EtherAddr::zero(),
                EtherAddr::zero(),
                b"no IRE for destination\0",
            );
            return Err(underlay_dev);
        }
        let ill = (*ire.inner()).ire_ill;
        if ill.is_null() {
            opte::engine::dbg!("destination ILL is NULL for {:?}", ip6_dst);
            next_hop_probe(
                ip6_dst,
                None,
                EtherAddr::zero(),
                EtherAddr::zero(),
                b"destination ILL is NULL\0",
            );
            return Err(underlay_dev);
        }

        // Step (2): Lookup the IRE for the gateway's link-local
        // address. This is going to return one of the `fe80::/10`
        // entries.
        let ireu = (*ire.inner()).ire_u;
        let gw = ireu.ire6_u.ire6_gateway_addr;
        let gw_ip6 = Ipv6Addr::from(&ireu.ire6_u.ire6_gateway_addr);

        // NOTE: specifying the ill is important here, because the gateway
        // address is going to be of the form fe80::<interface-id>. This means a
        // simple query that does not specify an ill could come back with any
        // route matching fe80::/10 over any interface. Since all interfaces
        // that have an IPv6 link-local address assigned have an associated
        // fe80::/10 route, we must restrict our search to the interface that
        // actually has a route to the desired (non-link-local) destination.
        let flags = ip::MATCH_IRE_ILL as i32;
        let gw_ire = DropRef::new(
            ire_refrele,
            ip::ire_ftable_lookup_v6(
                &gw,
                ptr::null(),
                ptr::null(),
                0,
                ill,
                sys::ALL_ZONES,
                ptr::null(),
                flags,
                xmit_hint,
                ipst,
                &mut generation_op as *mut ip::uint_t,
            ),
        );

        if gw_ire.inner().is_null() {
            opte::engine::dbg!("no IRE for gateway {:?}", gw_ip6);
            next_hop_probe(
                ip6_dst,
                Some(&gw_ip6),
                EtherAddr::zero(),
                EtherAddr::zero(),
                b"no IRE for gateway\0",
            );
            return Err(underlay_dev);
        }

        // Step (3): Determine the source address of the outer frame
        // from the physical address of the IP Lower Layer object
        // member or the internet routing entry.
        let src = (*ill).ill_phys_addr;
        if src.is_null() {
            opte::engine::dbg!(
                "gateway ILL phys addr is NULL for {:?}",
                gw_ip6
            );
            next_hop_probe(
                ip6_dst,
                Some(&gw_ip6),
                EtherAddr::zero(),
                EtherAddr::zero(),
                b"gateway ILL phys addr is NULL\0",
            );
            return Err(underlay_dev);
        }

        let src: [u8; 6] = alloc::slice::from_raw_parts(src, 6)
            .try_into()
            .expect("src mac from pointer");

        // Switch to the 2nd underlay device if we determine the source mac
        // belongs to that device.
        if src == ustate.u2.mac {
            underlay_dev = &ustate.u2;
        }

        let src = EtherAddr::from(src);

        // Step (4): Determine the destination address of the outer
        // frame by retrieving the NCE entry for the gateway's
        // link-local address.
        let nce = DropRef::new(nce_refrele, ip::nce_lookup_v6(ill, &gw));
        if nce.inner().is_null() {
            opte::engine::dbg!("no NCE for gateway {:?}", gw_ip6);
            next_hop_probe(
                ip6_dst,
                Some(&gw_ip6),
                src,
                EtherAddr::zero(),
                b"no NCE for gateway\0",
            );
            return Err(underlay_dev);
        }

        let nce_common = (*nce.inner()).nce_common;
        if nce_common.is_null() {
            opte::engine::dbg!("no NCE common for gateway {:?}", gw_ip6);
            next_hop_probe(
                ip6_dst,
                Some(&gw_ip6),
                src,
                EtherAddr::zero(),
                b"no NCE common for gateway\0",
            );
            return Err(underlay_dev);
        }

        let mac = (*nce_common).ncec_lladdr;
        if mac.is_null() {
            opte::engine::dbg!("NCE MAC address is NULL {:?}", gw_ip6);
            next_hop_probe(
                ip6_dst,
                Some(&gw_ip6),
                src,
                EtherAddr::zero(),
                b"NCE MAC address if NULL for gateway\0",
            );
            return Err(underlay_dev);
        }

        let maclen = (*nce_common).ncec_lladdr_length;
        assert!(maclen == 6);

        let dst: [u8; 6] = alloc::slice::from_raw_parts(mac, 6)
            .try_into()
            .expect("mac from pointer");
        let dst = EtherAddr::from(dst);

        next_hop_probe(ip6_dst, Some(&gw_ip6), src, dst, b"\0");

        Ok(Route { src, dst, underlay_dev })
    }
}

/// A simple caching layer over `next_hop`.
#[derive(Clone)]
pub struct RouteCache(Arc<KRwLock<BTreeMap<RouteKey, CachedRoute>>>);

impl Default for RouteCache {
    fn default() -> Self {
        let mut lock = KRwLock::new(BTreeMap::new());
        lock.init(KRwLockType::Driver);
        Self(lock.into())
    }
}

impl RouteCache {
    /// Retrieve a [`Route`] (device and L2 information) for a given `key`.
    ///
    /// This will retrieve an existing entry, if one exists from a recent
    /// query, or computes the current route using `next_hop` on miss or
    /// discovery of a stale entry.
    pub fn next_hop<'b>(&self, key: RouteKey, xde: &'b XdeDev) -> Route<'b> {
        let t = Moment::now();

        let maybe_route = {
            let route_cache = self.0.read();
            route_cache.get(&key).copied()
        };

        match maybe_route {
            Some(route) if route.is_still_valid(t) => {
                return route.into_route(xde)
            }
            _ => {}
        }

        // Cache miss: intent is to now ask illumos, then insert.
        let mut route_cache = self.0.write();

        // Someone else may have written while we were taking the lock.
        // DO NOT waste time if there's a good route.
        let maybe_route = route_cache.get(&key).copied();
        match maybe_route {
            Some(route) if route.is_still_valid(t) => {
                return route.into_route(xde)
            }
            _ => {}
        }

        // `next_hop` might fail for myriad reasons, but we still
        // send the packet on an underlay device depending on our
        // progress. However, we do not want to cache bad mappings.
        match next_hop(&key, xde) {
            Ok(route) => {
                route_cache.insert(key, route.cached(xde, t));
                route
            }
            Err(underlay_dev) => Route {
                src: EtherAddr::zero(),
                dst: EtherAddr::zero(),
                underlay_dev,
            },
        }
    }

    /// Discards any cached route entries which have expired.
    pub fn expire_routes(&self) {
        let mut route_cache = self.0.write();

        let t = Moment::now();
        route_cache.retain(|_, v| v.is_still_valid(t));
    }
}

/// An underlay routing destination and flow-dependent entropy.
#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RouteKey {
    pub dst: Ipv6Addr,
    pub l4_hash: Option<u32>,
}

/// Cached representation of [`Route`].
#[derive(Copy, Clone, Debug)]
pub struct CachedRoute {
    pub src: EtherAddr,
    pub dst: EtherAddr,
    pub underlay_idx: u8,
    pub timestamp: Moment,
}

impl CachedRoute {
    fn is_still_valid(&self, t: Moment) -> bool {
        t.delta_as_millis(self.timestamp)
            <= MAX_ROUTE_LIFETIME.as_millis() as u64
    }

    fn into_route(self, xde: &XdeDev) -> Route<'_> {
        Route {
            src: self.src,
            dst: self.dst,
            // This is not a pretty construction, and will not work for
            // a hypothetically higher port count.
            underlay_dev: if self.underlay_idx == 0 {
                &xde.u1
            } else {
                &xde.u2
            },
        }
    }
}

/// Output port and L2 information needed to emit a packet over the underlay.
#[derive(Copy, Clone, Debug)]
pub struct Route<'a> {
    pub src: EtherAddr,
    pub dst: EtherAddr,
    pub underlay_dev: &'a xde_underlay_port,
}

impl Route<'_> {
    fn cached(&self, xde: &XdeDev, timestamp: Moment) -> CachedRoute {
        // As unfortunate as `into_route`.
        let port_0: &xde_underlay_port = &xde.u1;
        let underlay_idx =
            if core::ptr::eq(self.underlay_dev, port_0) { 0 } else { 1 };

        CachedRoute { src: self.src, dst: self.dst, underlay_idx, timestamp }
    }
}
