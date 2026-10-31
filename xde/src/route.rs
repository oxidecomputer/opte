// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

use crate::ip;
use crate::route_policy::HopId;
use crate::route_policy::HopSlot;
use crate::route_policy::admit_exact_dest;
use crate::route_policy::assign_hop_slot;
use crate::route_policy::dest_reuses_stored_prefix;
use crate::route_policy::may_install;
use crate::route_policy::may_overwrite;
use crate::route_policy::may_touch_born;
use crate::route_policy::round_robin_hop;
use crate::route_policy::snapshot_generation;
use crate::sys;
use crate::xde::DropRef;
use crate::xde::UnderlayIndex;
use crate::xde::XdeDev;
use alloc::collections::BTreeMap;
use alloc::collections::btree_map::Entry;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ffi::CStr;
use core::ptr;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::Ordering;
use core::time::Duration;
use illumos_sys_hdrs::*;
use opte::ddi::kstat::KStatNamed;
use opte::ddi::kstat::KStatProvider;
use opte::ddi::kstat::KStatU64;
use opte::ddi::sync::KRwLock;
use opte::ddi::time::Moment;
use opte::engine::ether::EtherAddr;
use opte::engine::ip::v6::Ipv6Addr;
use opte::engine::port::PortCreateError;

/// Prefix sets stored for one port. An entry is one underlay prefix, not one flow.
const MAX_PREFIX_SETS: usize = 1024;

/// Equal-cost hops kept for one prefix. A sled has two underlay ports; the
/// extra slots cover a wider group without a heap allocation on the TX path.
const MAX_HOPS: usize = 8;

/// How long a stored snapshot may answer without walking the bucket again.
const CHOICE_LIFETIME: Duration = Duration::from_millis(100);

/// Chain walk limit. A corrupt `ire_next` must not spin the TX thread.
/// A bucket longer than this cannot be reproduced locally: the packet asks
/// `ire_ftable_lookup_v6` once instead of guessing from a partial list.
const MAX_BUCKET_WALK: usize = 64;

/// `slots[i]` is not a hop of this prefix. Round-robin skips it and continues.
const SLOT_OTHER: u8 = 0xff;
/// `slots[i]` is a matching hop that did not fit in `MAX_HOPS`.
const SLOT_MISSING: u8 = 0xfe;

unsafe extern "C" {
    pub safe fn __dtrace_probe_next__hop(
        dst: uintptr_t,
        gw: uintptr_t,
        gw_ether_src: uintptr_t,
        gw_ether_dst: uintptr_t,
        msg: *const c_char,
    );

    pub safe fn __dtrace_probe_routecache__full(
        cache: uintptr_t,
        dst: uintptr_t,
        entropy: uintptr_t,
    );

    pub safe fn __dtrace_probe_routecache__insert(
        cache: uintptr_t,
        dst: uintptr_t,
        entropy: uintptr_t,
    );

    pub safe fn __dtrace_probe_routecache__refresh(
        cache: uintptr_t,
        dst: uintptr_t,
        entropy: uintptr_t,
    );

    pub safe fn __dtrace_probe_routecache__delete(
        cache: uintptr_t,
        dst: uintptr_t,
        entropy: uintptr_t,
    );
}

fn next_hop_probe(
    dst: &Ipv6Addr,
    gw: Option<&Ipv6Addr>,
    gw_eth_src: EtherAddr,
    gw_eth_dst: EtherAddr,
    msg: &CStr,
) {
    let gw_bytes = gw.unwrap_or(&Ipv6Addr::from([0u8; 16])).bytes();

    __dtrace_probe_next__hop(
        dst.bytes().as_ptr() as uintptr_t,
        gw_bytes.as_ptr() as uintptr_t,
        gw_eth_src.to_bytes().as_ptr() as uintptr_t,
        gw_eth_dst.to_bytes().as_ptr() as uintptr_t,
        msg.as_ptr(),
    );
}

fn route_full_probe(map: uintptr_t, key: &RouteKey) {
    __dtrace_probe_routecache__full(
        map,
        key.dst.as_ptr() as uintptr_t,
        key.l4_hash.unwrap_or_default() as uintptr_t,
    );
}

fn route_insert_probe(map: uintptr_t, key: &RouteKey) {
    __dtrace_probe_routecache__insert(
        map,
        key.dst.as_ptr() as uintptr_t,
        key.l4_hash.unwrap_or_default() as uintptr_t,
    );
}

fn route_refresh_probe(map: uintptr_t, key: &RouteKey) {
    __dtrace_probe_routecache__refresh(
        map,
        key.dst.as_ptr() as uintptr_t,
        key.l4_hash.unwrap_or_default() as uintptr_t,
    );
}

fn route_delete_probe(map: uintptr_t, key: &RouteKey) {
    __dtrace_probe_routecache__delete(
        map,
        key.dst.as_ptr() as uintptr_t,
        key.l4_hash.unwrap_or_default() as uintptr_t,
    );
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
// sled2 host lives on `fd00:<rack1_sled2>::/64` -- the key point
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
//
// Issue #539: walk the bucket once per generation and remember each hop's MAC.
// A later packet does not call `ire_ftable_lookup_v6` while that destination's
// own confirmation and the hop snapshot are both inside `CHOICE_LIFETIME`.
// Traffic to another address of the same prefix can renew the snapshot
// without renewing this destination. After 100 ms the packet calls
// `identify`, which is what observes a more-specific route. The account
// is `ire_round_robin`: mix the hint, divide by `irb_ire_cnt`, skip
// that many non-condemned IREs, and take the next IRE of this exact address.
// The modulus is the whole bucket. `hash % n` over the stored hops is a
// different choice. A removed gateway stays reachable until this snapshot's
// 100 ms ends. A neighbor MAC that does not change
// `ire_generation` is resolved again on the first reuse after those 100 ms.
// If that read fails, the packet may still use the stored MAC, but the
// snapshot is not extended and the choice is not cached. The generation
// folds `generation_op`, the bucket length, each gateway, IRE generation,
// bad count, and `ire_ill`, then the complete flag and the slot array. It
// does not fold `PrefixKey` again. Another route moving inside the bucket
// is not reused. Local selection stays off when `_ecmp_behavior` is not the
// always-on mode, when a matching hop has `ire_badcnt` and another match
// exists, or when `ire_match_args_v6` rejects a held hop. Those packets ask
// IP, and that lookup can still fail. The xde lookup uses `ALL_ZONES`, so
// the zone gateway check does not run.
#[unsafe(no_mangle)]
fn get_os_next_hop(
    key: &RouteKey,
    ustate: &XdeDev,
) -> Result<Route, UnderlayIndex> {
    let (found, _, _, _) =
        consult(&key.dst, ustate, None, |_, _| (None, None))?;
    if let Some((route, _)) = local_select(&found, key.l4_hash) {
        return Ok(route);
    }
    chosen_route(&found, key.dst, key.l4_hash, ustate)
}

/// One prefix's resolved hops. `len == 0` is not stored.
#[derive(Copy, Clone)]
struct StoredSet {
    key: PrefixKey,
    hops: [Route; MAX_HOPS],
    /// Gateway of `hops[i]`, in bucket order.
    gws: [[u8; 16]; MAX_HOPS],
    /// `ire_ill` of `hops[i]`. The gateway address alone does not name the hop.
    ills: [usize; MAX_HOPS],
    /// `slots[i]` is the hop index at non-condemned position `i`, `SLOT_OTHER`,
    /// or `SLOT_MISSING`. Length used is `bucket_cnt`.
    slots: [u8; MAX_BUCKET_WALK],
    bucket_cnt: u16,
    /// Nonzero when `slots` covers the whole bucket and every match was stored.
    complete: u8,
    len: u8,
    generation: u32,
    /// An address covered by this prefix, used to re-read generation.
    /// The periodic pass does not re-confirm the other destinations.
    sample: [u8; 16],
    /// When this snapshot was last confirmed. Older than
    /// [`CHOICE_LIFETIME`] and the next packet walks again.
    born: Moment,
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct PrefixKey {
    masklen: u32,
    addr: [u8; 16],
}

/// One destination's prefix, and when that coverage was last confirmed.
///
/// `verified` belongs to this destination. Renewing the shared snapshot does
/// not move it.
#[derive(Copy, Clone)]
struct DestEntry {
    prefix: PrefixKey,
    verified: Moment,
}

/// IREs refheld by [`identify`]. Dropped with `ire_refrele`.
struct Ident {
    key: PrefixKey,
    generation: u32,
    sample: [u8; 16],
    n: u8,
    held: [*mut ip::ire_t; MAX_HOPS],
    slots: [u8; MAX_BUCKET_WALK],
    bucket_cnt: u16,
    complete: u8,
    ipst: *mut ip::ip_stack_t,
    netstack: *mut ip::netstack_t,
}

impl Ident {
    fn blank(sample: [u8; 16]) -> Self {
        Self {
            key: PrefixKey { masklen: 0, addr: [0; 16] },
            generation: 0,
            sample,
            n: 0,
            held: [ptr::null_mut(); MAX_HOPS],
            slots: [SLOT_OTHER; MAX_BUCKET_WALK],
            bucket_cnt: 0,
            complete: 0,
            ipst: ptr::null_mut(),
            netstack: ptr::null_mut(),
        }
    }
}

impl Drop for Ident {
    fn drop(&mut self) {
        for ire in self.held.iter_mut().take(self.n as usize) {
            if !ire.is_null() {
                ire_refrele(*ire);
                *ire = ptr::null_mut();
            }
        }
        self.n = 0;
        if !self.netstack.is_null() {
            netstack_rele(self.netstack);
            self.netstack = ptr::null_mut();
        }
    }
}

/// Look up `dst`, then walk its forwarding bucket for every equal prefix.
///
/// The bucket lock is held only while the chain is copied and refheld. Gateway
/// and NCE resolution happens later, without that lock, so a nested
/// `ire_ftable_lookup_v6` cannot deadlock on the same `irb_lock`.
fn identify(dst: &Ipv6Addr) -> Result<Ident, UnderlayIndex> {
    let mut ident = Ident::blank(dst.bytes());
    unsafe {
        let netstack = ip::netstack_find_by_zoneid(0);
        assert!(!netstack.is_null());
        ident.netstack = netstack;
        let ipst = (*netstack).netstack_u.nu_s.nu_ip;
        assert!(!ipst.is_null());
        ident.ipst = ipst;

        let addr = ip::in6_addr_t {
            _S6_un: ip::in6_addr__bindgen_ty_1 { _S6_u8: dst.bytes() },
        };
        let mut generation_op = 0u32;
        // Hint 0 only to discover the bucket. The walk, not the hint, picks
        // the set.
        let ire = ip::ire_ftable_lookup_v6(
            &addr,
            ptr::null(),
            ptr::null(),
            0,
            ptr::null_mut(),
            sys::ALL_ZONES,
            ptr::null(),
            0,
            0,
            ipst,
            &mut generation_op as *mut ip::uint_t,
        );
        if ire.is_null() {
            opte::engine::dbg!("no IRE for destination {:?}", dst);
            next_hop_probe(
                dst,
                None,
                EtherAddr::zero(),
                EtherAddr::zero(),
                c"no IRE for destination",
            );
            return Err(UnderlayIndex::U1);
        }
        // `ire` is refheld by the lookup. The walk takes its own refs.
        let masklen = (*ire).ire_masklen;
        let raw = ire_addr_bytes(ire);
        ident.key = PrefixKey { masklen, addr: mask_prefix(raw, masklen) };
        let orig_type = (*ire).ire_type;
        let orig_multirt = (*ire).ire_flags & ip::RTF_MULTIRT;

        let bucket = (*ire).ire_bucket;
        if bucket.is_null() {
            ident.held[0] = ire;
            ident.n = 1;
            ident.slots[0] = 0;
            ident.bucket_cnt = 1;
            ident.complete = 1;
        } else {
            ip::rw_enter(&mut (*bucket).irb_lock, ip::krw_t_RW_READER);
            let bucket_cnt = (*bucket).irb_ire_cnt as usize;
            ident.bucket_cnt = (*bucket).irb_ire_cnt as u16;
            let mut complete = bucket_cnt > 0 && bucket_cnt <= MAX_BUCKET_WALK;
            let mut cur = (*bucket).irb_ire;
            let mut steps = 0usize;
            let mut seen = 0usize;
            let mut n = 0u8;
            let mut seen_hop = [HopId { gw: [0; 16], ill: 0 }; MAX_HOPS];
            let mut penalized = false;
            let hard = bucket_cnt.saturating_add(MAX_BUCKET_WALK).min(256);
            while !cur.is_null()
                && seen < bucket_cnt
                && seen < MAX_BUCKET_WALK
                && steps < hard
            {
                steps += 1;
                if (*cur).ire_generation == ip::IRE_GENERATION_CONDEMNED {
                    cur = (*cur).ire_next;
                    continue;
                }
                let gw = ire_gw_bytes(cur);
                let ill = (*cur).ire_ill as usize;
                // Full address, as `IN6_ARE_ADDR_EQUAL` in `ire_round_robin`.
                // Another destination in this bucket is `SLOT_OTHER`.
                // The same gateway on another `ire_ill` is a different hop:
                // resolution reads that interface's MAC and underlay port.
                let same = (*cur).ire_type == orig_type
                    && ((*cur).ire_flags & ip::RTF_MULTIRT) == orig_multirt
                    && (*cur).ire_masklen == masklen
                    && ire_addr_bytes(cur) == raw
                    && is_offlink(cur);
                if same && (*cur).ire_badcnt != 0 {
                    penalized = true;
                }
                if same {
                    match assign_hop_slot(
                        &seen_hop[..n as usize],
                        gw,
                        ill,
                        MAX_HOPS,
                    ) {
                        HopSlot::Index(index) => {
                            if index as usize == n as usize {
                                ip::ire_refhold(cur);
                                ident.held[n as usize] = cur;
                                seen_hop[n as usize] = HopId { gw, ill };
                                n += 1;
                            }
                            ident.slots[seen] = index;
                        }
                        HopSlot::Missing => {
                            ident.slots[seen] = SLOT_MISSING;
                            complete = false;
                        }
                    }
                } else if seen < MAX_BUCKET_WALK {
                    ident.slots[seen] = SLOT_OTHER;
                }
                seen += 1;
                cur = (*cur).ire_next;
            }
            // `ire_refhold` ran while `irb_lock` was held. Dropping the lock
            // does not free the IRE: `ire_refrele` is what drops the last
            // reference, and that is also what releases `ire_ill`. `resolve_one`
            // runs before `Ident` drops those refs. It copies `ill_phys_addr`
            // into the route and holds the NCE only for the MAC copy
            // (`nce_lookup_v6` ref, then `nce_refrele`). The stored route keeps
            // the bytes, not the pointers.
            ip::rw_exit(&mut (*bucket).irb_lock);
            if seen != bucket_cnt || (penalized && n > 1) {
                complete = false;
            }
            if n > 0 {
                for held in ident.held.iter().take(n as usize) {
                    if !hop_matches_xde_lookup(*held, dst) {
                        complete = false;
                    }
                }
            }
            ident.complete = u8::from(complete);
            if n > 0 {
                ire_refrele(ire);
                ident.n = n;
            } else {
                ident.held[0] = ire;
                ident.n = 1;
                ident.complete = 0;
            }
        }
        // Bucket order, the order `ire_round_robin` walks. The slots record
        // where each hop sits among the other destinations in the bucket.
        // The interface pointer is part of the generation: the same gateway
        // address on two interfaces is not the same next hop. `generation_op`
        // is not known to change when only the layout or the interface changes.
        let n = ident.n as usize;
        let mut gws = [[0u8; 16]; MAX_HOPS];
        let mut ire_generation = [0u32; MAX_HOPS];
        let mut ire_badcnt = [0u32; MAX_HOPS];
        let mut ills = [0usize; MAX_HOPS];
        for (i, held) in ident.held.iter().take(n).enumerate() {
            gws[i] = ire_gw_bytes(*held);
            ire_generation[i] = (**held).ire_generation;
            ire_badcnt[i] = (**held).ire_badcnt;
            ills[i] = (**held).ire_ill as usize;
        }
        let nslots = (ident.bucket_cnt as usize).min(MAX_BUCKET_WALK);
        ident.generation = snapshot_generation(
            generation_op,
            ident.bucket_cnt as u32,
            &gws[..n],
            &ire_generation[..n],
            &ire_badcnt[..n],
            &ills[..n],
            ident.complete as u32,
            &ident.slots[..nslots],
        );
    }
    if ident.n == 0 { Err(UnderlayIndex::U1) } else { Ok(ident) }
}

fn consult<F>(
    dst: &Ipv6Addr,
    ustate: &XdeDev,
    lookups: Option<&KStatU64>,
    reuse: F,
) -> Result<(StoredSet, bool, Option<u32>, bool), UnderlayIndex>
where
    F: FnOnce(PrefixKey, u32) -> (Option<u32>, Option<StoredSet>),
{
    if let Some(stat) = lookups {
        stat.incr(1);
    }
    let ident = identify(dst)?;
    // The generation the map held before this walk. A later install may
    // store this set only while the map still holds that generation.
    let (observed, cached) = reuse(ident.key, ident.generation);
    if let Some(cached) = cached {
        // The IREs are still held. A MAC that changed without a new IRE
        // generation is read again once the 100 ms window has elapsed.
        // Failure keeps the stored snapshot and tells the caller not to
        // cache this answer. A fresh snapshot is reused without that read.
        if choice_is_fresh(cached.born, Moment::now()) {
            return Ok((cached, true, observed, true));
        }
        return match refresh_macs(&ident, &cached, dst, ustate) {
            Ok(updated) => Ok((updated, true, observed, true)),
            Err(_) => Ok((cached, true, observed, false)),
        };
    }
    let mut hops = [Route::zero_addr(UnderlayIndex::U1); MAX_HOPS];
    let mut gws = [[0u8; 16]; MAX_HOPS];
    let mut ills = [0usize; MAX_HOPS];
    let mut len = 0u8;
    let mut failure = UnderlayIndex::U1;
    for ire in ident.held.iter().take(ident.n as usize).copied() {
        match resolve_one(ire, dst, ustate, ident.ipst) {
            Ok(route) => {
                gws[len as usize] = ire_gw_bytes(ire);
                ills[len as usize] = unsafe { (*ire).ire_ill as usize };
                hops[len as usize] = route;
                len += 1;
            }
            Err(dev) => failure = dev,
        }
    }
    if len == 0 {
        return Err(failure);
    }
    let complete = u8::from(ident.complete != 0 && len == ident.n);
    Ok((
        StoredSet {
            key: ident.key,
            hops,
            gws,
            ills,
            slots: ident.slots,
            bucket_cnt: ident.bucket_cnt,
            complete,
            len,
            generation: ident.generation,
            sample: ident.sample,
            born: Moment::now(),
        },
        false,
        observed,
        true,
    ))
}

/// Re-read each held hop's neighbor entry into `cached`.
///
/// The caller still holds the IREs from `identify`. The gateway sequence is
/// the one that matched `cached.generation`.
fn refresh_macs(
    ident: &Ident,
    cached: &StoredSet,
    dst: &Ipv6Addr,
    ustate: &XdeDev,
) -> Result<StoredSet, UnderlayIndex> {
    if cached.len != ident.n || ident.n == 0 {
        return Err(UnderlayIndex::U1);
    }
    let mut updated = *cached;
    for i in 0..ident.n as usize {
        let ire = ident.held[i];
        updated.hops[i] = resolve_one(ire, dst, ustate, ident.ipst)?;
        updated.ills[i] = unsafe { (*ire).ire_ill as usize };
    }
    updated.born = Moment::now();
    Ok(updated)
}

fn resolve_one(
    ire: *mut ip::ire_t,
    ip6_dst: &Ipv6Addr,
    ustate: &XdeDev,
    ipst: *mut ip::ip_stack_t,
) -> Result<Route, UnderlayIndex> {
    unsafe {
        let mut underlay_idx = UnderlayIndex::U1;
        let ill = (*ire).ire_ill;
        if ill.is_null() {
            opte::engine::dbg!("destination ILL is NULL for {:?}", ip6_dst);
            next_hop_probe(
                ip6_dst,
                None,
                EtherAddr::zero(),
                EtherAddr::zero(),
                c"destination ILL is NULL",
            );
            return Err(underlay_idx);
        }

        let ireu = (*ire).ire_u;
        let gw = ireu.ire6_u.ire6_gateway_addr;
        let gw_ip6 = Ipv6Addr::from(&ireu.ire6_u.ire6_gateway_addr);
        let flags = ip::MATCH_IRE_ILL as i32;
        let mut generation_op = 0u32;
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
                0,
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
                c"no IRE for gateway",
            );
            return Err(underlay_idx);
        }

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
                c"gateway ILL phys addr is NULL",
            );
            return Err(underlay_idx);
        }
        let src: [u8; 6] = alloc::slice::from_raw_parts(src, 6)
            .try_into()
            .expect("src mac from pointer");
        if src == ustate.u2.mac {
            underlay_idx = UnderlayIndex::U2;
        }
        let src = EtherAddr::from(src);

        let nce = DropRef::new(nce_refrele, ip::nce_lookup_v6(ill, &gw));
        if nce.inner().is_null() {
            opte::engine::dbg!("no NCE for gateway {:?}", gw_ip6);
            next_hop_probe(
                ip6_dst,
                Some(&gw_ip6),
                src,
                EtherAddr::zero(),
                c"no NCE for gateway",
            );
            return Err(underlay_idx);
        }
        let nce_common = (*nce.inner()).nce_common;
        if nce_common.is_null() {
            opte::engine::dbg!("no NCE common for gateway {:?}", gw_ip6);
            next_hop_probe(
                ip6_dst,
                Some(&gw_ip6),
                src,
                EtherAddr::zero(),
                c"no NCE common for gateway",
            );
            return Err(underlay_idx);
        }
        let mac = (*nce_common).ncec_lladdr;
        if mac.is_null() {
            opte::engine::dbg!("NCE MAC address is NULL {:?}", gw_ip6);
            next_hop_probe(
                ip6_dst,
                Some(&gw_ip6),
                src,
                EtherAddr::zero(),
                c"NCE MAC address if NULL for gateway",
            );
            return Err(underlay_idx);
        }
        let maclen = (*nce_common).ncec_lladdr_length;
        assert!(maclen == 6);
        let dst: [u8; 6] = alloc::slice::from_raw_parts(mac, 6)
            .try_into()
            .expect("mac from pointer");
        let dst = EtherAddr::from(dst);
        next_hop_probe(ip6_dst, Some(&gw_ip6), src, dst, c"");
        Ok(Route { src, dst, underlay_idx })
    }
}

/// Ask IP which gateway this hash should use, then return the MAC already
/// resolved for that gateway.
///
/// The lookup uses the packet's `xmit_hint`. That is the same call the old
/// cache made, and it is the call that applies DDM's weights. A gateway that
/// is not in the stored set is resolved on its own and is not substituted by
/// another hop.
fn chosen_route(
    set: &StoredSet,
    dst: Ipv6Addr,
    l4_hash: Option<u32>,
    ustate: &XdeDev,
) -> Result<Route, UnderlayIndex> {
    unsafe {
        let netstack = ip::netstack_find_by_zoneid(0);
        assert!(!netstack.is_null());
        let ipst = (*netstack).netstack_u.nu_s.nu_ip;
        assert!(!ipst.is_null());
        let addr = ip::in6_addr_t {
            _S6_un: ip::in6_addr__bindgen_ty_1 { _S6_u8: dst.bytes() },
        };
        let mut generation_op = 0u32;
        let ire = ip::ire_ftable_lookup_v6(
            &addr,
            ptr::null(),
            ptr::null(),
            0,
            ptr::null_mut(),
            sys::ALL_ZONES,
            ptr::null(),
            0,
            l4_hash.unwrap_or(0),
            ipst,
            &mut generation_op as *mut ip::uint_t,
        );
        if ire.is_null() {
            netstack_rele(netstack);
            return Err(UnderlayIndex::U1);
        }
        let gw = ire_gw_bytes(ire);
        let ill = (*ire).ire_ill as usize;
        let known = (0..set.len as usize)
            .find(|&i| set.gws[i] == gw && set.ills[i] == ill);
        let route = if let Some(index) = known {
            ire_refrele(ire);
            Ok(set.hops[index])
        } else {
            let resolved = resolve_one(ire, &dst, ustate, ipst);
            ire_refrele(ire);
            resolved
        };
        netstack_rele(netstack);
        route
    }
}

/// `mod_prop_info_t` from `<inet/tunables.h>`. The layout is the public
/// header, not a CTF offset. `ucur` is `u.mpi_uval.mod_propval_ucur`.
#[repr(C)]
#[derive(Copy, Clone)]
struct ModPropvalUint32 {
    _umin: u32,
    _umax: u32,
    ucur: u32,
}

#[repr(C)]
union ModPropUnion {
    uval: ModPropvalUint32,
    _pad: [u64; 2],
}

#[repr(C)]
struct ModPropInfo {
    _name: *const c_char,
    _proto: u32,
    _align: u32,
    _setf: *const c_void,
    _getf: *const c_void,
    val: ModPropUnion,
    _def: u32,
    _align_end: u32,
}

const _: () = assert!(core::mem::size_of::<ModPropInfo>() == 0x38);
const _: () = assert!(core::mem::offset_of!(ModPropInfo, val) + 8 == 0x28);

/// `MOD_PROTO_IP` in `<inet/tunables.h>`.
const MOD_PROTO_IP: u32 = 0x01 | 0x02;

unsafe extern "C" {
    fn mod_prop_lookup(
        table: *mut ModPropInfo,
        name: *const c_char,
        proto: u32,
    ) -> *mut ModPropInfo;
}

/// Zone-0 netstack hold that keeps `ips_propinfo_tbl` alive, and the
/// `ucur` word inside the `_ecmp_behavior` entry. `ndd` updates that word
/// in place. The hold is dropped from `_fini`.
///
/// `ECMP_UCUR` is stored only after `ECMP_NS`, and only then does the state
/// become [`ECMP_READY`]. `release_ecmp_hold` drops a hold only from that
/// state, so it cannot observe the pointer without the hold and cannot miss
/// a hold that is stored while it is waiting. This is the order checked by
/// `ecmp_store_hold` and `ecmp_publish_pointer`.
static ECMP_NS: AtomicPtr<ip::netstack_t> = AtomicPtr::new(ptr::null_mut());
static ECMP_UCUR: AtomicPtr<u32> = AtomicPtr::new(ptr::null_mut());
const ECMP_EMPTY: u8 = 0;
const ECMP_BUSY: u8 = 1;
const ECMP_READY: u8 = 2;
static ECMP_STATE: AtomicU8 = AtomicU8::new(ECMP_EMPTY);

/// Drop the zone-0 hold taken for the ECMP property.
///
/// `_fini` calls this after `mod_remove` has returned 0, so no packet is
/// inside `ecmp_behavior`. The state machine still covers a publisher that
/// has not finished: the releaser waits out `ECMP_BUSY` and then hides the
/// pointer before releasing the hold.
pub fn release_ecmp_hold() {
    loop {
        match ECMP_STATE.compare_exchange(
            ECMP_READY,
            ECMP_BUSY,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => break,
            Err(ECMP_EMPTY) => return,
            Err(ECMP_BUSY) => {
                while ECMP_STATE.load(Ordering::Acquire) == ECMP_BUSY {
                    core::hint::spin_loop();
                }
            }
            Err(_) => return,
        }
    }
    ECMP_UCUR.store(ptr::null_mut(), Ordering::Release);
    let netstack = ECMP_NS.swap(ptr::null_mut(), Ordering::AcqRel);
    ECMP_STATE.store(ECMP_EMPTY, Ordering::Release);
    if !netstack.is_null() {
        netstack_rele(netstack);
    }
}

/// Read illumos `ip_ecmp_behavior` from the global-zone IP stack.
/// `None` means the table did not have it, and a multipath snapshot must
/// not be chosen locally.
fn ecmp_behavior() -> Option<u32> {
    let cached = ECMP_UCUR.load(Ordering::Acquire);
    if !cached.is_null() {
        return Some(unsafe { *cached });
    }
    if ECMP_STATE
        .compare_exchange(
            ECMP_EMPTY,
            ECMP_BUSY,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        // Another CPU is publishing, or `_fini` is tearing the hold down.
        // The pointer is visible only after the hold is stored.
        let cached = ECMP_UCUR.load(Ordering::Acquire);
        if cached.is_null() {
            return None;
        }
        return Some(unsafe { *cached });
    }
    match publish_ecmp() {
        Some(value) => Some(value),
        None => {
            ECMP_STATE.store(ECMP_EMPTY, Ordering::Release);
            None
        }
    }
}

/// Look up `_ecmp_behavior` and publish it. The caller owns `ECMP_BUSY`.
///
/// On success the hold is stored, then the pointer, then `ECMP_READY`.
/// On failure nothing is stored and the caller returns the state to empty.
fn publish_ecmp() -> Option<u32> {
    unsafe {
        let netstack = ip::netstack_find_by_zoneid(0);
        if netstack.is_null() {
            return None;
        }
        let ipst = (*netstack).netstack_u.nu_s.nu_ip;
        if ipst.is_null() {
            netstack_rele(netstack);
            return None;
        }
        let table = (*ipst).ips_propinfo_tbl as *mut ModPropInfo;
        if table.is_null() {
            netstack_rele(netstack);
            return None;
        }
        let info =
            mod_prop_lookup(table, c"_ecmp_behavior".as_ptr(), MOD_PROTO_IP);
        if info.is_null() {
            netstack_rele(netstack);
            return None;
        }
        let ucur = ptr::addr_of_mut!((*info).val.uval.ucur);
        ECMP_NS.store(netstack, Ordering::Release);
        ECMP_UCUR.store(ucur, Ordering::Release);
        ECMP_STATE.store(ECMP_READY, Ordering::Release);
        Some(*ucur)
    }
}

/// Round-robin only when the bucket has one route, or the stack is in the
/// mode illumos uses for this lookup: 2 always, 1 only for a default route.
fn ecmp_allows_local(masklen: u32, bucket_cnt: u16) -> bool {
    if bucket_cnt <= 1 {
        return true;
    }
    match ecmp_behavior() {
        Some(2) => true,
        Some(1) if masklen == 0 => true,
        _ => false,
    }
}

/// Same arguments the IPv6 lookup passes into `ire_round_robin`: the
/// destination, the IRE's own mask, a zero gateway, zone `ALL_ZONES`, and
/// no ill, type, label, or flags. The zone gateway check is skipped for
/// `ALL_ZONES` inside illumos, so it is not repeated here.
fn hop_matches_xde_lookup(ire: *mut ip::ire_t, dst: &Ipv6Addr) -> bool {
    unsafe {
        let addr = ip::in6_addr_t {
            _S6_un: ip::in6_addr__bindgen_ty_1 { _S6_u8: dst.bytes() },
        };
        let gw = ip::in6_addr_t {
            _S6_un: ip::in6_addr__bindgen_ty_1 { _S6_u8: [0; 16] },
        };
        let mask = (*ire).ire_u.ire6_u.ire6_mask;
        ip::ire_match_args_v6(
            ire,
            &addr,
            &mask,
            &gw,
            0,
            ptr::null(),
            sys::ALL_ZONES,
            ptr::null(),
            0,
        ) != 0
    }
}

/// Illumos `ire_round_robin` on the snapshot: mix the hint, modulo
/// `irb_ire_cnt`, then the next stored hop at or after that position.
/// The gateway is the address illumos would have to match, not the MAC.
fn local_select(
    set: &StoredSet,
    l4_hash: Option<u32>,
) -> Option<(Route, [u8; 16])> {
    if set.complete == 0 || set.len == 0 || set.bucket_cnt == 0 {
        return None;
    }
    if !ecmp_allows_local(set.key.masklen, set.bucket_cnt) {
        return None;
    }
    let cnt = set.bucket_cnt as usize;
    if cnt > MAX_BUCKET_WALK {
        return None;
    }
    let hop = round_robin_hop(
        &set.slots[..cnt],
        l4_hash.unwrap_or(0),
        SLOT_OTHER,
        SLOT_MISSING,
    )?;
    if hop < set.len as usize {
        return Some((set.hops[hop], set.gws[hop]));
    }
    None
}

fn same_hops(left: &StoredSet, right: &StoredSet) -> bool {
    if left.len != right.len
        || left.complete != right.complete
        || left.bucket_cnt != right.bucket_cnt
    {
        return false;
    }
    let hops = left.len as usize;
    for i in 0..hops {
        if left.hops[i].src != right.hops[i].src
            || left.hops[i].dst != right.hops[i].dst
            || left.hops[i].underlay_idx != right.hops[i].underlay_idx
            || left.ills[i] != right.ills[i]
        {
            return false;
        }
    }
    let cnt = (left.bucket_cnt as usize).min(MAX_BUCKET_WALK);
    left.slots[..cnt] == right.slots[..cnt]
}

fn ire_addr_bytes(ire: *mut ip::ire_t) -> [u8; 16] {
    unsafe {
        let ireu = (*ire).ire_u;
        ireu.ire6_u.ire6_addr._S6_un._S6_u8
    }
}

fn ire_gw_bytes(ire: *mut ip::ire_t) -> [u8; 16] {
    unsafe {
        let ireu = (*ire).ire_u;
        ireu.ire6_u.ire6_gateway_addr._S6_un._S6_u8
    }
}

fn is_offlink(ire: *mut ip::ire_t) -> bool {
    let kind = unsafe { (*ire).ire_type } as u32;
    kind & ip::IRE_OFFLINK != 0
}

fn mask_prefix(mut addr: [u8; 16], masklen: u32) -> [u8; 16] {
    let bits = (masklen as usize).min(128);
    for (i, byte) in addr.iter_mut().enumerate() {
        let start = i * 8;
        if start >= bits {
            *byte = 0;
        } else if start + 8 > bits {
            let keep = bits - start;
            *byte &= 0xffu8 << (8 - keep);
        }
    }
    addr
}

fn choice_is_fresh(born: Moment, now: Moment) -> bool {
    u128::from(now.delta_as_millis(born)) <= CHOICE_LIFETIME.as_millis()
}

/// Shared prefix hop-set cache.
///
/// A fresh snapshot chooses the hop locally and does not call illumos. The
/// first packet of an address, and any packet whose own prefix confirmation
/// or hop snapshot is older than 100 ms, calls `identify`. Another
/// destination keeping the snapshot fresh does not extend this confirmation.
/// The one-second periodic still re-reads every stored prefix through its
/// sample address. The generation checks in `note_checked`,
/// `install_if_current` and `remove_routes` reject a stale overwrite.
pub struct RouteCache {
    sets: Arc<KRwLock<BTreeMap<PrefixKey, StoredSet>>>,
    /// Exact underlay destination to the prefix that covered it, plus when
    /// that coverage was confirmed. There is no longest-prefix match. An
    /// address missing from this map, or confirmed more than 100 ms ago,
    /// calls `identify`. A more-specific route is therefore visible on the
    /// next packet after that confirmation expires, even when another
    /// destination has kept the shorter prefix's snapshot fresh.
    /// `admit_exact_dest` bounds the map.
    dests: Arc<KRwLock<BTreeMap<[u8; 16], DestEntry>>>,
    stats: KStatNamed<RouteCacheStats>,
}

enum Stored {
    /// Snapshot is fresh and the local account is allowed.
    Hit(Route),
    /// Snapshot is fresh, and this hash must ask illumos.
    Ask(StoredSet),
    /// No snapshot, or this destination's confirmation or the snapshot is
    /// older than 100 ms.
    Miss,
}

impl RouteCache {
    pub fn new(port_name: &str) -> Result<Self, PortCreateError> {
        let stats = RouteCacheStats::new();
        stats
            .capacity
            .set(u64::try_from(MAX_PREFIX_SETS).expect("usize is u64"));
        let name = format!("{port_name}_route_cache");
        Ok(Self {
            sets: KRwLock::new(BTreeMap::new()).into(),
            dests: KRwLock::new(BTreeMap::new()).into(),
            stats: KStatNamed::new("xde", &name, stats)?,
        })
    }

    /// Pick a hop from the stored bucket snapshot, or resolve one.
    pub fn next_hop(&self, key: RouteKey, xde: &XdeDev) -> Route {
        let dst = key.dst.bytes();
        self.stats.vals.miss.incr(1);
        match self.stored_choice(&dst, key.l4_hash) {
            Stored::Hit(route) => {
                self.stats.vals.prefix_hit.incr(1);
                return route;
            }
            Stored::Ask(set) => {
                self.stats.vals.local_skip.incr(1);
                return match chosen_route(&set, key.dst, key.l4_hash, xde) {
                    Ok(route) => route,
                    Err(dev) => {
                        self.stats.vals.error.incr(1);
                        Route::zero_addr(dev)
                    }
                };
            }
            Stored::Miss => {}
        }

        let (found, reused, observed, cache) = match consult(
            &key.dst,
            xde,
            Some(&self.stats.vals.ip_lookup),
            |prefix, generation| {
                let sets = self.sets.read();
                match sets.get(&prefix).copied() {
                    Some(set) if set.generation == generation => {
                        (Some(generation), Some(set))
                    }
                    Some(set) => (Some(set.generation), None),
                    None => (None, None),
                }
            },
        ) {
            Ok(found) => found,
            Err(dev) => {
                self.stats.vals.error.incr(1);
                return Route::zero_addr(dev);
            }
        };

        if reused {
            if cache {
                self.note_checked(&found);
            }
        } else {
            self.stats.vals.set_walk.incr(1);
            self.install_if_current(&key, found, observed);
        }
        if found.complete != 0 {
            self.remember_dest(dst, found.key);
        }
        if let Some((route, _)) = local_select(&found, key.l4_hash) {
            self.stats.vals.prefix_hit.incr(1);
            route
        } else {
            self.stats.vals.local_skip.incr(1);
            match chosen_route(&found, key.dst, key.l4_hash, xde) {
                Ok(route) => route,
                Err(dev) => {
                    self.stats.vals.error.incr(1);
                    Route::zero_addr(dev)
                }
            }
        }
    }

    /// A fresh snapshot answered locally, must ask IP, or is missing or older
    /// than 100 ms. The destination's own confirmation has to be fresh too:
    /// a sibling that renewed the snapshot does not keep this address on it.
    fn stored_choice(&self, dst: &[u8; 16], l4_hash: Option<u32>) -> Stored {
        let Some(entry) = self.dests.read().get(dst).copied() else {
            return Stored::Miss;
        };
        let Some(set) = self.sets.read().get(&entry.prefix).copied() else {
            return Stored::Miss;
        };
        let now = Moment::now().raw();
        if !dest_reuses_stored_prefix(entry.verified.raw(), set.born.raw(), now)
        {
            return Stored::Miss;
        }
        match local_select(&set, l4_hash) {
            Some((route, _)) => Stored::Hit(route),
            None => Stored::Ask(set),
        }
    }

    /// Write a refreshed copy back only while the stored generation is the
    /// one that was reused. `born` moves forward only when this copy was
    /// re-resolved after the 100 ms window; a reuse inside that window does
    /// not extend it. A newer snapshot is left in place.
    fn note_checked(&self, found: &StoredSet) {
        let mut map = self.sets.write();
        let Some(set) = map.get_mut(&found.key) else {
            return;
        };
        if !may_touch_born(set.generation, found.generation) {
            return;
        }
        set.hops = found.hops;
        set.ills = found.ills;
        if found.born.raw() > set.born.raw() {
            set.born = found.born;
        }
    }

    fn remember_dest(&self, dst: [u8; 16], key: PrefixKey) {
        let mut dests = self.dests.write();
        if !admit_exact_dest(dests.len(), dests.contains_key(&dst)) {
            return;
        }
        dests.insert(dst, DestEntry { prefix: key, verified: Moment::now() });
    }

    fn forget_dests(&self, key: PrefixKey) {
        self.dests.write().retain(|_, stored| stored.prefix != key);
    }

    /// Store `found` only when the map still holds the generation observed
    /// before the walk. A newer installation is left in place.
    fn install_if_current(
        &self,
        probe: &RouteKey,
        found: StoredSet,
        observed: Option<u32>,
    ) {
        let ptr = self.probe_ptr();
        let mut map = self.sets.write();
        let current = map.get(&found.key).map(|set| set.generation);
        if !may_install(observed, current) {
            return;
        }
        let room = map.len() < MAX_PREFIX_SETS;
        match map.entry(found.key) {
            Entry::Occupied(mut slot) => {
                if slot.get().generation != found.generation {
                    self.stats.vals.refresh.incr(1);
                    route_refresh_probe(ptr, probe);
                }
                slot.insert(found);
            }
            Entry::Vacant(slot) if room => {
                slot.insert(found);
                self.stats.vals.occupancy.incr(1);
                route_insert_probe(ptr, probe);
            }
            Entry::Vacant(_) => {
                self.stats.vals.table_full.incr(1);
                route_full_probe(ptr, probe);
            }
        }
    }

    /// Drop or refresh every stored prefix. Runs from the one-second periodic.
    pub fn remove_routes(&self, xde: &XdeDev) {
        let snapshot: Vec<(PrefixKey, StoredSet)> = {
            let sets = self.sets.read();
            sets.iter().map(|(key, set)| (*key, *set)).collect()
        };
        let ptr = self.probe_ptr();
        for (key, old) in snapshot {
            let sample = Ipv6Addr::from(old.sample);
            let probe_key = RouteKey { dst: sample, l4_hash: None };
            match consult(
                &sample,
                xde,
                Some(&self.stats.vals.ip_lookup),
                |_, _| (None, None),
            ) {
                Ok((found, _, _, _))
                    if found.key == key
                        && found.generation == old.generation
                        && same_hops(&found, &old) => {}
                Ok((found, _, _, _)) => {
                    let mut sets = self.sets.write();
                    let current = sets.get(&key).map(|set| set.generation);
                    if !may_overwrite(current, old.generation) {
                        continue;
                    }
                    if found.key != key {
                        let installed =
                            sets.get(&found.key).map(|set| set.generation);
                        if !may_install(None, installed) {
                            sets.remove(&key);
                            drop(sets);
                            self.forget_dests(key);
                            route_delete_probe(ptr, &probe_key);
                            continue;
                        }
                    }
                    sets.remove(&key);
                    sets.insert(found.key, found);
                    drop(sets);
                    if found.key != key {
                        self.forget_dests(key);
                    }
                    route_refresh_probe(ptr, &probe_key);
                    self.stats.vals.refresh.incr(1);
                }
                Err(_) => {
                    let mut sets = self.sets.write();
                    let current = sets.get(&key).map(|set| set.generation);
                    if !may_overwrite(current, old.generation) {
                        continue;
                    }
                    let removed = sets.remove(&key).is_some();
                    drop(sets);
                    if removed {
                        self.forget_dests(key);
                        route_delete_probe(ptr, &probe_key);
                    }
                }
            }
        }
        let len = self.sets.read().len();
        self.stats
            .vals
            .occupancy
            .set(u64::try_from(len).expect("u64 is usize"));
    }

    fn probe_ptr(&self) -> uintptr_t {
        self as *const Self as uintptr_t
    }
}

/// An underlay routing destination and the entropy IP uses to choose a hop.
///
/// The hash is passed to `ire_ftable_lookup_v6` as `xmit_hint` and to the
/// local round-robin account, so two flows that share a prefix do not share
/// a chosen gateway. `None` passes hint 0, which is what hairpin and multicast
/// already did.
#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RouteKey {
    pub dst: Ipv6Addr,
    pub l4_hash: Option<u32>,
}

/// Output port and L2 information needed to emit a packet over the underlay.
#[derive(Copy, Clone, Debug)]
pub struct Route {
    pub src: EtherAddr,
    pub dst: EtherAddr,
    pub underlay_idx: UnderlayIndex,
}

impl Route {
    fn zero_addr(underlay_idx: UnderlayIndex) -> Route {
        Self { src: EtherAddr::zero(), dst: EtherAddr::zero(), underlay_idx }
    }
}

#[derive(KStatProvider)]
struct RouteCacheStats {
    /// Maximum number of prefix sets.
    capacity: KStatU64,
    /// Prefix sets currently stored.
    occupancy: KStatU64,
    /// Unused. There is no per-CPU TLB. The name stays so older readers still
    /// find the counter, and it remains zero.
    hit: KStatU64,
    /// Every `next_hop` call, including one answered from the snapshot.
    /// Those also increment `prefix_hit`. `hit` stays zero: there is no
    /// per-CPU TLB.
    miss: KStatU64,
    /// Stored sets replaced because the IRE generation changed.
    refresh: KStatU64,
    /// Misses that could not be stored because the prefix map was full.
    table_full: KStatU64,
    /// Lookups that failed to resolve a hop.
    error: KStatU64,
    /// Bucket walks that resolved a hop set from IP.
    set_walk: KStatU64,
    /// Packets answered by the local account of a stored bucket.
    prefix_hit: KStatU64,
    /// Calls into `ire_ftable_lookup_v6` to discover or refresh a prefix.
    /// A remembered destination of a fresh prefix does not increment this.
    ip_lookup: KStatU64,
    /// Fresh snapshot refused local selection, so the packet asked IP.
    local_skip: KStatU64,
}
