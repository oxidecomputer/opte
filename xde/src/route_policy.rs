// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! Decisions the route cache can check without the illumos forwarding table.
//!
//! The hop account itself stays in `route.rs`. These functions only answer
//! whether two hops are the same next hop, whether a snapshot read before a
//! refresh may be published, and whether one destination may still reuse the
//! prefix it was last confirmed to belong to.

/// Confirmed underlay destinations remembered per port.
///
/// The previous flow cache stopped at 8,192 `(destination, hash)` entries.
/// That cap, applied to exact destinations of one prefix, made every later
/// destination call `ire_ftable_lookup_v6` on every packet. 65,536 is the
/// bound on destinations whose prefix IP has already selected. Past it, a
/// new destination is resolved but not remembered.
pub const MAX_EXACT_DESTS: usize = 65_536;

/// Former per-flow cap. The regression test shows what that bound rejected.
#[cfg(test)]
pub const OLD_FLOW_CAP: usize = 8_192;

/// How long a stored choice may be reused, in milliseconds.
const CHOICE_LIFETIME_MS: u64 = 100;

const NS_PER_MS: u64 = 1_000_000;

/// A confirmation stamped at `verified_ns` still covers `now_ns`.
///
/// Exactly 100 ms is still live. One millisecond later is not.
fn association_is_fresh(verified_ns: u64, now_ns: u64) -> bool {
    now_ns.saturating_sub(verified_ns) / NS_PER_MS <= CHOICE_LIFETIME_MS
}

/// Whether this destination may be answered from the stored prefix.
///
/// `verified_ns` is when this destination itself was confirmed to belong to
/// that prefix. `set_born_ns` is when the shared hop snapshot was last
/// confirmed. Traffic to another destination can move `set_born_ns` without
/// moving `verified_ns`. Both have to be inside the lifetime; otherwise the
/// packet calls `identify` and can observe a more-specific route.
pub fn dest_reuses_stored_prefix(
    verified_ns: u64,
    set_born_ns: u64,
    now_ns: u64,
) -> bool {
    association_is_fresh(verified_ns, now_ns)
        && association_is_fresh(set_born_ns, now_ns)
}

/// Gateway plus the interface that resolves it.
///
/// `resolve_one` reads `ire_ill` for the source MAC and the underlay port.
/// The same gateway address on two interfaces is two next hops.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct HopId {
    pub gw: [u8; 16],
    pub ill: usize,
}

/// Index of an already stored hop with this gateway and interface.
pub fn find_same_hop(
    hops: &[HopId],
    gw: [u8; 16],
    ill: usize,
) -> Option<usize> {
    hops.iter().position(|hop| hop.gw == gw && hop.ill == ill)
}

/// Where a matching bucket entry goes in the stored hop list.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum HopSlot {
    /// Index of a hop already stored, or of the new hop about to be stored.
    Index(u8),
    /// A new hop that does not fit. The packet must ask IP.
    Missing,
}

/// A duplicate keeps the index it already has, including after `max_hops`
/// distinct hops are stored. Only a new hop past that limit is missing.
pub fn assign_hop_slot(
    seen: &[HopId],
    gw: [u8; 16],
    ill: usize,
    max_hops: usize,
) -> HopSlot {
    if let Some(index) = find_same_hop(seen, gw, ill) {
        return HopSlot::Index(index as u8);
    }
    if seen.len() < max_hops {
        HopSlot::Index(seen.len() as u8)
    } else {
        HopSlot::Missing
    }
}

#[cfg(test)]
pub fn choice_expired(born_ns: u64, now_ns: u64) -> bool {
    !association_is_fresh(born_ns, now_ns)
}

/// `note_checked` may move `born` only for the generation it just confirmed.
pub fn may_touch_born(
    stored_generation: u32,
    confirmed_generation: u32,
) -> bool {
    stored_generation == confirmed_generation
}

/// Periodic refresh may replace an entry only when it is still the generation
/// that refresh read. `None` means a concurrent path already removed it.
pub fn may_overwrite(current: Option<u32>, snapshot_generation: u32) -> bool {
    current == Some(snapshot_generation)
}

/// A packet may store the set it just resolved only when the map still holds
/// the generation it observed before the walk. `None` means the prefix was
/// absent. A generation installed in between is left in place.
pub fn may_install(observed: Option<u32>, current: Option<u32>) -> bool {
    observed == current
}

/// Whether this destination is recorded so a later packet can skip IP.
///
/// This is not a longest-prefix match. An address that is not remembered
/// calls `identify`, so a more-specific route that has not been cached yet
/// cannot hide behind a shorter prefix already in the map.
pub fn admit_exact_dest(len: usize, already_present: bool) -> bool {
    already_present || len < MAX_EXACT_DESTS
}

/// Generation of one bucket snapshot.
///
/// `slots` is the position of each hop in the whole bucket, including
/// positions that belong to other destinations. `local_select` walks those
/// positions. `ills` is `ire_ill` for each stored hop: the same gateway
/// address on two interfaces is two next hops, so the interface is part of
/// the generation. Two snapshots with the same gateways and a different
/// layout, or the same gateways on reversed interfaces, are different
/// generations. The reuse path cannot keep the old choice.
pub fn snapshot_generation(
    generation_op: u32,
    bucket_cnt: u32,
    gateways: &[[u8; 16]],
    ire_generation: &[u32],
    ire_badcnt: &[u32],
    ills: &[usize],
    complete: u32,
    slots: &[u8],
) -> u32 {
    let mut generation = generation_op;
    generation = fold_gen(generation, bucket_cnt);
    let n = gateways
        .len()
        .min(ire_generation.len())
        .min(ire_badcnt.len())
        .min(ills.len());
    for i in 0..n {
        for byte in gateways[i] {
            generation = fold_gen(generation, u32::from(byte));
        }
        generation = fold_gen(generation, ire_generation[i]);
        generation = fold_gen(generation, ire_badcnt[i]);
        generation = fold_usize(generation, ills[i]);
    }
    generation = fold_gen(generation, complete);
    for slot in slots {
        generation = fold_gen(generation, u32::from(*slot));
    }
    generation
}

fn fold_usize(generation: u32, value: usize) -> u32 {
    let generation = fold_gen(generation, value as u32);
    // Two 16-bit shifts keep the high half on 64-bit and stay in range on
    // 32-bit, where that half is zero.
    fold_gen(generation, (value >> 16 >> 16) as u32)
}

fn fold_gen(generation: u32, piece: u32) -> u32 {
    generation.wrapping_mul(0x0100_0193).wrapping_add(piece)
}

/// Hop index `ire_round_robin` would pick from a bucket layout.
///
/// `other` is a position that belongs to a different destination. `missing`
/// means the layout is not usable and the packet must ask IP.
pub fn round_robin_hop(
    slots: &[u8],
    hint: u32,
    other: u8,
    missing: u8,
) -> Option<usize> {
    if slots.is_empty() {
        return None;
    }
    let mixed = hint ^ (hint >> 8) ^ (hint >> 16);
    let mut index = mixed as usize % slots.len();
    for _ in 0..slots.len() {
        let slot = slots[index];
        if slot == missing {
            return None;
        }
        if slot != other {
            return Some(usize::from(slot));
        }
        index += 1;
        if index == slots.len() {
            index = 0;
        }
    }
    None
}

/// Publication of the ECMP property pointer.
///
/// `hold` is stored first. `pointer` becomes visible only after that. A
/// releaser that sees `pointer` therefore still has a hold to drop. A
/// releaser that runs while `hold` is true and `pointer` is still false must
/// wait; the hold is already stored and must not be missed. `publish_ecmp`
/// stores `ECMP_NS` before `ECMP_UCUR`, and `release_ecmp_hold` takes the
/// hold only after that publication is visible.
#[cfg(test)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct EcmpPub {
    pub hold: bool,
    pub pointer: bool,
}

#[cfg(test)]
pub fn ecmp_begin() -> EcmpPub {
    EcmpPub { hold: false, pointer: false }
}

#[cfg(test)]
pub fn ecmp_store_hold(mut slot: EcmpPub) -> EcmpPub {
    slot.hold = true;
    slot
}

#[cfg(test)]
pub fn ecmp_publish_pointer(mut slot: EcmpPub) -> Option<EcmpPub> {
    if !slot.hold {
        return None;
    }
    slot.pointer = true;
    Some(slot)
}

/// IP lookups to serve `n_dests` destinations of one prefix for `rounds`
/// passes, remembering at most `cap` destinations.
#[cfg(test)]
fn ip_lookups_for_shared_prefix(
    n_dests: usize,
    rounds: usize,
    cap: usize,
) -> usize {
    let mut known = 0usize;
    let mut lookups = 0usize;
    for _ in 0..rounds {
        for i in 0..n_dests {
            if i < known {
                continue;
            }
            lookups += 1;
            if known < cap {
                known += 1;
            }
        }
    }
    lookups
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_gateway_on_two_interfaces_is_two_hops() {
        let gw = [0x20u8; 16];
        let stored = [HopId { gw, ill: 0x1000 }];
        assert_eq!(find_same_hop(&stored, gw, 0x1000), Some(0));
        assert_eq!(find_same_hop(&stored, gw, 0x2000), None);
        assert_eq!(find_same_hop(&stored, [0x21u8; 16], 0x1000), None);
    }

    #[test]
    fn a_line_at_exactly_100ms_is_still_live() {
        let born = 0;
        let now = 100 * NS_PER_MS;
        assert!(!choice_expired(born, now));
        assert!(choice_expired(born, now + NS_PER_MS));
    }

    #[test]
    fn note_checked_rejects_a_different_generation() {
        assert!(may_touch_born(7, 7));
        assert!(!may_touch_born(7, 8));
    }

    #[test]
    fn periodic_refresh_does_not_overwrite_a_newer_generation() {
        assert!(may_overwrite(Some(3), 3));
        assert!(!may_overwrite(Some(9), 3));
        assert!(!may_overwrite(None, 3));
    }

    #[test]
    fn install_does_not_replace_a_generation_it_did_not_observe() {
        assert!(may_install(None, None));
        assert!(may_install(Some(3), Some(3)));
        assert!(!may_install(Some(3), Some(9)));
        assert!(!may_install(None, Some(9)));
    }

    #[test]
    fn a_bucket_reorder_changes_generation_and_the_selected_hop() {
        let gw_a = [1u8; 16];
        let gw_b = [2u8; 16];
        let gateways = [gw_a, gw_b];
        let ire_generation = [10u32, 11];
        let ire_badcnt = [0u32, 0];
        // Hint 0 starts at slot 0. `0xff` is another destination's position.
        let layout_a = [0u8, 0xff, 1];
        let layout_b = [0xff, 1, 0];
        let ills = [10usize, 11];
        let gen_a = snapshot_generation(
            7,
            3,
            &gateways,
            &ire_generation,
            &ire_badcnt,
            &ills,
            1,
            &layout_a,
        );
        let gen_b = snapshot_generation(
            7,
            3,
            &gateways,
            &ire_generation,
            &ire_badcnt,
            &ills,
            1,
            &layout_b,
        );
        assert_ne!(gen_a, gen_b);
        assert_eq!(round_robin_hop(&layout_a, 0, 0xff, 0xfe), Some(0));
        assert_eq!(round_robin_hop(&layout_b, 0, 0xff, 0xfe), Some(1));
    }

    #[test]
    fn reversed_interfaces_do_not_share_a_generation() {
        let gw = [9u8; 16];
        let gateways = [gw, gw];
        let ire_generation = [4u32, 4];
        let ire_badcnt = [0u32, 0];
        let slots = [0u8, 1];
        let forward = [1usize, 2];
        let reversed = [2usize, 1];
        let gen_forward = snapshot_generation(
            7,
            2,
            &gateways,
            &ire_generation,
            &ire_badcnt,
            &forward,
            1,
            &slots,
        );
        let gen_reversed = snapshot_generation(
            7,
            2,
            &gateways,
            &ire_generation,
            &ire_badcnt,
            &reversed,
            1,
            &slots,
        );
        assert_ne!(gen_forward, gen_reversed);
        // The walk index is the same. The hop stored at that index is not.
        assert_eq!(round_robin_hop(&slots, 0, 0xff, 0xfe), Some(0));
        let high = [0x1_0000_0001usize, 2];
        let low = [1usize, 2];
        assert_ne!(
            snapshot_generation(
                7,
                2,
                &gateways,
                &ire_generation,
                &ire_badcnt,
                &high,
                1,
                &slots
            ),
            snapshot_generation(
                7,
                2,
                &gateways,
                &ire_generation,
                &ire_badcnt,
                &low,
                1,
                &slots
            ),
        );
    }

    #[test]
    fn a_duplicate_past_eight_hops_reuses_its_index() {
        let mut seen = [HopId { gw: [0; 16], ill: 0 }; 8];
        let mut n = 0usize;
        for i in 0..8 {
            let gw = [i as u8; 16];
            match assign_hop_slot(&seen[..n], gw, 1, 8) {
                HopSlot::Index(index) => {
                    assert_eq!(index, i as u8);
                    seen[n] = HopId { gw, ill: 1 };
                    n += 1;
                }
                HopSlot::Missing => {
                    panic!("a distinct hop within the limit is stored")
                }
            }
        }
        assert_eq!(
            assign_hop_slot(&seen[..n], [0u8; 16], 1, 8),
            HopSlot::Index(0)
        );
        assert_eq!(
            assign_hop_slot(&seen[..n], [3u8; 16], 1, 8),
            HopSlot::Index(3)
        );
        assert_eq!(
            assign_hop_slot(&seen[..n], [9u8; 16], 1, 8),
            HopSlot::Missing
        );
        // The same gateway address on the other interface is still a new hop.
        assert_eq!(
            assign_hop_slot(&seen[..n], [0u8; 16], 2, 8),
            HopSlot::Missing
        );
    }

    #[test]
    fn the_ecmp_pointer_is_not_visible_before_the_hold() {
        let slot = ecmp_begin();
        assert!(ecmp_publish_pointer(slot).is_none());
        let held = ecmp_store_hold(slot);
        assert!(!held.pointer);
        assert!(held.hold);
        let published = ecmp_publish_pointer(held).expect("hold is stored");
        assert!(published.hold);
        assert!(published.pointer);
    }

    #[test]
    fn more_than_8192_destinations_of_one_prefix_are_remembered() {
        let n = OLD_FLOW_CAP + 108;
        let with_old_cap = ip_lookups_for_shared_prefix(n, 2, OLD_FLOW_CAP);
        let with_prefix_cap =
            ip_lookups_for_shared_prefix(n, 2, MAX_EXACT_DESTS);
        assert!(with_old_cap > n);
        assert_eq!(with_prefix_cap, n);
        assert!(admit_exact_dest(OLD_FLOW_CAP, false));
        assert!(!admit_exact_dest(MAX_EXACT_DESTS, false));
        assert!(admit_exact_dest(MAX_EXACT_DESTS, true));
    }

    #[derive(Copy, Clone, Eq, PartialEq, Debug)]
    enum Cover {
        P,
        Q,
    }

    /// D1 and D2 start on P. After `q_since`, identify(D1) returns Q.
    struct Pair {
        p_born: u64,
        d1_prefix: Cover,
        d1_verified: u64,
        d2_prefix: Cover,
        d2_verified: u64,
        q_since: u64,
    }

    impl Pair {
        fn identified(&self, d1: bool, now: u64) -> Cover {
            if d1 && now >= self.q_since { Cover::Q } else { Cover::P }
        }

        /// One packet. A hit does not move either clock. A miss identifies
        /// this destination only. Refreshing P moves `p_born` only when the
        /// snapshot had already expired, which is what `note_checked` does.
        fn packet(&mut self, d1: bool, now: u64) -> Cover {
            let (prefix, verified) = if d1 {
                (self.d1_prefix, self.d1_verified)
            } else {
                (self.d2_prefix, self.d2_verified)
            };
            if prefix == Cover::P
                && dest_reuses_stored_prefix(verified, self.p_born, now)
            {
                return Cover::P;
            }
            let found = self.identified(d1, now);
            if found == Cover::P && !association_is_fresh(self.p_born, now) {
                self.p_born = now;
            }
            if d1 {
                self.d1_prefix = found;
                self.d1_verified = now;
            } else {
                self.d2_prefix = found;
                self.d2_verified = now;
            }
            found
        }
    }

    #[test]
    fn a_sibling_refresh_does_not_hide_a_more_specific_route() {
        let ms = |n: u64| n * NS_PER_MS;
        let mut pair = Pair {
            p_born: 0,
            d1_prefix: Cover::P,
            d1_verified: 0,
            d2_prefix: Cover::P,
            d2_verified: 0,
            q_since: ms(50),
        };

        // Q is already installed. D1 was confirmed at t = 0, so the
        // association is still inside the lifetime, including at 100 ms.
        assert_eq!(pair.packet(true, ms(50)), Cover::P);
        assert_eq!(pair.d1_verified, 0);
        assert_eq!(pair.packet(true, ms(100)), Cover::P);
        assert_eq!(pair.d1_verified, 0);
        assert_eq!(pair.p_born, 0);

        // D2 after the snapshot expired. identify still returns P, and that
        // refresh moves the shared born. D1's confirmation stays at 0.
        // The periodic pass reads one sample per prefix; a sample of D2
        // would also leave D1's confirmation where it is.
        assert_eq!(pair.packet(false, ms(101)), Cover::P);
        assert_eq!(pair.p_born, ms(101));
        assert_eq!(pair.d2_verified, ms(101));
        assert_eq!(pair.d1_verified, 0);
        assert_eq!(pair.d1_prefix, Cover::P);

        // P looks fresh because of D2. D1 does not, so the next packet
        // identifies D1 and takes Q.
        let now = ms(110);
        assert!(association_is_fresh(pair.p_born, now));
        assert!(!dest_reuses_stored_prefix(pair.d1_verified, pair.p_born, now));
        assert_eq!(pair.packet(true, now), Cover::Q);
        assert_eq!(pair.d1_prefix, Cover::Q);
        assert_eq!(pair.d1_verified, now);

        // D2 is still on P. Renewing P again does not pull D1 back.
        assert_eq!(pair.packet(false, ms(120)), Cover::P);
        assert_eq!(pair.d1_prefix, Cover::Q);
        assert_eq!(pair.d2_prefix, Cover::P);

        // The other conjunct: a destination confirmed just now does not
        // reuse a snapshot whose own lifetime has already ended.
        assert!(association_is_fresh(ms(110), ms(210)));
        assert!(!association_is_fresh(0, ms(210)));
        assert!(!dest_reuses_stored_prefix(ms(110), 0, ms(210)));
    }
}
