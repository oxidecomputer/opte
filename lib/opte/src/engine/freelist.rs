// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! A freelist based on a bitmap, for fast port allocations in NAT pools.

use crate::engine::rule::ResourceError;
use alloc::vec::Vec;
use core::ops::RangeInclusive;

/// A freelist of ports, based on a bitmap.
///
/// The SNAT resource type relies on quickly loaning and reclaiming ports with a
/// fixed range. This type uses a fixed-size bitmap to track those free ports,
/// and supports fast operations to claim a specific port or the highest free
/// port, and to release taken ports back to the freelist.
///
/// # Performance
///
/// Internally, this uses a 2-level bitmap of 64-bit words to represent free
/// ports. There are 2 levels to the summarization: the first level represents
/// the actual port's state (free == 1, or allocated == 0). The second level
/// indicates whether the first-level word contains any 1 bits, i.e., if any of
/// the ports it represents are free. This is used to quickly search for the
/// next port in two steps: the highest word with at least one free port, and
/// then the highest port within that word.
///
/// The runtime of taking the next port is technically linear in the number of
/// ports, but the constant factors are very small. For the common case in the
/// Oxide VPC of 2**14 = 16Ki ports, there are 256 first-level and 4
/// second-level words, and only this latter list is iterated through
/// sequentially. Operations within each iteration are extremely fast, amounting
/// to a few bitshifts and other integer numerical operations. Once we have the
/// index of the first-level word, we can directly access it in O(1) and
/// manipulate the bits as needed.
///
/// Both asking for a _specific_ free port and freeing any port are O(1).
#[derive(Clone)]
pub struct Freelist {
    /// The full range of ports.
    ports: RangeInclusive<u16>,
    /// First-level bitmap, with one bit per port, 1 meaning the port is free.
    free: Vec<u64>,
    /// Second-level summary words, indicating which words in `free` have a bit
    /// set.
    summaries: Vec<u64>,
    /// The total number of free ports, i.e., 1 bits in `free`.
    n_free: usize,
}

impl core::fmt::Debug for Freelist {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Freelist")
            .field("ports", &self.ports)
            .field("n_free", &self.n_free)
            .field("free", &"<elided>")
            .field("summaries", &"<elided>")
            .finish()
    }
}

impl Freelist {
    const BITS: usize = u64::BITS as usize;

    /// Construct a new freelist with the provided range of ports.
    ///
    /// If the range of ports is empty, the resulting freelist will also be
    /// empty.
    //
    // TODO-correctness: We may want to return an error or option if the range
    // is empty instead, but the callers all expect this to work and construct
    // an empty list.
    pub fn new(ports: RangeInclusive<u16>) -> Self {
        let n_free = ports.len();
        let free = Self::build_words_for_bits(n_free);
        let summaries = Self::build_words_for_bits(free.len());
        let self_ = Self { ports, free, summaries, n_free };
        debug_assert_eq!(self_.popcount(), n_free);
        debug_assert!(self_.summaries_are_consistent());
        self_
    }

    // Build an array of 64-bit words storing `n_bits` ones and masking the
    // rest.
    fn build_words_for_bits(n_bits: usize) -> Vec<u64> {
        // We might have some bits at the end of the array that are not in the
        // allowed range at all, if the number of bits isn't a multiple of the
        // word size.
        let n_words = n_bits.div_ceil(Self::BITS);
        let mut words = vec![u64::MAX; n_words];
        if !n_bits.is_multiple_of(Self::BITS) {
            // Mask off those bits, so we never allow a caller to see or set
            // them.
            let mask = (1_u64 << (n_bits % Self::BITS)) - 1;
            let last = words
                .last_mut()
                .expect("div_ceil ensures we have at least 1 item");
            *last &= mask;
        }
        words
    }

    /// Return the full range of ports in self.
    pub fn ports(&self) -> &RangeInclusive<u16> {
        &self.ports
    }

    /// Return the number of free ports.
    pub fn n_free(&self) -> usize {
        self.n_free
    }

    /// Count the total number of 1 bits in self.
    fn popcount(&self) -> usize {
        self.free.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// Return true if the provided port is free.
    #[cfg(test)]
    pub fn is_free(&self, port: u16) -> bool {
        let Ok((word, mask)) = self.bit_for_port(port) else {
            return false;
        };
        self.free[word] & mask == mask
    }

    fn summaries_are_consistent(&self) -> bool {
        // Sanity check that the lengths are correct
        self.summaries.len() == self.free.len().div_ceil(Self::BITS)
            // And that each summary bit is a 1 iff the word it summarizes has
            // any bits set too.
            && (0..self.summaries.len() * Self::BITS).all(|w| {
                let (s, mask) = Self::word_and_mask(w);
                let summary_bit_is_set = self.summaries[s] & mask != 0;
                let word_has_free_bits = self.free.get(w).is_some_and(|&word| word != 0);
                summary_bit_is_set == word_has_free_bits
            })
    }

    /// Given a port, return the index of the word and a bitmask selecting it in
    /// that word. If the port is out of range, return an error.
    fn bit_for_port(&self, port: u16) -> Result<(usize, u64), ResourceError> {
        if !self.ports.contains(&port) {
            return Err(ResourceError::NoMatch(format!("Port: {}", port)));
        }
        let i = usize::from(port - *self.ports.start());
        Ok(Self::word_and_mask(i))
    }

    // Given a `bit`, return the word it resides in and a mask selecting it in
    // that word. This is used both for going from "is free" bits to words, and
    // from "word bits" to summaries.
    fn word_and_mask(bit: usize) -> (usize, u64) {
        (bit / Self::BITS, 1_u64 << (bit % Self::BITS))
    }

    /// Take the next free port, highest first.
    pub fn take_next(&mut self) -> Result<u16, ResourceError> {
        // Use the summary words to find the first word from the back that has
        // any 1 bit in it.
        let (sum_i, summary) = self
            .summaries
            .iter_mut()
            .enumerate()
            .rev()
            .find(|(_, summary)| **summary != 0)
            .ok_or(ResourceError::Exhausted)?;

        // Use `ilog2()` to compute the index of the word itself.
        let bit_in_summary = usize::try_from(summary.ilog2()).unwrap();
        let word_i = sum_i * Self::BITS + bit_in_summary;
        let word = self
            .free
            .get_mut(word_i)
            .expect("summary bit is set, word must exist");

        // Use `ilog2()` again to compute the index of the highest set bit in
        // that word, and clear the bit.
        debug_assert!(
            *word != 0,
            "word should have at least one bit set, since its summary bit \
            was also set"
        );
        let bit_in_word = usize::try_from(word.ilog2()).unwrap();
        *word &= !(1 << bit_in_word);
        self.n_free -= 1;

        // Offset to the word and bit in that word, to get the port itself.
        let offset = u16::try_from(word_i * Self::BITS + bit_in_word).unwrap();
        let port = *self.ports.start() + offset;

        // Make sure to clear the summary bit, if that was the last free bit in
        // the word itself.
        if *word == 0 {
            *summary &= !(1 << bit_in_summary);
        }

        Ok(port)
    }

    /// Attempt to take a specific port, if it's available.
    pub fn take(&mut self, port: u16) -> Result<(), ResourceError> {
        let (word_i, word_mask) = self.bit_for_port(port)?;
        if self.free[word_i] & word_mask == 0 {
            return Err(ResourceError::InUse(format!("Port: {}", port)));
        }
        self.free[word_i] &= !word_mask;
        self.n_free -= 1;

        // If the word is now completely empty, clear its summary bit too.
        if self.free[word_i] == 0 {
            let (sum_i, sum_mask) = Self::word_and_mask(word_i);
            self.summaries[sum_i] &= !sum_mask;
        }
        Ok(())
    }

    /// Free a port back to the list, if it's allocated. Return whether it was
    /// freed.
    ///
    /// If the port is out of range entirely, return
    /// `ResourceError::NoMatch(_)`. Otherwise return `Ok(freed)`, where `freed`
    /// is true if the port was _newly_ freed. This is analogous to how insert
    /// methods work on standard library set types.
    ///
    /// Callers should probably treat Ok(false) as a bug, since it indicates one
    /// tried to free an already-freed port.
    pub fn free(&mut self, port: u16) -> Result<bool, ResourceError> {
        let (word_i, word_mask) = self.bit_for_port(port)?;
        let was_in_use = self.free[word_i] & word_mask == 0;
        if was_in_use {
            self.free[word_i] |= word_mask;
            self.n_free += 1;

            // Make sure to mark the summary, as this word now contains a free
            // bit.
            let (sum_i, sum_mask) = Self::word_and_mask(word_i);
            self.summaries[sum_i] |= sum_mask;
        }
        Ok(was_in_use)
    }
}

#[cfg(test)]
mod tests {
    use super::Freelist;
    use super::ResourceError;
    use core::ops::RangeInclusive;
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    #[test]
    // This is exactly what we're checking, so silence the warning.
    #[allow(clippy::reversed_empty_ranges)]
    fn empty_ports_makes_empty_freelist() {
        assert_eq!(Freelist::new(1..=0).n_free(), 0);
        std::assert_matches!(
            Freelist::new(1..=0).take_next(),
            Err(ResourceError::Exhausted)
        );
    }

    #[test]
    fn freelist_sanity() {
        let mut list = Freelist::new(0..=128);

        // Allocate in reverse order
        let n_total = list.n_free;
        for x in (0..list.n_free).rev() {
            let expected = u16::try_from(x).unwrap();
            let actual = list.take_next().expect("expected to take a port");
            assert_eq!(actual, expected);
        }

        // No more left.
        assert!(list.take_next().is_err());

        // Put them back.
        for x in 0..n_total {
            std::assert_matches!(list.free(x.try_into().unwrap()), Ok(true));
        }

        // Take and free a few ports.
        //
        // This is a weak test, the proptest is the real deal.
        std::assert_matches!(list.take(64), Ok(()));
        std::assert_matches!(list.take(1), Ok(()));
        std::assert_matches!(list.take(1), Err(ResourceError::InUse(_)));
        std::assert_matches!(list.free(64), Ok(true));
        std::assert_matches!(list.free(64), Ok(false));
        std::assert_matches!(list.take(64), Ok(()));
    }

    #[test]
    fn freelist_does_not_alloc_out_of_bounds() {
        let mut list = Freelist::new(56..=128);
        assert!(list.take(129).is_err());
        assert!(list.take(0).is_err());
    }

    // A test operation to perform on the freelist
    #[derive(Debug, Clone, Copy)]
    enum FreelistOp {
        TakeNext,
        Take(u16),
        Free(u16),
    }

    /// Generate ranges with useful start / length.
    fn range_strategy() -> impl Strategy<Value = RangeInclusive<u16>> {
        let len = prop_oneof![
            // Exactly 1 port, the minimum for the freelist
            3 => Just(1u16),
            // Lengths around the u64 word boundaries.
            3 => prop::sample::select(vec![63u16, 64, 65, 127, 128, 129]),
            // Arbitrary in a range
            4 => 1u16..=2048,
        ];

        // Random start, most of the time random, but at the edges every once in
        // a while.
        let start = prop_oneof![
            1 => Just(0u16),
            1 => Just(u16::MAX),
            8 => any::<u16>(),
        ];

        // Make it into a range.
        (start, len).prop_map(|(start, len)| {
            let start = start.min(u16::MAX - (len - 1));
            start..=start + (len - 1)
        })
    }

    /// Generate ports that are mostly in a range. This slightly weights up
    /// values at the boundaries and just outside them.
    fn port_strategy(r: RangeInclusive<u16>) -> impl Strategy<Value = u16> {
        let (start, end) = (*r.start(), *r.end());
        prop_oneof![
            // 60% of the time, just use the range.
            6 => r.clone(),
            // 20% select a boundary
            2 => prop::sample::select(vec![start, end]),
            // 10% right outside the boundary
            1 => prop::sample::select(vec![start.wrapping_sub(1), end.wrapping_add(1)]),
            // And 10% completely arbitrary.
            1 => any::<u16>(),
        ]
    }

    /// Generate a random op to take on the freelist
    fn op_strategy(
        r: RangeInclusive<u16>,
    ) -> impl Strategy<Value = Vec<FreelistOp>> {
        let op = prop_oneof![
            // Take the next item
            1 => Just(FreelistOp::TakeNext),
            // Take a specific item
            1 => port_strategy(r.clone()).prop_map(FreelistOp::Take),
            // Release a specific item
            1 => port_strategy(r).prop_map(FreelistOp::Free),
        ];

        // Take a bunch of random operations in each case.
        prop::collection::vec(op, 0..1024)
    }

    /// Generate a proptest strategy for each test case.
    fn case_strategy()
    -> impl Strategy<Value = (RangeInclusive<u16>, Vec<FreelistOp>)> {
        range_strategy().prop_flat_map(|r| (Just(r.clone()), op_strategy(r)))
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn freelist_matches_reference((range, ops) in case_strategy()) {
            let mut list = Freelist::new(range.clone());
            let mut reference: BTreeSet<_> = range.clone().collect();

            for (i, op) in ops.into_iter().enumerate() {
                match op {
                    FreelistOp::TakeNext => {
                        // If we can pop a port from the reference, we should
                        // also be able to pop it from our freelist.
                        let expected = reference.pop_last();
                        let actual = list.take_next().ok();
                        prop_assert_eq!(
                            actual,
                            expected,
                            "failed to take next free port, step {}",
                            i,
                        );
                    }
                    FreelistOp::Take(port) => {
                        let res = list.take(port);
                        if !range.contains(&port) {
                            prop_assert!(
                                matches!(res, Err(ResourceError::NoMatch(_))),
                                "Should have failed to take the port {} \
                                which is completely out of the freelist \
                                range [{}, {}]",
                                port,
                                range.start(),
                                range.end(),
                            );
                        } else if reference.remove(&port) {
                            // It was in the reference, and we removed it, so we
                            // should be able to take it.
                            prop_assert!(
                                res.is_ok(),
                                "Should successfully take a port {} \
                                that is in-range and was in the reference \
                                freelist",
                                port,
                            );
                        } else {
                            prop_assert!(
                                matches!(res, Err(ResourceError::InUse(_))),
                                "Should fail to take the port {} \
                                that is not in the reference freelist",
                                port,
                            );
                        }
                    }
                    FreelistOp::Free(port) => {
                        let res = list.free(port);
                        if !range.contains(&port) {
                            prop_assert!(
                                matches!(res, Err(ResourceError::NoMatch(_))),
                                "Should have failed to free the port {} \
                                which is completely out of the freelist \
                                range [{}, {}]",
                                port,
                                range.start(),
                                range.end(),
                            );
                        } else if reference.insert(port) {
                            // It wasn't in the reference, so freeing it should
                            // work.
                            prop_assert!(
                                matches!(res, Ok(true)),
                                "Should have succeeded in freeing the port {} \
                                which was not in the reference freelist",
                                port,
                            );
                        } else {
                            prop_assert!(
                                matches!(res, Ok(false)),
                                "Should have returned Ok(false) for port {} \
                                which was already free, to indicate the double-\
                                free",
                                port,
                            );
                        }
                    }
                }

                // We should have exactly the same number of items in the
                // freelist and the reference.
                prop_assert_eq!(list.n_free, reference.len());
                prop_assert_eq!(list.popcount(), list.n_free);

                // And the summaries should exactly represent the free words
                // with at least 1 bit set.
                prop_assert!(list.summaries_are_consistent(), "step {}: {:?}", i, op);
            }

            // And the exact ports we claim are free should actually be in the
            // reference freelist.
            let bits: BTreeSet<u16> = range
                .clone()
                .filter(|p| list.is_free(*p))
                .collect();
            prop_assert_eq!(bits, reference);
        }
    }

    #[test]
    fn freelist_with_full_port_range() {
        let mut list = Freelist::new(0..=u16::MAX);
        for i in (0..=u16::MAX).rev() {
            assert_eq!(i, list.take_next().unwrap());
        }
        assert_eq!(list.n_free, 0);
        std::assert_matches!(list.take_next(), Err(ResourceError::Exhausted));
        std::assert_matches!(list.take(10), Err(ResourceError::InUse(_)));

        // Free a few and take them back, just to cover those methods near the
        // numerical range.
        for port in (0..=u16::MAX).rev().take(4) {
            std::assert_matches!(list.free(port), Ok(true));
        }
        for port in (0..=u16::MAX).rev().take(4) {
            list.take(port).unwrap();
        }
    }
}
