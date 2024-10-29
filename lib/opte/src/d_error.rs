// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Utility for converting nested enum `Error`s into collections of
//! static strings to avoid paying the `fmt` tax when calling an SDT.

use core::ffi::CStr;
pub use derror_macro::DError;

// XXX: I think we want some way of doing the whole thing in one big chunk
//      to prevent e.g. 4 dyn dispatches in a row.

/// A trait used for walking chains of errors (or other types -- mainly `enum`s)
/// which store useful data in a leaf node.
pub trait DError {
    /// Provide the name of an error's discriminant.
    fn discriminant(&self) -> &'static CStr;

    /// Provide a reference to the next error in the chain.
    fn child(&self) -> Option<&dyn DError>;

    /// Store data from a leaf error to be bundled with a probe.
    fn leaf_data(&self, _data: &mut [u64]) {}
}

static EMPTY_STRING: &CStr = c"";

/// A string list designed to be passed to a DTrace handler.
///
/// This contains the names of all `enum` discriminators encountered when
/// resolving an error or other result-like enum, as well as the data from a
/// leaf node.
///
/// This wrapper cannot contain a null c_string pointer, so all entries are
/// safe to dereference from a DTrace script. Additionally, it has a fixed
/// C-ABI representation to minimise the work needed to pass it as an SDT arg.
#[derive(Debug)]
#[repr(C)]
pub struct LabelBlock<const L: usize> {
    len: usize,
    more: bool,
    // XXX: Maybe we can move this to a generic?
    data: [u64; 2],
    // XXX: Box?
    entries: [*const i8; L],
}

/// Signals that a [`LabelBlock`] could not contain a new string entry.
#[derive(Clone, Copy, Debug)]
pub struct LabelBlockFull;

impl<const L: usize> Default for LabelBlock<L> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const L: usize> LabelBlock<L> {
    /// Create storage to hold at most `L` static string entries.
    pub fn new() -> Self {
        Self {
            entries: [EMPTY_STRING.as_ptr(); L],

            len: 0,
            more: false,

            data: [0; 2],
        }
    }

    /// Flatten a nested type into a static string list.
    ///
    /// This function will return an `Err` if the provided `val` contains
    /// too many entries to include within this `LabelBlock`.
    pub fn from_nested(
        val: &dyn DError,
    ) -> Result<LabelBlock<L>, LabelBlock<L>> {
        let mut out = LabelBlock::new();

        if out.append(val).is_err() {
            Err(out)
        } else {
            Ok(out)
        }
    }

    /// Push all layers (and data) of a nested type into a block.
    pub fn append(&mut self, err: &dyn DError) -> Result<(), LabelBlockFull> {
        let mut top: Option<&dyn DError> = Some(err);
        while let Some(el) = top {
            self.append_name(el)?;
            top = el.child();

            if top.is_none() {
                el.leaf_data(&mut self.data[..]);
            }
        }
        Ok(())
    }

    /// Appends the top layer name of a given error.
    pub fn append_name(
        &mut self,
        err: &dyn DError,
    ) -> Result<(), LabelBlockFull> {
        if self.len >= L {
            self.more = true;
            return Err(LabelBlockFull);
        }

        self.entries[self.len] = err.discriminant().as_ptr();
        self.len += 1;

        Ok(())
    }

    /// Appends the top layer name of a given error.
    ///
    /// # Safety
    /// Callers must ensure that pointee outlives this LabelBlock.
    pub unsafe fn append_name_raw<'a, 'b: 'a>(
        &'a mut self,
        err: &'b CStr,
    ) -> Result<(), LabelBlockFull> {
        if self.len >= L {
            self.more = true;
            return Err(LabelBlockFull);
        }

        self.entries[self.len] = err.as_ptr();
        self.len += 1;

        Ok(())
    }

    /// Return the number of stored strings entries.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Return whether this block contains no layer names.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Provides access to all stored [`CStr`]s.
    pub fn entries(&self) -> LabelBlockIter<'_, L> {
        LabelBlockIter { pos: 0, inner: self }
    }

    /// Provides pointers to all stored [`CStr`]s.
    pub fn entries_ptr(&self) -> &[*const i8] {
        &self.entries[..self.len]
    }

    /// Provides access to data stored in a leaf error.
    pub fn data(&self) -> &[u64] {
        &self.data[..]
    }

    /// Return a pointer to this object for inclusion in an SDT.
    pub fn as_ptr(&self) -> *const Self {
        self as *const LabelBlock<L>
    }
}

pub struct LabelBlockIter<'a, const L: usize> {
    pos: usize,
    inner: &'a LabelBlock<L>,
}

impl<const L: usize> Iterator for LabelBlockIter<'_, L> {
    type Item = &'static CStr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.inner.len {
            return None;
        }

        // SAFETY: LabelBlock can only be constructed using 'static CStr
        //         entries, and defaults to be full of empty entries.
        //         So any pointee is a valid static CStr.
        let out = unsafe { CStr::from_ptr(self.inner.entries[self.pos]) };
        self.pos += 1;

        Some(out)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let rem = self.len();
        (rem, Some(rem))
    }
}

impl<const L: usize> ExactSizeIterator for LabelBlockIter<'_, L> {
    fn len(&self) -> usize {
        self.inner.len - self.pos
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static A_C: &CStr = c"A";
    static B_C: &CStr = c"B";
    static ND_C: &CStr = c"NoData";
    static D_C: &CStr = c"Data";

    #[derive(DError)]
    enum TestEnum {
        A,
        B(TestChildEnum),
    }

    #[derive(DError)]
    #[derror(leaf_data = TestChildEnum::data)]
    enum TestChildEnum {
        NoData,
        Data { a: u8, b: u8 },
    }

    impl TestChildEnum {
        fn data(&self, data: &mut [u64]) {
            match self {
                TestChildEnum::NoData => {}
                TestChildEnum::Data { a, b } => {
                    [data[0], data[1]] = [*a as u64, *b as u64]
                }
            }
        }
    }

    #[test]
    fn name_and_data_storage() {
        let err = TestEnum::A;
        let block: LabelBlock<2> = LabelBlock::from_nested(&err).unwrap();
        let mut block_iter = block.entries();
        assert_eq!(block_iter.len(), 1);
        assert_eq!(block_iter.next(), Some(A_C));
        assert_eq!(block_iter.len(), 0);
        assert_eq!(block_iter.next(), None);

        let err = TestEnum::B(TestChildEnum::NoData);
        let block: LabelBlock<2> = LabelBlock::from_nested(&err).unwrap();
        let names = block.entries().collect::<Vec<_>>();
        assert_eq!(&names[..], &[B_C, ND_C][..]);

        let err = TestEnum::B(TestChildEnum::Data { a: 0xab, b: 0xcd });
        let block: LabelBlock<2> = LabelBlock::from_nested(&err).unwrap();
        let names = block.entries().collect::<Vec<_>>();
        assert_eq!(&names[..], &[B_C, D_C][..]);
        assert_eq!(block.data[0], 0xab);
        assert_eq!(block.data[1], 0xcd);
    }

    #[test]
    fn name_truncation() {
        let err = TestEnum::B(TestChildEnum::NoData);
        let block: LabelBlock<1> = LabelBlock::from_nested(&err).unwrap_err();
        let mut block_iter = block.entries();
        assert_eq!(block_iter.len(), 1);
        assert_eq!(block_iter.next(), Some(B_C));
        assert_eq!(block_iter.len(), 0);
        assert_eq!(block_iter.next(), None);
        assert!(block.more);
    }
}
