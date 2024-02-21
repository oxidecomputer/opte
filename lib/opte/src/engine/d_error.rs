// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

//! Utility for converting nested enum `Error`s into collections of
//! static strings to avoid paying the `fmt` tax when calling an SDT.

use core::ffi::CStr;
pub use derror_macro::DError;

/// Compile-time const cstring from a byte slice. Callers must
/// include a `b'\0'`.
macro_rules! cstr {
    ($e:expr) => {
        if let Ok(s) = CStr::from_bytes_with_nul($e) {
            s
        } else {
            panic!("Bad cstring constant!")
        }
    };
}

/// Compile-time const cstring from a byte slice, including declaration.
/// Callers must include a `b'\0'`.
macro_rules! static_cstr {
    ($i:ident, $e:expr) => {
        static $i: &CStr = cstr!($e);
    };
}

static_cstr!(EMPTY_STRING, b"\0");

// XXX: I think we want some way of doing the whole thing in one big chunk
//      to prevent e.g. 4 dyn dispatches in a row.

/// A trait used for walking chains of errors which store useful data in
/// a leaf node.
pub trait DError {
    /// Provide the name of an error's discriminant.
    fn discriminant(&self) -> &'static CStr;

    /// Provide a reference to the next error in the chain.
    fn child(&self) -> Option<&dyn DError>;

    /// Store data from a leaf error to be bundled with a probe, returning
    /// an optional additional string parameter.
    fn leaf_data(&self, _data: &mut [u64]) -> Option<&'static CStr> { None }
}

/// A static string which is jointly usable as a `CStr` and `str`.
pub struct CRStr(&'static str, &'static CStr);

impl CRStr {
    pub const fn new(data: &'static str) -> Result<Self, ()> {
        if let Ok(cs) = CStr::from_bytes_with_nul(data.as_bytes()) {
            if let Some((_nul, actual_str)) = data.as_bytes().split_last() {
                Ok(Self(
                    // SAFETY: We have been given a valid &str, and we know
                    // its last character *must* be \0 due to the success of
                    // from_bytes_with_nul. Additionally, \0 cannot be an interior
                    // byte of a UTF8 multibyte character (which are `0x10xx_xxxx`).
                    unsafe {std::str::from_utf8_unchecked(actual_str)},
                    cs
                ))    
            } else {
                Err(())
            }
        } else {
            Err(())
        }
    }

    pub fn as_str(&self) -> &'static str {
        self.0
    }

    pub fn as_cstr(&self) -> &'static CStr {
        self.1
    }
}

impl AsRef<str> for CRStr {
    fn as_ref(&self) -> &'static str {
        self.as_str()
    }
}

impl AsRef<CStr> for CRStr {
    fn as_ref(&self) -> &'static CStr {
        &self.as_cstr()
    }
}

impl DError for CRStr {
    fn discriminant(&self) -> &'static CStr {
        self.as_cstr()
    }

    fn child(&self) -> Option<&dyn DError> {
        None
    }
}

impl DError for &CRStr {
    fn discriminant(&self) -> &'static CStr {
        self.as_cstr()
    }

    fn child(&self) -> Option<&dyn DError> {
        None
    }
}

impl std::fmt::Debug for CRStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::fmt::Display for CRStr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Create a const/statically verified `str`/`CStr` hybrid.
#[macro_export]
macro_rules! static_crstr {
    ($i:ident, $e:expr) => {
        static $i: CRStr = {
            static LOCAL: &str = concat!($e, "\0");

            let Ok(b) = CRStr::new(LOCAL) else {
                panic!();
            };

            b
        };
    };
}

/// An error trace designed to be passed to a Dtrace handler, which contains
/// the names of all `enum` discriminators encountered when resolving an error
/// as well as the data from a leaf node.
///
/// This wrapper cannot contain a null c_string pointer, so all entries are
/// safe to dereference from a dtrace script. Additionally, it has a fixed
/// C-ABI representation to minimise the work needed to pass it as an SDT arg.
#[derive(Debug)]
#[repr(C)]
pub struct ErrorBlock<const L: usize> {
    len: usize,
    more: bool,
    // XXX: Maybe we can move this to a generic?
    data: [u64; 2],
    // XXX: Box?
    entries: [*const i8; L],
}

impl<const L: usize> ErrorBlock<L> {
    /// Create storage to hold at most `L` static string entries.
    pub fn new() -> Self {
        Self {
            entries: [EMPTY_STRING.as_ptr(); L],

            len: 0,
            more: false,

            data: [0; 2],
        }
    }

    /// Flatten a nested error into a static string list.
    ///
    /// This function will return an error if the provided `err` contains
    /// too many entries to include within this `ErrorBlock`.
    pub fn from_err(err: &dyn DError) -> Result<ErrorBlock<L>, ErrorBlock<L>> {
        let mut out = ErrorBlock::new();

        if out.append(err).is_err() {
            Err(out)
        } else {
            Ok(out)
        }
    }

    /// Push all layers (and data) of an error into a block.
    pub fn append(&mut self, err: &dyn DError) -> Result<(), ()> {
        let mut top: Option<&dyn DError> = Some(err);
        while let Some(el) = top {
            self.append_name(el)?;
            top = el.child();

            if top.is_none() {
                if let Some(extra_label) = el.leaf_data(&mut self.data[..]) {
                    self.append_static_name(extra_label)?;
                }
            }
        }
        Ok(())
    }

    /// Appends the top layer name of a given error.
    pub fn append_name(&mut self, err: &dyn DError) -> Result<(), ()> {
        self.append_static_name(err.discriminant())
    }

    /// XXX
    #[inline]
    pub fn append_static_name(&mut self, err: &'static CStr) -> Result<(), ()> {
        if self.len >= L {
            self.more = true;
            return Err(());
        }

        self.entries[self.len] = err.as_ptr();
        self.len += 1;

        Ok(())
    }

    /// XXX
    ///
    /// Callers must ensure that pointee outlives this ErrorBlock.
    pub unsafe fn append_name_raw<'a, 'b: 'a>(
        &'a mut self,
        err: &'b CStr,
    ) -> Result<(), ()> {
        if self.len >= L {
            self.more = true;
            return Err(());
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
    pub fn entries<'a>(&'a self) -> ErrorBlockIter<'a, L> {
        ErrorBlockIter { pos: 0, inner: self }
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
        self as *const ErrorBlock::<L>
    }
}

pub struct ErrorBlockIter<'a, const L: usize> {
    pos: usize,
    inner: &'a ErrorBlock<L>,
}

impl<'a, const L: usize> Iterator for ErrorBlockIter<'a, L> {
    type Item = &'static CStr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.inner.len {
            return None;
        }

        // SAFETY: ErrorBlock can only be constructed using 'static CStr
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

impl<'a, const L: usize> ExactSizeIterator for ErrorBlockIter<'a, L> {
    fn len(&self) -> usize {
        self.inner.len - self.pos
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static_cstr!(A_C, b"A\0");
    static_cstr!(B_C, b"B\0");
    static_cstr!(ND_C, b"NoData\0");
    static_cstr!(D_C, b"Data\0");
    static_cstr!(EXTRASTR_C, b"ExtraStr\0");
    static_crstr!(EXTRA_C, "Extra! Extra!");

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
        ExtraStr { s: &'static CRStr },
    }

    impl TestChildEnum {
        fn data(&self, data: &mut [u64])-> Option<&'static CStr> {
            match self {
                TestChildEnum::NoData => None,
                TestChildEnum::Data { a, b } => {
                    [data[0], data[1]] = [*a as u64, *b as u64];
                    None
                }
                TestChildEnum::ExtraStr { s } => Some(s.as_cstr()),
            }
        }
    }

    #[test]
    fn name_and_data_storage() {
        let err = TestEnum::A;
        let block: ErrorBlock<2> = ErrorBlock::from_err(&err).unwrap();
        let mut block_iter = block.entries();
        assert_eq!(block_iter.len(), 1);
        assert_eq!(block_iter.next(), Some(A_C));
        assert_eq!(block_iter.len(), 0);
        assert_eq!(block_iter.next(), None);

        let err = TestEnum::B(TestChildEnum::NoData);
        let block: ErrorBlock<2> = ErrorBlock::from_err(&err).unwrap();
        let names = block.entries().collect::<Vec<_>>();
        assert_eq!(&names[..], &[B_C, ND_C][..]);

        let err = TestEnum::B(TestChildEnum::Data { a: 0xab, b: 0xcd });
        let block: ErrorBlock<2> = ErrorBlock::from_err(&err).unwrap();
        let names = block.entries().collect::<Vec<_>>();
        assert_eq!(&names[..], &[B_C, D_C][..]);
        assert_eq!(block.data[0], 0xab);
        assert_eq!(block.data[1], 0xcd);

        let err = TestEnum::B(TestChildEnum::ExtraStr { s: &EXTRA_C });
        let block: ErrorBlock<3> = ErrorBlock::from_err(&err).unwrap();
        let names = block.entries().collect::<Vec<_>>();
        assert_eq!(&names[..], &[B_C, EXTRASTR_C, EXTRA_C.as_cstr()][..]);
    }

    #[test]
    fn name_truncation() {
        let err = TestEnum::B(TestChildEnum::NoData);
        let block: ErrorBlock<1> = ErrorBlock::from_err(&err).unwrap_err();
        let mut block_iter = block.entries();
        assert_eq!(block_iter.len(), 1);
        assert_eq!(block_iter.next(), Some(B_C));
        assert_eq!(block_iter.len(), 0);
        assert_eq!(block_iter.next(), None);
        assert_eq!(block.more, true);
    }
}
