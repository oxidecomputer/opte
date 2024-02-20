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

// XXX: I think we want some way of doing the whole thing in one big chunk
//      to prevent e.g. 4 dyn dispatches in a row.

/// A trait used for walking chains of errors which store useful data in
/// a leaf node.
pub trait DError {
    /// Provide the name of an error's discriminant.
    fn discriminant(&self) -> &'static CStr;

    /// Provide a reference to the next error in the chain.
    fn child(&self) -> Option<&dyn DError>;

    /// Store data from a leaf error to be bundled with a probe.
    fn leaf_data(&self, _data: &mut [u64]) {}
}

static EMPTY_STRING: &CStr = cstr!(b"\0");

/// An error trace designed to be passed to a Dtrace handler, which contains
/// the names of all `enum` discriminators encountered when resolving an error
/// as well as the data from a leaf node.
///
/// This wrapper cannot contain a null c_string pointer, so all entries are
/// safe to dereference from a dtrace script.
#[derive(Debug)]
pub struct ErrorBlock<const L: usize> {
    entries: [*const i8; L],

    len: usize,
    more: bool,

    // XXX: Maybe we can move this to a generic?
    data: [u64; 2],
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
                el.leaf_data(&mut self.data[..]);
            }
        }
        Ok(())
    }

    /// Appends the top layer name of a given error.
    pub fn append_name(&mut self, err: &dyn DError) -> Result<(), ()> {
        if self.len >= L {
            self.more = true;
            return Err(());
        }

        self.entries[self.len] = err.discriminant().as_ptr();
        self.len += 1;

        Ok(())
    }

    /// Appends the top layer name of a given error.
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

static_cstr!(BAD_HEADER, b"BadHeader\0");
static_cstr!(BAD_INNER_IP_LEN, b"BadInnerIpLen\0");
static_cstr!(BAD_OUTER_IP_LEN, b"BadOuterIpLen\0");
static_cstr!(BAD_INNER_ULP_LEN, b"BadInnerUlpLen\0");
static_cstr!(BAD_OUTER_ULP_LEN, b"BadOuterUlpLen\0");
static_cstr!(BAD_READ, b"BadRead\0");
static_cstr!(TRUNCATED_BODY, b"TruncatedBody\0");
static_cstr!(UNEXPECTED_ETHER_TYPE, b"UnexpectedEtherType\0");
static_cstr!(UNSUPPORTED_ETHER_TYPE, b"UnsupportedEtherType\0");
static_cstr!(UNEXPECTED_PROTOCOL, b"UnexpectedProtocol\0");
static_cstr!(UNSUPPORTED_PROTOCOL, b"UnsupportedProtocol\0");
impl DError for super::packet::ParseError {
    fn discriminant(&self) -> &'static CStr {
        match self {
            Self::BadHeader(_) => BAD_HEADER,
            Self::BadInnerIpLen { .. } => BAD_INNER_IP_LEN,
            Self::BadInnerUlpLen { .. } => BAD_INNER_ULP_LEN,
            Self::BadOuterIpLen { .. } => BAD_OUTER_IP_LEN,
            Self::BadOuterUlpLen { .. } => BAD_OUTER_ULP_LEN,
            Self::BadRead(_) => BAD_READ,
            Self::TruncatedBody { .. } => TRUNCATED_BODY,
            Self::UnexpectedEtherType(_) => UNEXPECTED_ETHER_TYPE,
            Self::UnsupportedEtherType(_) => UNSUPPORTED_ETHER_TYPE,
            Self::UnexpectedProtocol(_) => UNEXPECTED_PROTOCOL,
            Self::UnsupportedProtocol(_) => UNSUPPORTED_PROTOCOL,
        }
    }

    fn child(&self) -> Option<&dyn DError> {
        match self {
            // Currently need to pull out the string at the end when needed -- ouch.
            // TODO: Convert to BadHeader(Box<dyn DError>).
            // Safely treating a String inside this is a little fraught:
            // I think it can be done if it's a valid CStr and we e.g. take
            // ownership of the root err. No point in doing this and needing
            // to reason about non-static strings when we should just replace
            // that body with e.g. another dyn DError in future.
            Self::BadHeader(_s) => None,
            Self::BadRead(r) => Some(r),
            _ => None,
        }
    }

    fn leaf_data(&self, data: &mut [u64]) {
        match self {
            Self::BadInnerIpLen { expected, actual }
            | Self::BadInnerUlpLen { expected, actual }
            | Self::BadOuterIpLen { expected, actual }
            | Self::BadOuterUlpLen { expected, actual }
            | Self::TruncatedBody { expected, actual } => {
                [data[0], data[1]] = [*expected as u64, *actual as u64]
            }
            Self::UnexpectedEtherType(eth) => data[0] = u16::from(*eth).into(),
            Self::UnsupportedEtherType(eth) => data[0] = *eth as u64,
            Self::UnexpectedProtocol(proto) => {
                data[0] = u8::from(*proto).into()
            }
            Self::UnsupportedProtocol(proto) => {
                data[0] = u8::from(*proto).into()
            }

            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static_cstr!(A_C, b"A\0");
    static_cstr!(B_C, b"B\0");
    static_cstr!(ND_C, b"NoData\0");
    static_cstr!(D_C, b"Data\0");

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
