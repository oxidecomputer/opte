// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Support for DHCPv6 Options
//!
//! The majority of data transferred in DHCPv6 is done so via Options. They have
//! a simple format:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |          option-code          |           option-len          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          option-data                          |
//! |                      (option-len octets)                      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The option-code defines the interpretation of option-data. For example, if
//! option-code is `OPTION_CLIENTID`, numeric value 1, then option-data is a
//! DUID identifying a single client in a message exchange. Options are also
//! used to transmit leased IP addresses, DNS servers, and pretty much
//! everything else of note.
//!
//! Clients are expected to submit the options they would like the server to
//! provide them with in both Solicit and Request messages. Clients can either
//! do so by submitting an actual option, formatted like above, or by sending
//! just the option-code of the option they want in a special "Option Request
//! option". See below for details.
//!
//! Information Associations
//! ------------------------
//!
//! An Information Assocation (IA) is DHCPv6's fancy way of referring data that
//! is associated with or committed to a particular client. For example, an IPv6
//! address leased to a client is one IA.
//!
//! Notes
//! -----
//!
//! RFC 8415 sec 21 describes options in general, with each option in a
//! subsection.

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use alloc::borrow::Cow;
        use alloc::str::from_utf8;
        use alloc::vec::Vec;
    } else {
        use std::borrow::Cow;
        use std::str::from_utf8;
        use std::vec::Vec;
    }
}

use super::Duid;
use super::Error;
use super::Lifetime;
use core::mem::size_of;
use core::ops::Range;
use opte_api::DomainName;
use opte_api::Ipv6Addr;

/// A DHCPv6 Option code.
///
/// Note that we don't support every option (there are a lot), and
/// unsupported options are captured in the `Other` variant. See [IANA
/// DHCPv6 Parameters] for a complete list of option codes.
///
/// [IANA DHCPv6 Parameters]:
/// https://www.iana.org/assignments/dhcpv6-parameters/dhcpv6-parameters.xhtml
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Code {
    /// The option contains a client DUID.
    ClientId,
    /// The option contains a server DUID.
    ServerId,
    /// A Non-Temporary Address Information Association
    IaNa,
    /// A Temporary Address Information Association.
    IaTa,
    /// An actual IPv6 address.
    ///
    /// These must be encapsulated in IaNa or IaTa options.
    IaAddr,
    /// The option contains a list of option-codes.
    OptionRequest,
    /// The option contains the elapsed time since a client began its current
    /// transaction, in 10ms increments.
    ElapsedTime,
    /// The option contains a status code and message referring to the
    /// current message or option in which it appears. See [RFC 8415
    /// §21.13] for a list of the codes and messages.
    ///
    /// [RFC 8415 §21.13]:
    /// https://www.rfc-editor.org/rfc/rfc8415.html#section-21.13
    StatusCode,
    /// An option indicating that the client would like data to be committed
    /// immediately, bypassing the normal acknowledgement message sequence.
    RapidCommit,
    /// The option contains a list of IPv6 addresses the client can use for DNS
    /// servers.
    ///
    /// This option is specified in RFC 3646.
    DnsServers,
    /// The option contains a list of domains that the client should use when
    /// resolving names via DNS that are not fully-qualified.
    ///
    /// This option is specified in RFC 3646.
    DomainList,
    /// The option contains a list of IPv6 addresses the client can use for SNTP
    /// servers.
    ///
    /// This option is specified in RFC 4075.
    SntpServers,
    /// Any other option, which is unsupported and uninterpreted.
    Other(u16),
}

impl Code {
    const SIZE: usize = size_of::<u16>();
}

impl From<Code> for u16 {
    fn from(code: Code) -> u16 {
        use Code::*;
        match code {
            ClientId => 1,
            ServerId => 2,
            IaNa => 3,
            IaTa => 4,
            IaAddr => 5,
            OptionRequest => 6,
            ElapsedTime => 8,
            StatusCode => 13,
            RapidCommit => 14,
            DnsServers => 23,
            DomainList => 24,
            SntpServers => 31,
            Other(x) => x,
        }
    }
}

impl From<u16> for Code {
    fn from(x: u16) -> Code {
        use Code::*;
        match x {
            1 => ClientId,
            2 => ServerId,
            3 => IaNa,
            4 => IaTa,
            5 => IaAddr,
            6 => OptionRequest,
            8 => ElapsedTime,
            13 => StatusCode,
            14 => RapidCommit,
            23 => DnsServers,
            24 => DomainList,
            31 => SntpServers,
            x => Other(x),
        }
    }
}

/// An Information Association Identifier (IAID).
///
/// Information Associations are a confusing way of describing data that has
/// been assigned or committed to a client by a server. The most important kind
/// of IA is an address that a server leases to a client.
///
/// IAIDs are supposed to be unique for each client and IA type. For example,
/// the IAIDs for the IPv6 addresses leased to two clients must be different, as
/// must the IAIDs for the the Non-Temporary addresses and delegate prefixes for
/// the same client. Other than that, it's just a unique integer.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct IaId(pub u32);

/// Constants used for IAIDs of various types.
///
/// IDs are supposed to be unique between type and client. There is only one
/// client, so there only needs to be one ID per IA type.
pub const IANA_ID: IaId = IaId(1);
pub const IATA_ID: IaId = IaId(2);

/// A raw, uninterpreted DHCPv6 option.
///
/// Most options are not supported, but we're required to simply ingore those.
/// This type is used to store uninterpreted options in messages received from
/// clients.
#[derive(Clone, Debug, PartialEq)]
pub struct RawOption<'a>(pub Cow<'a, [u8]>);

impl<'a> RawOption<'a> {
    // NOTE: This includes _only_ the length of the raw data itself.
    fn buffer_len(&self) -> usize {
        self.0.len()
    }

    fn copy_into(&self, buf: &'a mut [u8]) -> Result<(), Error> {
        if buf.len() < self.buffer_len() {
            return Err(Error::Truncated);
        }
        buf.copy_from_slice(&self.0);
        Ok(())
    }
}

/// A single DHCPv6 option.
#[derive(Clone, Debug, PartialEq)]
pub enum Option<'a> {
    ClientId(Duid<'a>),
    ServerId(Duid<'a>),
    IaNa(IaNa<'a>),
    IaTa(IaTa<'a>),
    IaAddr(IaAddr<'a>),
    OptionRequest(OptionRequest<'a>),
    ElapsedTime(ElapsedTime),
    Status(Status<'a>),
    RapidCommit,
    DnsServers(IpList<'a>),
    DomainList(Cow<'a, [u8]>),
    SntpServers(IpList<'a>),
    Other { code: Code, data: RawOption<'a> },
}

impl<'a> Option<'a> {
    const CODE: Range<usize> = 0..2;
    const LEN: Range<usize> = 2..4;
    const DATA_START: usize = 4;

    /// Return the code associated with this Option.
    pub fn code(&self) -> Code {
        match self {
            Option::ClientId(_) => Code::ClientId,
            Option::ServerId(_) => Code::ServerId,
            Option::IaNa(_) => Code::IaNa,
            Option::IaTa(_) => Code::IaTa,
            Option::IaAddr(_) => Code::IaAddr,
            Option::OptionRequest(_) => Code::OptionRequest,
            Option::ElapsedTime(_) => Code::ElapsedTime,
            Option::Status(_) => Code::StatusCode,
            Option::RapidCommit => Code::RapidCommit,
            Option::DnsServers(_) => Code::DnsServers,
            Option::DomainList(_) => Code::DomainList,
            Option::SntpServers(_) => Code::SntpServers,
            Option::Other { code, .. } => *code,
        }
    }

    fn data_len(&self) -> usize {
        match self {
            Option::ClientId(inner) => inner.buffer_len(),
            Option::ServerId(inner) => inner.buffer_len(),
            Option::IaNa(inner) => inner.buffer_len(),
            Option::IaTa(inner) => inner.buffer_len(),
            Option::IaAddr(inner) => inner.buffer_len(),
            Option::OptionRequest(inner) => inner.buffer_len(),
            Option::ElapsedTime(inner) => inner.buffer_len(),
            Option::Status(inner) => inner.buffer_len(),
            Option::RapidCommit => 0,
            Option::DnsServers(inner) => inner.buffer_len(),
            Option::DomainList(inner) => inner.len(),
            Option::SntpServers(inner) => inner.buffer_len(),
            Option::Other { data, .. } => data.buffer_len(),
        }
    }

    /// Return the length of a buffer required to completely serialize this
    /// option.
    pub fn buffer_len(&self) -> usize {
        size_of::<u16>() * 2 + self.data_len()
    }

    /// Copy the data corresponding to this Option into the given buffer. If the
    /// buffer isn't large enough, an Err is returned. The appropriate size can
    /// be determined with `Option::buffer_len()`.
    pub fn copy_into(&self, buf: &mut [u8]) -> Result<(), Error> {
        if buf.len() < self.buffer_len() {
            return Err(Error::Truncated);
        }
        let code = self.code();
        buf[Self::CODE].copy_from_slice(&u16::from(self.code()).to_be_bytes());
        let data_len =
            u16::try_from(self.data_len()).map_err(|_| Error::Truncated)?;
        buf[Self::LEN].copy_from_slice(&data_len.to_be_bytes());

        // Check for the Rapid Commit option first. That has a zero actual data,
        // and so the indexing below would fail in that case.
        if matches!(code, Code::RapidCommit) {
            return Ok(());
        }

        let data = &mut buf[Self::DATA_START..];
        match self {
            Option::ClientId(inner) => inner.copy_into(data),
            Option::ServerId(inner) => inner.copy_into(data),
            Option::IaNa(inner) => inner.copy_into(data),
            Option::IaTa(inner) => inner.copy_into(data),
            Option::IaAddr(inner) => inner.copy_into(data),
            Option::OptionRequest(inner) => inner.copy_into(data),
            Option::ElapsedTime(inner) => inner.copy_into(data),
            Option::Status(inner) => inner.copy_into(data),
            Option::RapidCommit => unreachable!(),
            Option::DnsServers(inner) => inner.copy_into(data),
            Option::DomainList(inner) => {
                data[..inner.len()].copy_from_slice(inner);
                Ok(())
            }
            Option::SntpServers(inner) => inner.copy_into(data),
            Option::Other { data: d, .. } => d.copy_into(data),
        }
    }

    /// Parse out an Option from a byte array, if possible.
    pub fn from_bytes(buf: &'a [u8]) -> Result<Self, Error> {
        // Options must have a type / length.
        if buf.len() < Self::DATA_START {
            return Err(Error::Truncated);
        }

        // Sanity check the option-data length.
        //
        // Safety: The unwraps are safe since we above check that the buffer has
        // at least the code and length.
        let code =
            Code::from(u16::from_be_bytes(buf[Self::CODE].try_into().unwrap()));
        let len = u16::from_be_bytes(buf[Self::LEN].try_into().unwrap());
        let ulen = usize::from(len);
        if buf.len() < Self::DATA_START + ulen {
            return Err(Error::Truncated);
        }

        // Check for the Rapid Commit option first. The indexing below is
        // invalid in that case, since the option-data is actually empty.
        if matches!(code, Code::RapidCommit) {
            return Ok(Option::RapidCommit);
        }

        let indices = Self::DATA_START..(Self::DATA_START + ulen);
        let data = &buf[indices];
        match code {
            Code::ClientId => Ok(Option::ClientId(Duid(data.into()))),
            Code::ServerId => Ok(Option::ServerId(Duid(data.into()))),
            Code::IaNa => IaNa::from_bytes(data).map(Option::IaNa),
            Code::IaTa => IaTa::from_bytes(data).map(Option::IaTa),
            Code::IaAddr => IaAddr::from_bytes(data).map(Option::IaAddr),
            Code::OptionRequest => {
                OptionRequest::from_bytes(data).map(Option::OptionRequest)
            }
            Code::ElapsedTime => {
                data.try_into().map_err(|_| Error::Truncated).map(|t| {
                    Option::ElapsedTime(ElapsedTime(u16::from_be_bytes(t)))
                })
            }
            Code::StatusCode => Status::from_bytes(data).map(Option::Status),
            Code::RapidCommit => unreachable!(),
            Code::DnsServers => {
                IpList::from_bytes(data).map(Option::DnsServers)
            }
            Code::DomainList => Ok(Option::DomainList(data.into())),
            Code::SntpServers => {
                IpList::from_bytes(data).map(Option::SntpServers)
            }
            Code::Other(_) => {
                Ok(Option::Other { code, data: RawOption(data.into()) })
            }
        }
    }
}

// Build a DomainList option from a list of `DomainName`s.
impl<'a> From<&'a [DomainName]> for Option<'a> {
    fn from(list: &'a [DomainName]) -> Self {
        let mut bytes = Vec::new();
        for name in list.iter() {
            bytes.extend_from_slice(name.encode());
        }
        Option::DomainList(Cow::from(bytes))
    }
}

/// An Information Association of a single IPv6 address.
///
/// This option contains one IP address leased to a client. It's encapsulated in
/// either an `IaNa` or `IaTa` option.
#[derive(Clone, Debug, PartialEq)]
pub struct IaAddr<'a> {
    pub addr: Ipv6Addr,
    pub preferred: Lifetime,
    pub valid: Lifetime,
    pub options: Vec<Option<'a>>,
}

impl<'a> IaAddr<'a> {
    const ADDR: Range<usize> = 0..16;
    const PREF: Range<usize> = 16..20;
    const VALID: Range<usize> = 20..24;
    const OPTIONS: usize = 24;

    pub fn infinite_lease(addr: Ipv6Addr) -> Self {
        Self {
            addr,
            preferred: Lifetime::infinite(),
            valid: Lifetime::infinite(),
            options: vec![],
        }
    }

    fn option_len(&self) -> usize {
        self.options.iter().map(|x| x.buffer_len()).sum()
    }

    fn buffer_len(&self) -> usize {
        self.addr.len() + size_of::<Lifetime>() * 2 + self.option_len()
    }

    fn copy_into(&self, buf: &mut [u8]) -> Result<(), Error> {
        if buf.len() < self.buffer_len() {
            return Err(Error::Truncated);
        }
        buf[Self::ADDR].copy_from_slice(&self.addr);
        buf[Self::PREF].copy_from_slice(&self.preferred.0.to_be_bytes());
        buf[Self::VALID].copy_from_slice(&self.valid.0.to_be_bytes());

        let mut start = Self::OPTIONS;
        for opt in &self.options {
            let len = opt.buffer_len();
            opt.copy_into(&mut buf[start..start + len])?;
            start += len;
        }
        Ok(())
    }

    fn from_bytes(buf: &'a [u8]) -> Result<Self, Error> {
        if buf.len() < Self::OPTIONS {
            return Err(Error::Truncated);
        }

        // Safety: The length check above guarantees we have enough bytes here.
        let arr: [u8; 16] = buf[Self::ADDR].try_into().unwrap();
        let addr = Ipv6Addr::from(arr);

        // Safety: The length check above guarantees we have enough bytes here.
        let arr = buf[Self::PREF].try_into().unwrap();
        let preferred = Lifetime(u32::from_be_bytes(arr));
        let arr = buf[Self::VALID].try_into().unwrap();
        let valid = Lifetime(u32::from_be_bytes(arr));

        let mut options = Vec::new();
        let mut start = Self::OPTIONS;
        while start < buf.len() {
            let opt = Option::from_bytes(&buf[start..])?;
            start += opt.buffer_len();
            options.push(opt);
        }
        Ok(Self { addr, preferred, valid, options })
    }
}

/// An Identity Association for a Non-Temporary Address.
///
/// This option encapsulates an IP address leased to a client by a server.
#[derive(Clone, Debug, PartialEq)]
pub struct IaNa<'a> {
    /// The ID for this IA.
    pub id: IaId,
    /// The time interval after which the client should contact the server that
    /// leased the address to renew it or lease a new one.
    pub t1: Lifetime,
    /// The time interval after which the client should contact _any_ server to
    /// lease a new address.
    pub t2: Lifetime,
    /// The data for this option. The most prominent case is the `IaAddr`
    /// option, which has the actual IP address, though technically others can
    /// be included as well.
    pub options: Vec<Option<'a>>,
}

impl<'a> IaNa<'a> {
    const ID: Range<usize> = 0..4;
    const T1: Range<usize> = 4..8;
    const T2: Range<usize> = 8..12;
    const OPTIONS: usize = 12;

    pub fn infinite_lease(addr: Ipv6Addr) -> Self {
        let ia_addr = IaAddr::infinite_lease(addr);
        Self {
            id: IANA_ID,
            t1: Lifetime::infinite(),
            t2: Lifetime::infinite(),
            options: vec![Option::IaAddr(ia_addr)],
        }
    }

    fn buffer_len(&self) -> usize {
        let option_len: usize =
            self.options.iter().map(|x| x.buffer_len()).sum();
        size_of::<IaId>() + 2 * size_of::<Lifetime>() + option_len
    }

    fn from_bytes(buf: &'a [u8]) -> Result<Self, Error> {
        if buf.len() < Self::OPTIONS {
            return Err(Error::Truncated);
        }
        // Safety: We've just confirmed there are at least 12 bytes, so the
        // below unwraps are all safe.
        let id = IaId(u32::from_be_bytes(buf[Self::ID].try_into().unwrap()));
        let t1 =
            Lifetime(u32::from_be_bytes(buf[Self::T1].try_into().unwrap()));
        let t2 =
            Lifetime(u32::from_be_bytes(buf[Self::T2].try_into().unwrap()));

        // Parse out any embedded options.
        //
        // This should include an IAAddr, but who knows.
        let mut start = Self::OPTIONS;
        let mut options = Vec::new();
        while start < buf.len() {
            let next_option = Option::from_bytes(&buf[start..])?;
            start += next_option.buffer_len();
            options.push(next_option);
        }
        Ok(Self { id, t1, t2, options })
    }

    fn copy_into(&self, buf: &mut [u8]) -> Result<(), Error> {
        if buf.len() < self.buffer_len() {
            return Err(Error::Truncated);
        }
        let id = self.id.0.to_be_bytes();
        buf[Self::ID].copy_from_slice(&id);
        let t1 = self.t1.0.to_be_bytes();
        buf[Self::T1].copy_from_slice(&t1);
        let t2 = self.t2.0.to_be_bytes();
        buf[Self::T2].copy_from_slice(&t2);
        let mut i = Self::OPTIONS;
        for opt in &self.options {
            opt.copy_into(&mut buf[i..])?;
            i += opt.buffer_len();
        }
        Ok(())
    }
}

/// An Identity Association for a Temporary Address.
///
/// Temporary addresses are part of SLAAC, see [RFC 4941] for more
/// details.
///
/// [RFC 4941]: https://www.rfc-editor.org/rfc/rfc4941
#[derive(Clone, Debug, PartialEq)]
pub struct IaTa<'a> {
    pub id: IaId,
    pub options: Vec<Option<'a>>,
}

impl<'a> IaTa<'a> {
    const ID: Range<usize> = 0..4;
    const OPTIONS: usize = 4;

    pub fn new(addr: Ipv6Addr) -> Self {
        let ia_addr = IaAddr::infinite_lease(addr);
        Self { id: IATA_ID, options: vec![Option::IaAddr(ia_addr)] }
    }

    fn option_len(&self) -> usize {
        self.options.iter().map(|x| x.buffer_len()).sum()
    }

    fn buffer_len(&self) -> usize {
        size_of::<IaId>() + self.option_len()
    }

    fn from_bytes(buf: &'a [u8]) -> Result<Self, Error> {
        if buf.len() < Self::OPTIONS {
            return Err(Error::Truncated);
        }
        // Safety: We've just confirmed there are at least 4 bytes, so the
        // below unwrap is safe.
        let id = IaId(u32::from_be_bytes(buf[Self::ID].try_into().unwrap()));

        // Parse out any embedded options.
        //
        // This should include an IAAddr, but who knows.
        let mut start = Self::OPTIONS;
        let mut options = Vec::new();
        while start < buf.len() {
            let next_option = Option::from_bytes(&buf[start..])?;
            start += next_option.buffer_len();
            options.push(next_option);
        }
        Ok(Self { id, options })
    }

    fn copy_into(&self, buf: &mut [u8]) -> Result<(), Error> {
        if buf.len() < self.buffer_len() {
            return Err(Error::Truncated);
        }
        let id = self.id.0.to_be_bytes();
        buf[Self::ID].copy_from_slice(&id);
        let mut i = Self::OPTIONS;
        for opt in &self.options {
            opt.copy_into(&mut buf[i..])?;
            i += opt.buffer_len();
        }
        Ok(())
    }
}

/// An Option Request option is a list of option-codes.
///
/// This is used by clients to request particular Options from the server. In
/// some cases, those options are themselves written into the message. E.g., for
/// an IANA, clients write out the full option including code, length, and data.
///
/// For others, such as DNS serves, clients request that but including its
/// option-code in an Option Request option.
///
/// See [RFC 8415 Table 4] for the list of options that must or must
/// not be included in an OptionRequest.
///
/// [RFC 8415 Table 4]: https://www.rfc-editor.org/rfc/rfc8415.html#section-24
#[derive(Clone, Debug, PartialEq)]
pub struct OptionRequest<'a>(pub Cow<'a, [Code]>);

impl<'a> OptionRequest<'a> {
    pub fn contains(&self, code: Code) -> bool {
        self.0.contains(&code)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Code> {
        self.0.iter()
    }

    fn buffer_len(&self) -> usize {
        self.0.len() * Code::SIZE
    }

    fn copy_into(&self, buf: &'a mut [u8]) -> Result<(), Error> {
        if buf.len() < self.buffer_len() {
            return Err(Error::Truncated);
        }
        let mut start = 0;
        let mut end = Code::SIZE;
        for code in self.0.iter() {
            let bytes = u16::from(*code).to_be_bytes();
            buf[start..end].copy_from_slice(&bytes);
            start = end;
            end += Code::SIZE;
        }
        Ok(())
    }

    fn from_bytes(buf: &'a [u8]) -> Result<Self, Error> {
        if buf.len() % Code::SIZE != 0 {
            return Err(Error::Truncated);
        }
        let count = buf.len() / Code::SIZE;
        let mut codes = Vec::with_capacity(count);
        for i in 0..count {
            let word = u16::from_be_bytes([
                buf[Code::SIZE * i],
                buf[Code::SIZE * i + 1],
            ]);
            codes.push(Code::from(word));
        }
        Ok(Self(Cow::from(codes)))
    }
}

/// The Elapsed Time option must be included in client messages, and provides
/// the time (in units of 10ms) since the client began the current transaction.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ElapsedTime(pub u16);

impl ElapsedTime {
    fn buffer_len(&self) -> usize {
        size_of::<u16>()
    }

    fn copy_into(&self, buf: &mut [u8]) -> Result<(), Error> {
        if buf.len() < self.buffer_len() {
            return Err(Error::Truncated);
        }
        let x = self.0.to_be_bytes();
        buf[0] = x[0];
        buf[1] = x[1];
        Ok(())
    }

    /// Return the Duration this elapsed time represents.
    pub fn as_duration(&self) -> core::time::Duration {
        core::time::Duration::from_millis(self.0 as u64 * 10)
    }
}

/// A status code contained in a Status option.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum StatusCode {
    Success,
    UnspecFail,
    NoAddrsAvail,
    NoBinding,
    NotOnLink,
    UseMulticast,
    NoPrefixAvail,
    Other(u16),
}

impl From<u16> for StatusCode {
    fn from(x: u16) -> Self {
        use StatusCode::*;
        match x {
            0 => Success,
            1 => UnspecFail,
            2 => NoAddrsAvail,
            3 => NoBinding,
            4 => NotOnLink,
            5 => UseMulticast,
            6 => NoPrefixAvail,
            x => Other(x),
        }
    }
}

impl From<StatusCode> for u16 {
    fn from(code: StatusCode) -> u16 {
        use StatusCode::*;
        match code {
            Success => 0,
            UnspecFail => 1,
            NoAddrsAvail => 2,
            NoBinding => 3,
            NotOnLink => 4,
            UseMulticast => 5,
            NoPrefixAvail => 6,
            Other(x) => x,
        }
    }
}

/// A Status Option indicates the status of the thing it's contained in. If
/// that's a standalone option, it's the status of the message; if in another
/// option, the status of that option.
#[derive(Clone, Debug, PartialEq)]
pub struct Status<'a> {
    pub code: StatusCode,
    pub message: &'a str,
}

impl<'a> Status<'a> {
    const CODE: Range<usize> = 0..2;
    const MSG: usize = 2;

    fn buffer_len(&self) -> usize {
        size_of::<u16>() + self.message.len()
    }

    fn copy_into(&self, buf: &mut [u8]) -> Result<(), Error> {
        if buf.len() < self.buffer_len() {
            return Err(Error::Truncated);
        }
        let code = u16::from(self.code).to_be_bytes();
        buf[0] = code[0];
        buf[1] = code[1];
        buf[2..].copy_from_slice(self.message.as_bytes());
        Ok(())
    }

    fn from_bytes(buf: &'a [u8]) -> Result<Self, Error> {
        if buf.len() < Self::MSG {
            return Err(Error::Truncated);
        }
        // Safety: The condition above guarantees there are enough bytes for
        // this unwrap to not panic.
        let code = StatusCode::from(u16::from_be_bytes(
            buf[Self::CODE].try_into().unwrap(),
        ));

        // Take any further bytes as the status message.
        let message = from_utf8(buf.get(Self::MSG..).unwrap_or(&[]))
            .map_err(|_| Error::InvalidData)?;
        Ok(Self { code, message })
    }
}

/// A list of IPv6 addresses.
///
/// This is used in DNS Server options, and others where just a list of addresses
/// is required.
#[derive(Clone, Debug, PartialEq)]
pub struct IpList<'a>(pub Cow<'a, [Ipv6Addr]>);

impl<'a> From<&'a [Ipv6Addr]> for IpList<'a> {
    fn from(addrs: &'a [Ipv6Addr]) -> Self {
        Self(Cow::from(addrs))
    }
}

impl<'a> IpList<'a> {
    fn buffer_len(&self) -> usize {
        size_of::<Ipv6Addr>() * self.0.len()
    }

    fn from_bytes(buf: &'a [u8]) -> Result<Self, Error> {
        const SIZE: usize = size_of::<Ipv6Addr>();
        if buf.len() % SIZE != 0 {
            return Err(Error::Truncated);
        }
        let count = buf.len() / SIZE;
        let mut start = 0;
        let mut addrs = Vec::with_capacity(count);
        while start < buf.len() {
            let arr: [u8; SIZE] = buf[start..start + SIZE]
                .try_into()
                .map_err(|_| Error::Truncated)?;
            start += SIZE;
            addrs.push(Ipv6Addr::from(arr));
        }
        Ok(Self(Cow::from(addrs)))
    }

    fn copy_into(&self, buf: &mut [u8]) -> Result<(), Error> {
        const SIZE: usize = size_of::<Ipv6Addr>();
        if buf.len() < self.buffer_len() {
            return Err(Error::Truncated);
        }
        let mut start = 0;
        let mut end = SIZE;
        for addr in self.0.iter() {
            buf[start..end].copy_from_slice(addr);
            start = end;
            end += SIZE;
        }
        Ok(())
    }

    // pub fn to_owned(&self) -> IpList<'static> {
    //     Self(self.0.to_owned())
    // }
}

#[cfg(test)]
mod test {
    use super::Code;
    use super::DomainName;
    use super::Duid;
    use super::ElapsedTime;
    use super::IaNa;
    use super::IaTa;
    use super::IpList;
    use super::Ipv6Addr;
    use super::Lifetime;
    use super::Option;
    use super::OptionRequest;
    use super::Status;
    use super::StatusCode;
    use crate::engine::dhcpv6::test_data;

    #[test]
    fn test_iana() {
        let addr = Ipv6Addr::from_const([0xfd00, 0, 0, 0, 1, 2, 3, 4]);
        let iana = IaNa::infinite_lease(addr);
        assert_eq!(iana.id, super::IANA_ID);
        let opt = &iana.options[0];
        if let Option::IaAddr(inner) = &opt {
            assert_eq!(inner.addr, addr);
            assert_eq!(inner.preferred, Lifetime::infinite());
            assert_eq!(inner.valid, Lifetime::infinite());
            assert!(inner.options.is_empty());
        } else {
            panic!("Expected an IaAddr option");
        }

        let opt = Option::IaNa(iana);
        let mut buf = vec![0; opt.buffer_len()];
        opt.copy_into(&mut buf).unwrap();
        let new = Option::from_bytes(&buf).unwrap();
        assert_eq!(opt, new);
    }

    #[test]
    fn test_iata() {
        let addr = Ipv6Addr::from_const([0xfd00, 0, 0, 0, 1, 2, 3, 4]);
        let iata = IaTa::new(addr);
        let opt = Option::IaTa(iata);
        let mut buf = vec![0; opt.buffer_len()];
        opt.copy_into(&mut buf).unwrap();
        let new = Option::from_bytes(&buf).unwrap();
        assert_eq!(opt, new);
    }

    #[test]
    fn test_raw_option_from_bytes() {
        let original_data = &[0, 1, 2, 3];
        let mut buf = vec![0u8; 4 + original_data.len()];
        buf[1] = 200;
        buf[3] = original_data.len() as u8;
        buf[4..].copy_from_slice(original_data);

        let opt = Option::from_bytes(&buf).unwrap();
        if let Option::Other { code, data } = &opt {
            assert_eq!(code, code);
            assert_eq!(data.0, original_data.as_ref());
        } else {
            panic!("Expected a raw option");
        }

        let mut out = vec![0; opt.buffer_len()];
        opt.copy_into(&mut out).unwrap();
        assert_eq!(buf, out);
    }

    #[test]
    fn test_client_id() {
        let duid = Duid(vec![0, 1, 2].into());
        let id = Option::ClientId(duid.clone());

        let mut buf = vec![0u8; id.buffer_len()];
        id.copy_into(&mut buf).unwrap();

        let opt = Option::from_bytes(&buf).unwrap();
        assert_eq!(opt.code(), Code::ClientId);
        if let Option::ClientId(inner) = &opt {
            assert_eq!(inner, &duid);
        } else {
            panic!("Expected a client ID option");
        }

        let mut out = vec![0; opt.buffer_len()];
        opt.copy_into(&mut out).unwrap();
        assert_eq!(buf, out);
    }

    #[test]
    fn test_server_id() {
        let duid = Duid(vec![0, 1, 2].into());
        let id = Option::ServerId(duid.clone());

        let mut buf = vec![0u8; id.buffer_len()];
        id.copy_into(&mut buf).unwrap();

        let opt = Option::from_bytes(&buf).unwrap();
        assert_eq!(opt.code(), Code::ServerId);
        if let Option::ServerId(inner) = &opt {
            assert_eq!(inner, &duid);
        } else {
            panic!("Expected a server ID option");
        }

        let mut out = vec![0; opt.buffer_len()];
        opt.copy_into(&mut out).unwrap();
        assert_eq!(buf, out);
    }

    #[test]
    fn test_status() {
        let message = "an error message";
        let code = StatusCode::UnspecFail;
        let sts = Status { code, message };
        let opt = Option::Status(sts);

        let mut buf = vec![0; opt.buffer_len()];
        opt.copy_into(&mut buf).unwrap();

        let new = Option::from_bytes(&buf).unwrap();
        assert_eq!(opt, new);
        if let Option::Status(s) = &new {
            assert_eq!(s.code, code);
            assert_eq!(s.message, message);
        } else {
            panic!("Expected a Status option");
        }
    }

    #[test]
    fn test_elapsed_time() {
        let time = ElapsedTime(100);
        let opt = Option::ElapsedTime(time);

        let mut buf = vec![0; opt.buffer_len()];
        opt.copy_into(&mut buf).unwrap();

        let new = Option::from_bytes(&buf).unwrap();
        assert_eq!(opt, new);
        if let Option::ElapsedTime(t) = &opt {
            assert_eq!(t.0, time.0);
        } else {
            panic!("Expected an Elapsed Time option");
        }
    }

    #[test]
    fn test_rapid_commit() {
        let opt = Option::RapidCommit;
        let mut buf = vec![0; opt.buffer_len()];
        opt.copy_into(&mut buf).unwrap();
        let new = Option::from_bytes(&buf).unwrap();
        assert_eq!(opt, new);
    }

    #[test]
    fn test_ip_list_bad_length_fails() {
        let buf = [0u8; std::mem::size_of::<Ipv6Addr>() + 1];
        assert!(IpList::from_bytes(&buf).is_err());
    }

    #[test]
    fn test_dns_servers() {
        let addrs = vec![
            Ipv6Addr::from_const([0xfd00, 0, 0, 0, 0, 0, 0, 1]),
            Ipv6Addr::from_const([0xfd00, 0, 0, 0, 0, 0, 0, 2]),
        ];
        let opt = Option::DnsServers(IpList(addrs.into()));

        let mut buf = vec![0; opt.buffer_len()];
        opt.copy_into(&mut buf).unwrap();
        let new = Option::from_bytes(&buf).unwrap();
        assert_eq!(opt, new);
    }

    #[test]
    fn test_sntp_servers() {
        let addrs = vec![
            Ipv6Addr::from_const([0xfd00, 0, 0, 0, 0, 0, 0, 1]),
            Ipv6Addr::from_const([0xfd00, 0, 0, 0, 0, 0, 0, 2]),
        ];
        let opt = Option::SntpServers(IpList(addrs.into()));

        let mut buf = vec![0; opt.buffer_len()];
        opt.copy_into(&mut buf).unwrap();
        let new = Option::from_bytes(&buf).unwrap();
        assert_eq!(opt, new);
    }

    #[test]
    fn test_option_request() {
        let codes = [Code::SntpServers, Code::DomainList, Code::Other(100)];
        let opt = Option::OptionRequest(OptionRequest(codes.as_slice().into()));
        let mut buf = vec![0; opt.buffer_len()];
        opt.copy_into(&mut buf).unwrap();
        let new = Option::from_bytes(&buf).unwrap();
        assert_eq!(opt, new);
    }

    #[test]
    fn test_parse_snooped_iana() {
        let opt =
            Option::from_bytes(test_data::test_solicit_packet_iana()).unwrap();
        if let Option::IaNa(inner) = opt {
            assert_eq!(inner.id.0, 0x25fadd0b);
            assert_eq!(inner.t1.0, 3600);
            assert_eq!(inner.t2.0, 5400);
        } else {
            panic!("Expected an IANA");
        }
    }

    #[test]
    fn test_parse_snooped_option_request() {
        let opt =
            Option::from_bytes(test_data::test_solicit_packet_option_request())
                .unwrap();
        if let Option::OptionRequest(inner) = opt {
            assert!(inner.contains(Code::DnsServers));
            assert!(inner.contains(Code::DomainList));
            assert!(inner.contains(Code::SntpServers));
            assert!(inner.contains(Code::Other(0x27)));
        } else {
            panic!("Expected an Option Request");
        }
    }

    #[test]
    fn test_parse_snooped_client_id() {
        let opt =
            Option::from_bytes(test_data::test_solicit_packet_client_id())
                .unwrap();
        if let Option::ClientId(duid) = opt {
            assert_eq!(duid.0, test_data::test_solicit_packet_client_duid());
        } else {
            panic!("Expected a Client ID");
        }
    }

    #[test]
    fn test_domain_list_from_slice() {
        let list = [
            "foo.bar.com".parse::<DomainName>().unwrap(),
            "something".parse::<DomainName>().unwrap(),
            "another.fqdn.".parse::<DomainName>().unwrap(),
        ];
        let opt = Option::from(list.as_slice());
        let Option::DomainList(bytes) = &opt else {
            panic!("Expected a DomainList");
        };
        let mut index = 0;
        for name in list.iter() {
            let enc = name.encode();
            assert_eq!(enc, &bytes[index..][..enc.len()]);
            index += enc.len();
        }

        let expected_len: usize =
            list.iter().map(|name| name.encode().len()).sum();
        assert_eq!(opt.data_len(), expected_len);
        assert_eq!(opt.buffer_len(), expected_len + 4); // Option code and len
    }
}
