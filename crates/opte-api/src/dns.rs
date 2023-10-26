// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Types related to DNS and advertisement of DNS options to clients.

use alloc::str;
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::fmt;
use core::str::FromStr;
use serde::Deserialize;
use serde::Serialize;

/// A DNS domain name, which can be encoded in the label-sequence format of RFC
/// 1035 section 3.1.
///
/// # Requirements
///
/// It's recommended that domain names follow the LDH rule: only ASCII letters,
/// digits, and hyphens, and not starting with a hyphen. However, this is not
/// currently enforced, and the domain name is just a UTF-8 string. No other
/// encoding is enforced.
///
/// The only other enforcements are currently around length:
///
/// - The string form of the name may not exceed 253 octets
/// - Each label (except for possibly the last, root label) must be between 1
/// and 63 octets.
///
/// # Details
///
/// A DNS domain name is a sequence of labels. Colloquially, this is a string
/// like `foo.bar.com.`. When specified as in a domain search list on a system,
/// this allows tools like `ping` to use items from the list when they are
/// provided just a hostname.
///
/// For example, given:
///
/// ```console
/// $ ping baz
/// ```
///
/// and the above domain name in its search list, `ping` will try to resolve the
/// host `baz.foo.bar.com` before sending IP packets.
///
/// Each of the strings separated by `.` is a "label". In the standard format of
/// RFC 1035 section 3.1 each label is prefixed by a single octet describing its
/// length. All label sequences technically end with the "root label", a bare
/// ".", which is encoded as a length octet of zero. Thus all DNS domains are
/// null terminated.
///
/// There are also length requirements: Each label cannot be more than 63 octets
/// long; and the total length cannot be more than 255 octets.
///
/// # Notes
///
/// Technically, labels can contain any octets. However, DNS servers are
/// required to compare labels without considering case, assuming ASCII with
/// zero parity. (See RFC 1035 section 3.1, final paragraph.)
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DomainName {
    // The original, parsed string.
    name: String,
    // The name encoded according to RFC 1035 sec 3.1.
    encoded: Vec<u8>,
}

impl DomainName {
    const MAX_STR_LEN: usize = 253;
    const MAX_ENCODED_LEN: usize = 255;
    const MAX_LABEL_LEN: usize = 63;

    /// Encode the full domain name in the format prescribed by RFC 1035 section
    /// 3.1.
    ///
    /// # Example
    ///
    /// ```rust
    /// use opte_api::DomainName;
    /// let n: DomainName = "quuz.bar.com".parse().unwrap();
    /// assert_eq!(n.encode(), b"\x04quuz\x03bar\x03com\x00");
    /// ```
    pub fn encode(&self) -> &[u8] {
        self.encoded.as_slice()
    }

    /// Return the validated domain name string.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl TryFrom<&[u8]> for DomainName {
    type Error = &'static str;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        // Sanity check the size of the buffer.
        //
        // From RFC 1035, section 3.1, this is limited to 255 octets.
        if buf.len() > Self::MAX_ENCODED_LEN || buf.is_empty() {
            return Err("Encoded domain name too long or empty");
        }

        // Pull out each label length, then the label itself.
        let mut start: u8 = 0;
        let mut name = String::new();
        loop {
            let Some(&len) = buf.get(usize::from(start)) else {
                return Err("Invalid label length");
            };

            // Root label has zero length.
            if len == 0 {
                break;
            }

            // The name starts on the next octet. Check that the end is within a
            // u8 and the length of the string!
            start += 1;
            let Some(end) = start.checked_add(len) else {
                return Err("Invalid label length");
            };
            let Some(chunk) = buf.get(usize::from(start)..usize::from(end))
            else {
                return Err("Invalid label length");
            };

            // Push the label and _then_ the label-separator.
            let Ok(label) = str::from_utf8(chunk) else {
                return Err("Non-UTF8 label");
            };
            name.push_str(label);
            name.push('.');

            // Off to the next label.
            start += len;
        }

        // Take an owned copy of the prefix of `buf` that we've decoded.
        //
        // We break the above loop when `len == 0`, at which point `start`
        // points to the root label's length octet of zero. So we clone from the
        // beginning to that `start` offset, _inclusive_.
        //
        // Safety: This can't panic because we only break the above loop if we
        // can successfully index at `buf[start]`.
        let encoded = buf[..=usize::from(start)].to_vec();

        // We've already pushed the root label separator, since we push `'.'`
        // after each label, including the last, before breaking.
        Ok(Self { encoded, name })
    }
}

impl FromStr for DomainName {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > Self::MAX_STR_LEN || s.is_empty() {
            return Err("Domain name too long or empty");
        }
        if s.starts_with('.') {
            return Err("Domain name cannot start with '.'");
        }

        // Pull out a possible `.` at the very end, and handle that separately.
        let relative_name = s.trim_end_matches('.');

        // Split out each label, and create the encoded form.
        //
        // The length of the encoded form is the length of `s`, plus 1 for the
        // length octet for the first label, plus 1 if the domain name is
        // fully-qualified and 0 otherwise (since the last `.` is _replaced_
        // with the root label length of 0).
        let encoded_len = s.len() + 1 + usize::from(!s.ends_with('.'));
        let mut encoded = Vec::with_capacity(encoded_len);
        for label in relative_name.split('.') {
            if label.is_empty() || label.len() > Self::MAX_LABEL_LEN {
                return Err("Label empty or too long");
            }
            encoded.push(label.len() as u8);
            encoded.extend_from_slice(label.as_bytes());
        }

        // Push final "length" for the root label.
        encoded.push(0);
        Ok(Self { name: String::from(s), encoded })
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::DomainName;

    #[test]
    fn test_domain_name() {
        // String and expected encoding.
        let orig = "foo.bar.com";
        let encoded = b"\x03foo\x03bar\x03com\x00";

        // Check parsing and API
        let name: DomainName = orig.parse().unwrap();
        assert_eq!(format!("{name}"), orig);
        assert_eq!(name.name(), orig);
        assert_eq!(name.encode(), encoded);

        // Check we can reconstruct the same thing out of encoded bytes.
        let from_encoded = DomainName::try_from(encoded.as_slice()).unwrap();
        assert_eq!(from_encoded.name(), format!("{orig}."));
        assert_eq!(from_encoded.encode(), encoded);

        // Should support FQDNs
        assert!("foo.bar.com.".parse::<DomainName>().is_ok());

        // Malformed
        assert!("a".repeat(256).parse::<DomainName>().is_err());
        assert!(".foo.bar".parse::<DomainName>().is_err());
        assert!("foo..bar".parse::<DomainName>().is_err());
        assert!(DomainName::try_from(b"\xffnonono".as_slice()).is_err());

        // Check that we only take a prefix, if a larger slice is provided.
        let encoded = b"\x03foo\x03bar\x03com\x00someextrabytes";
        let prefix_name = DomainName::try_from(encoded.as_slice()).unwrap();
        assert_eq!(prefix_name.name(), format!("{orig}."));
        assert_eq!(prefix_name.encode(), &encoded[..(3 + 1) * 3 + 1]);
    }
}
