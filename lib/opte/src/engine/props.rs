// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! Diagnostic property exposure for actions and other engine objects.
//!
//! Inspired by `dladm show-linkprop`, this gives operators a generic way
//! to query the immutable configuration of an action (e.g. the VNI an
//! `EncapAction` is encapsulating into) without `opteadm` needing any
//! per-action knowledge.

pub use opte_api::ActionProperty;

use alloc::string::ToString;
use alloc::vec::Vec;

/// Implemented by anything that wants to expose immutable, read-only,
/// human/machine-friendly configuration to inspection tooling.
///
/// All methods have sensible defaults so types with nothing to report
/// can simply rely on the blanket behavior — no boilerplate, no opt-in
/// derive required.
pub trait ActionProperties {
    /// Names of every property this implementation can return.
    ///
    /// Treated as a stable contract with operators: prefer adding new
    /// names over renaming existing ones.
    fn property_names(&self) -> &'static [&'static str] {
        &[]
    }

    /// Return the value of a single named property, or `None` if the
    /// implementation does not know the name.
    fn get_property(&self, _name: &str) -> Option<alloc::string::String> {
        None
    }

    /// Materialize every `(name, value)` pair this implementation
    /// exposes. The default implementation walks [`Self::property_names`]
    /// and calls [`Self::get_property`] for each entry.
    fn properties(&self) -> Vec<ActionProperty> {
        self.property_names()
            .iter()
            .filter_map(|name| {
                self.get_property(name).map(|value| ActionProperty {
                    name: (*name).to_string(),
                    value,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    /// A test type that exposes a couple of properties.
    struct Sample {
        a: u32,
        b: &'static str,
    }

    impl ActionProperties for Sample {
        fn property_names(&self) -> &'static [&'static str] {
            &["a", "b"]
        }
        fn get_property(&self, name: &str) -> Option<String> {
            use alloc::string::ToString;
            match name {
                "a" => Some(self.a.to_string()),
                "b" => Some(self.b.to_string()),
                _ => None,
            }
        }
    }

    #[test]
    fn default_impl_is_empty() {
        struct Empty;
        impl ActionProperties for Empty {}
        assert!(Empty.properties().is_empty());
        assert!(Empty.get_property("anything").is_none());
        assert!(Empty.property_names().is_empty());
    }

    #[test]
    fn properties_walks_names() {
        let s = Sample { a: 42, b: "hi" };
        let props = s.properties();
        assert_eq!(props.len(), 2);
        assert_eq!(props[0].name, "a");
        assert_eq!(props[0].value, "42");
        assert_eq!(props[1].name, "b");
        assert_eq!(props[1].value, "hi");
    }

    #[test]
    fn get_property_unknown_returns_none() {
        let s = Sample { a: 0, b: "" };
        assert!(s.get_property("nope").is_none());
        assert_eq!(s.get_property("a").as_deref(), Some("0"));
    }
}

