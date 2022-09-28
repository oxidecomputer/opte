// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2022 Oxide Computer Company

use proc_macro::TokenStream;
use quote::format_ident;
use quote::quote;
use syn::parse_macro_input;
use syn::DeriveInput;
use syn::Field;
use syn::FieldsNamed;
use syn::FieldsUnnamed;
use syn::Ident;

/// Generate a [`opte::ddi::kstat::KStatProvider`] implementation
/// given a struct of named fields of type
/// [`opte::ddi::kstat::KStatU64`].
///
/// ```Rust
/// #[derive(KStatProvider)]
/// struct PortStats {
///     in_pkts: KStatU64,
///     out_pkts: KStatU64,
/// }
/// ```
///
/// This macro generates the following code based on the struct above.
///
/// ```Rust
/// impl KStatProvider for PortStats {
///     const NUM_FIELDS: u32 = 2;
///
///     fn init(&mut self) -> result::Result<(), kstat::Error> {
///         self.in_pkts.init("in_pkts")?;
///         self.in_drop.init("out_pkts")?;
///         Ok(())
///     }
///
///     fn new() -> Self {
///         Self {
///             in_pkts: KStatU64::new(),
///             out_pkts: KStatU64::new(),
///         }
///     }
/// }
/// ````
#[proc_macro_derive(KStatProvider)]
pub fn derive_kstat_provider(input: TokenStream) -> TokenStream {
    let DeriveInput { ident, data, .. } = parse_macro_input!(input);
    let fields: Vec<Field> = match data {
        syn::Data::Struct(s) => match s.fields {
            syn::Fields::Named(FieldsNamed { named, .. }) => {
                named.into_iter().collect()
            }

            syn::Fields::Unnamed(FieldsUnnamed { unnamed: _, .. }) => {
                panic!("A KStatProvider cannot have unnamed fields");
            }

            syn::Fields::Unit => {
                panic!("A unit struct cannot be a KStatProvider");
            }
        },

        _ => panic!("Only a struct may be a KStatProvider"),
    };

    let num_fields = fields.len() as u32;
    let fields_ident: Vec<Ident> =
        fields.iter().map(|f| f.ident.clone().unwrap()).collect();
    let ident_snap = format_ident!("{}Snap", ident);

    let output = quote! {
        #[derive(Clone, Debug)]
        pub struct #ident_snap {
            #( pub #fields_ident: u64, )*
        }

        impl KStatProvider for #ident {
            const NUM_FIELDS: u32 = #num_fields;
            type Snap = #ident_snap;

            fn init(
                &mut self
            ) -> core::result::Result<(), kstat::Error> {
                #( self.#fields_ident.init(stringify!(#fields_ident))?; )*
                Ok(())
            }

            fn new() -> Self {
                use ::opte::ddi::kstat::KStatU64;

                Self {
                    #( #fields_ident: KStatU64::new(), )*
                }
            }

            fn snapshot(&self) -> Self::Snap {
                #ident_snap {
                    #( #fields_ident: self.#fields_ident.val(), )*
                }
            }
        }
    };

    output.into()
}
