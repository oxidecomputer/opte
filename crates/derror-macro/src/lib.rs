// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use darling::FromDeriveInput;
use proc_macro2::TokenStream;
use quote::format_ident;
use quote::quote;
use syn::parse_macro_input;
use syn::DeriveInput;

#[derive(FromDeriveInput)]
#[darling(attributes(derror))]
struct Args {
    leaf_data: Option<syn::Path>,
}

/// Generate a `DError` implementation given a tree-structured enum
/// where only leaf nodes hold additional data.
///
/// This allows for deeply nested enums to be more easily understood in
/// dtrace probes without calling `format!()`.
///
/// This is intended for annotating error chains such as:
/// ```ignore
/// #[derive(DError)]
/// enum SomeErrors {
///     A,
///     B(NestedError),
/// }
///
/// #[derive(DError)]
/// #[derror(leaf_data = data_fn)]
/// enum NestedError {
///     Data1 { val1: u64, val2: u8},
///     #[leaf]
///     Data2(u32),
///     NoData,
/// }
///
/// fn data_fn(val: &NestedError, data: &mut [u8]) {
///     [data[0], data[1]] = match {
///         Self::Data1 { val1, val2 } => [val1 as u64, val2 as u64],
///         Self::Data2(d) => [d as u64, 0],
///         _ => [0, 0],
///     }   
/// }
/// ```
/// The macro will automatically generate `CStrs` for every enum variant
/// and will traverse down all single-element tuple variants unless annotated
/// as `#[leaf]`s. A `leaf_data` function can be specfied to fill in the data
/// segment of an `ErrorBlock`. This is currently fixed as a `[u64; 2]`.
#[proc_macro_derive(DError, attributes(derror, leaf))]
pub fn derive_derror(
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let derive_input = parse_macro_input!(input);

    let parsed_args = match Args::from_derive_input(&derive_input) {
        Ok(o) => o,
        Err(e) => return e.write_errors().into(),
    };

    let DeriveInput { ident, data, .. } = derive_input;

    let syn::Data::Enum(data) = data else {
        panic!("cannot autoderive `DError` for struct or union");
    };

    let mut cstr_decls: Vec<TokenStream> = vec![];
    let mut cstr_arms: Vec<TokenStream> = vec![];
    let mut child_arms: Vec<TokenStream> = vec![];

    for pair in data.variants.into_pairs() {
        let variant = pair.into_value();
        let var_name = variant.ident;

        let static_name = format_ident!("{}_cstr", var_name);
        let mut var_name_bytes = var_name.to_string().into_bytes();
        var_name_bytes.push(0);
        let static_name_val =
            syn::LitByteStr::new(&var_name_bytes, var_name.span());

        // TODO: use c"" once proc_macro_c_str_literals (https://github.com/rust-lang/rust/issues/119750) stabilised.
        cstr_decls.push(quote! {
            static #static_name: &CStr = if let Ok(s) = CStr::from_bytes_with_nul(#static_name_val) {
                s
            } else {
                panic!("Bad cstring constant!")
            };
        });

        let known_leaf =
            variant.attrs.iter().any(|v| v.path().is_ident("leaf"));

        let (cstr_block, child_block) = match variant.fields {
            syn::Fields::Unnamed(fields) => (
                quote! {Self::#var_name(f) => #static_name,},
                if !known_leaf && fields.unnamed.len() == 1 {
                    quote! {
                        Self::#var_name(f) => Some(f),
                    }
                } else {
                    quote! {
                        Self::#var_name(..) => None,
                    }
                },
            ),
            syn::Fields::Named(_) => (
                quote! {
                    Self::#var_name{ .. } => #static_name,
                },
                quote! {
                    Self::#var_name{ .. } => None,
                },
            ),
            syn::Fields::Unit => (
                quote! {
                    Self::#var_name => #static_name,
                },
                quote! {
                    Self::#var_name => None,
                },
            ),
        };

        cstr_arms.push(cstr_block);
        child_arms.push(child_block);
    }

    let leaf_data_impl = if let Some(data_fn) = parsed_args.leaf_data {
        quote! {
            fn leaf_data(&self, data: &mut [u64]) {
                #data_fn(self, data);
            }
        }
    } else {
        quote! {}
    };

    quote! {
        impl DError for #ident {
            #[allow(non_upper_case_globals)]
            fn discriminant(&self) -> &'static ::core::ffi::CStr {
                use ::core::ffi::CStr;
                #( #cstr_decls )*
                match self {
                    #( #cstr_arms )*
                }
            }

            fn child(&self) -> Option<&dyn DError> {
                match self {
                    #( #child_arms )*
                }
            }

            #leaf_data_impl
        }
    }
    .into()
}
