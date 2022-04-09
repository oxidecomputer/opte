#![no_std]

// NOTE: Things get weird if you move the extern crate into cfg_if!.
#[cfg(any(feature = "std", test))]
#[macro_use]
extern crate std;

#[cfg(all(not(feature = "std"), not(test)))]
#[macro_use]
extern crate alloc;

#[macro_use]
extern crate cfg_if;

cfg_if! {
    if #[cfg(all(not(feature = "std"), not(test)))] {
        use core::result;
        use alloc::string::String;
    } else {
        use std::result;
        use std::str::FromStr;
        use std::string::{String, ToString};
        use std::vec::Vec;
    }
}

use core::fmt::{self, Display};
use serde::{Deserialize, Serialize};

use illumos_sys_hdrs::{c_int, datalink_id_t, size_t};


