// stuff we need from dld

use illumos_ddi_dki::{c_int, c_uint, c_void, cred_t, intptr_t, size_t};

pub const XDE_IOC: u16 = 0xde00;

pub const DLDCOPYIN: u32 = 0x00000001;
pub const DLDCOPYOUT: u32 = 0x00000002;
pub const DLDCOPYINOUT: u32 = DLDCOPYIN | DLDCOPYOUT;

#[repr(C)]
#[derive(Debug)]
pub struct dld_ioc_info_t {
    pub di_cmd: c_uint,
    pub di_flags: c_uint,
    pub di_argsize: size_t,

    pub di_func: unsafe extern "C" fn(
        *mut c_void,
        intptr_t,
        c_int,
        *mut cred_t,
        *mut c_int,
    ) -> c_int,

    pub di_priv_func: unsafe extern "C" fn(*const cred_t) -> c_int,
}

extern "C" {
    // data link driver (DLD)
    pub fn dld_ioc_register(
        modid: u16,
        list: *const dld_ioc_info_t,
        count: c_uint,
    ) -> c_int;

    pub fn dld_ioc_unregister(modid: u16);
}
