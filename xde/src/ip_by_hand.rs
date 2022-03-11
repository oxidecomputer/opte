// XXX? this file is the beginning of hand crafting the data structures we need
// from the kernel to build an IRE/NCE client. That list turns out to be big and
// for the sake of expediency i'm just using bindgen for the moment. Use of
// bindgen is a tradeoff for sure, the generated code is asthetically aweful but
// it's also less error prone than hand porting data structures.

use illumos_ddi_dki::*;

#[repr(C)]
pub struct ill_s {
    //TODO
}
type ill_t = ill_s;

#[repr(C)]
pub struct ip_recv_attr_s {
    //TODO
}
type ip_recv_attr_t = ip_recv_attr_s;

type pfirerecv_t = unsafe extern "C" fn(
    *mut ire_t,
    *mut mblk_t, 
    *mut c_void, 
    *mut ip_recv_attr_t,
);

#[repr(C)]
pub struct ip_xmit_attr_s {
    //TODO
}
type ip_xmit_attr_t = ip_xmit_attr_s;

type pfiresend_t = unsafe extern "C" fn(
    *mut ire_t,
    *mut mblk_t,
    *mut c_void,
    *mut ip_xmit_attr_t,
    *mut uint32_t,
) -> c_int;

type pfirepostfrag_t = unsafe extern "C" fn(
    *mut mblk_t,
    *mut nce_t,
    iaflags_t,
    uint_t,
    uint32_t,
    zoneid_t,
    zoneid_t,
    *mut uintptr_t,
) -> c_int;

#[repr(C)]
pub struct ire_s {
	ire_next:           *mut ire_s,         /* The hash chain must be first. */
	ire_ptpn:           *mut *mut ire_s,    /* Pointer to previous next. */
	ire_refcnt:         u32,                /* Number of references */
	ire_ill:            *mut ill_t,
	ire_identical_ref:  u32,                /* IRE_INTERFACE, IRE_BROADCAST */
	ire_ipversion:      uchar_t,            /* IPv4/IPv6 version */
	ire_type:           ushort_t,           /* Type of IRE */
	ire_generation:     uint_t,             /* Generation including CONDEMNED */
	ire_ib_pkt_count:   uint_t,             /* Inbound packets for ire_addr */
	ire_ob_pkt_count:   uint_t,             /* Outbound packets to ire_addr */
	ire_create_time:    time_t,             /* Time (in secs) IRE was created. */
	ire_flags:          uint32_t,           /* flags related to route (RTF_*) */

	/*
	 * ire_testhidden is TRUE for INTERFACE IREs of IS_UNDER_IPMP(ill)
	 * interfaces
	 */
	ire_testhidden:     boolean_t,
	ire_recvfn:         pfirerecv_t,                /* Receive side handling */
	ire_sendfn:         pfiresend_t,                /* Send side handling */
	ire_postfragfn:     pfirepostfrag_t,            /* Bottom end of send handling */

	ire_masklen:        uint_t,                     /* # bits in ire_mask{,_v6} */
	ire_u:              ire_addr_u_t,               /* IPv4/IPv6 address info. */

	ire_bucket:         *mut irb_t,                 /* Hash bucket when ire_ptphn is set */
	ire_lock:           kmutex_t,
	ire_last_used_time: clock_t,                    /* For IRE_LOCAL reception */
	ire_gw_secattr:     *mut tsol_ire_gw_secattr_t, /* gateway security attributes */
	ire_zoneid:         zoneid_t,

	/*
	 * Cached information of where to send packets that match this route.
	 * The ire_dep_* information is used to determine when ire_nce_cache
	 * needs to be updated.
	 * ire_nce_cache is the fastpath for the Neighbor Cache Entry
	 * for IPv6; arp info for IPv4
	 * Since this is a cache setup and torn down independently of
	 * applications we need to use nce_ref{rele,hold}_notr for it.
	 */
	ire_nce_cache:  *mut nce_t,

	/*
	 * Quick check whether the ire_type and ire_masklen indicates
	 * that the IRE can have ire_nce_cache set i.e., whether it is
	 * IRE_ONLINK and for a single destination.
	 */
	ire_nce_capable:    boolean_t,

	/*
	 * Dependency tracking so we can safely cache IRE and NCE pointers
	 * in offlink and onlink IREs.
	 * These are locked under the ips_ire_dep_lock rwlock. Write held
	 * when modifying the linkage.
	 * ire_dep_parent (Also chain towards IRE for nexthop)
	 * ire_dep_parent_generation: ire_generation of ire_dep_parent
	 * ire_dep_children (From parent to first child)
	 * ire_dep_sib_next (linked list of siblings)
	 * ire_dep_sib_ptpn (linked list of siblings)
	 *
	 * The parent has a ire_refhold on each child, and each child has
	 * an ire_refhold on its parent.
	 * Since ire_dep_parent is a cache setup and torn down independently of
	 * applications we need to use ire_ref{rele,hold}_notr for it.
	 */
	ire_dep_parent:             *mut ire_t,
	ire_dep_children:           *mut ire_t,
	ire_dep_sib_next:           *mut ire_t,
	ire_dep_sib_ptpn;           *mut *mut ire_t,    /* Pointer to previous next */
	ire_dep_parent_generation:  uint_t,

	ire_badcnt:         uint_t,     /* Number of times ND_UNREACHABLE */
	ire_last_badcnt:    uint64_t,   /* In seconds */

	/* ire_defense* and ire_last_used_time are only used on IRE_LOCALs */
	ire_defense_count:  uint_t, /* number of ARP conflicts */
	ire_defense_time:   uint_t, /* last time defended (secs) */

	ire_trace_disable:  boolean_t,          /* True when alloc fails */
	ire_ipst:           *mut ip_stack_t,    /* Does not have a netstack_hold */
	ire_metrics:        iulp_t,

	/*
	 * default and prefix routes that are added without explicitly
	 * specifying the interface are termed "unbound" routes, and will
	 * have ire_unbound set to true.
	 */
	ire_unbound:    boolean_t,
}

type ire_t = ire_s;

extern "C" {

/*
ire_t *
ire_ftable_lookup_v6(const in6_addr_t *addr, const in6_addr_t *mask,
    const in6_addr_t *gateway, int type, const ill_t *ill,
    zoneid_t zoneid, const ts_label_t *tsl, int flags,
    uint32_t xmit_hint, ip_stack_t *ipst, uint_t *generationp)
*/

    pub fn ire_ftable_lookup_v6(
    ) -> *mut ire_t;


}
