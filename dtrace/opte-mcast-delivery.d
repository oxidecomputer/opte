/*
 * Track multicast packet delivery through OPTE/XDE.
 *
 * Usage:
 *   dtrace -L ./lib -I . -Cqs ./opte-mcast-delivery.d
 *
 * Configuration (set in BEGIN block):
 *   suppress_output = 1  - Suppress per-event output, show only aggregations
 *   flow_debug = 1       - Enable multicast TX/RX function entry/exit tracing
 *   show_summary = 1     - Show aggregated summary at END (default: enabled)
 */
#include "common.h"

/* Local print formats (avoid colliding with common.h FLOW_FMT macros) */
#define	M_HDR_FMT     "%-12s %-6s %-39s %-39s\n"
#define	M_LINE_FMT    "%-12s %-6u %-39s %-39s\n"
#define	M_FWD_HDR_FMT "%-12s %-6s %-39s %-39s\n"
#define	M_FWD_LINE_FMT "%-12s %-6u %-39s %-39s\n"
#define	DBG_LINE_FMT  "%-20s %-30s %s\n"

/* Macro to reduce code duplication for group address formatting */
#define MCAST_GROUP_STR(af, ptr) \
	((af) == AF_INET ? inet_ntoa((ipaddr_t *)(ptr)) : \
			   inet_ntoa6((in6_addr_t *)(ptr)))

/* Configurable header reprint interval */
#define HEADER_REPRINT_INTERVAL 10

/*
 * OPTE command numbers for multicast-related ioctls (see crates/opte-api/src/cmd.rs).
 */
#define CMD_SET_MCAST_FWD       100
#define CMD_CLEAR_MCAST_FWD     101
#define CMD_DUMP_MCAST_FWD      102
#define CMD_MCAST_SUBSCRIBE     103
#define CMD_MCAST_UNSUBSCRIBE   104
#define CMD_SET_M2P             105
#define CMD_CLEAR_M2P           106
#define CMD_DUMP_MCAST_SUBS     107

BEGIN {
	flow_debug = 0;  /* Set to 1 to enable detailed flow debugging */
	suppress_output = 0;  /* Set to 1 to suppress per-event output (aggregations only) */
	show_summary = 1;  /* Set to 1 to show aggregated summary at END */

	num = 0;

	printf("OPTE Multicast Delivery Tracker\n");
	printf("Configuration:\n");
	printf("  flow_debug      = %d\n", flow_debug);
	printf("  suppress_output = %d\n", suppress_output);
	printf("  show_summary    = %d\n", show_summary);
	printf("\n");
}

BEGIN
/!suppress_output/
{
	printf(M_HDR_FMT, "EVENT", "VNI", "GROUP", "PORT/NEXTHOP");
}

/* Multicast TX function entry/exit (optional detailed debugging) */
xde_mc_tx:entry
/flow_debug/
{
	printf(DBG_LINE_FMT, "xde_mc_tx-entry", "", "");
}

xde_mc_tx:return
/flow_debug/
{
	printf(DBG_LINE_FMT, "xde_mc_tx-return", "", "");
}

mcast-tx {
	/* arg0=af, arg1=addr_ptr, arg2=vni */
	this->af = arg0;
	this->group_ptr = arg1;
	this->vni = arg2;
	this->group_str = MCAST_GROUP_STR(this->af, this->group_ptr);

	/* Always track aggregations (even when suppressing output) */
	@by_event["TX"] = count();
	@by_vni["TX", this->vni] = count();
	@by_group["TX", this->group_str] = count();
}

mcast-tx
/!suppress_output/
{
	if (num >= HEADER_REPRINT_INTERVAL) {
		printf(M_HDR_FMT, "EVENT", "VNI", "GROUP", "PORT/NEXTHOP");
		num = 0;
	}

	printf(M_LINE_FMT, "TX", this->vni, this->group_str, "-");
	num++;
}

mcast-rx {
	/* arg0=af, arg1=addr_ptr, arg2=vni */
	this->af = arg0;
	this->group_ptr = arg1;
	this->vni = arg2;
	this->group_str = MCAST_GROUP_STR(this->af, this->group_ptr);

	/* Always track aggregations (even when suppressing output) */
	@by_event["RX"] = count();
	@by_vni["RX", this->vni] = count();
	@by_group["RX", this->group_str] = count();
}

mcast-rx
/!suppress_output/
{
	if (num >= HEADER_REPRINT_INTERVAL) {
		printf(M_HDR_FMT, "EVENT", "VNI", "GROUP", "PORT/NEXTHOP");
		num = 0;
	}

	printf(M_LINE_FMT, "RX", this->vni, this->group_str, "-");
	num++;
}

mcast-local-delivery {
	/* arg0=af, arg1=addr_ptr, arg2=vni, arg3=port */
	this->af = arg0;
	this->group_ptr = arg1;
	this->vni = arg2;
	this->port = stringof(arg3);
	this->group_str = MCAST_GROUP_STR(this->af, this->group_ptr);

	/* Always track aggregations (even when suppressing output) */
	@by_event["DELIVER"] = count();
	@by_vni["DELIVER", this->vni] = count();
	@by_port[this->port] = count();
	@by_group["DELIVER", this->group_str] = count();
}

mcast-local-delivery
/!suppress_output/
{
	if (num >= HEADER_REPRINT_INTERVAL) {
		printf(M_HDR_FMT, "EVENT", "VNI", "GROUP", "PORT/NEXTHOP");
		num = 0;
	}

	printf(M_LINE_FMT, "DELIVER", this->vni, this->group_str, this->port);
	num++;
}

mcast-underlay-fwd {
	/* arg0=af, arg1=addr_ptr (underlay mcast), arg2=vni, arg3=next_hop (unicast switch) */
	this->af = arg0;
	this->underlay_ptr = arg1;
	this->vni = arg2;
	this->next_hop_unicast = (in6_addr_t *)arg3;
	this->underlay_str = MCAST_GROUP_STR(this->af, this->underlay_ptr);
	this->next_hop_str = inet_ntoa6(this->next_hop_unicast);

	/* Always track aggregations (even when suppressing output) */
	@by_event["UNDERLAY"] = count();
	@by_vni["UNDERLAY", this->vni] = count();
	@by_underlay["UNDERLAY", this->underlay_str] = count();
	@by_nexthop_unicast[this->next_hop_str] = count();
}

mcast-underlay-fwd
/!suppress_output/
{
	if (num >= HEADER_REPRINT_INTERVAL) {
		printf(M_FWD_HDR_FMT, "EVENT", "VNI", "UNDERLAY_MCAST", "ROUTE_UNICAST");
		num = 0;
	}

	printf(M_FWD_LINE_FMT, "UNDERLAY", this->vni, this->underlay_str, this->next_hop_str);
	num++;
}

mcast-external-fwd {
	/* arg0=af, arg1=addr_ptr (underlay mcast), arg2=vni, arg3=next_hop (unicast switch) */
	this->af = arg0;
	this->underlay_ptr = arg1;
	this->vni = arg2;
	this->next_hop_unicast = (in6_addr_t *)arg3;
	this->underlay_str = MCAST_GROUP_STR(this->af, this->underlay_ptr);
	this->next_hop_str = inet_ntoa6(this->next_hop_unicast);

	/* Always track aggregations (even when suppressing output) */
	@by_event["EXTERNAL"] = count();
	@by_vni["EXTERNAL", this->vni] = count();
	@by_underlay["EXTERNAL", this->underlay_str] = count();
	@by_nexthop_unicast[this->next_hop_str] = count();
}

mcast-external-fwd
/!suppress_output/
{
	if (num >= HEADER_REPRINT_INTERVAL) {
		printf(M_FWD_HDR_FMT, "EVENT", "VNI", "UNDERLAY_MCAST", "ROUTE_UNICAST");
		num = 0;
	}

	printf(M_FWD_LINE_FMT, "EXTERNAL", this->vni, this->underlay_str, this->next_hop_str);
	num++;
}

/* Control-plane config operations via ioctl */
xde_ioc_opte_cmd:entry
{
	this->ioc = (opte_cmd_ioctl_t *)arg0;
	this->cmd = this->ioc->cmd;
	/* Only track multicast-related commands */
	this->name =
		this->cmd == CMD_SET_M2P ? "CFG SET_M2P" :
		this->cmd == CMD_CLEAR_M2P ? "CFG CLEAR_M2P" :
		this->cmd == CMD_SET_MCAST_FWD ? "CFG SET_FWD" :
		this->cmd == CMD_CLEAR_MCAST_FWD ? "CFG CLEAR_FWD" :
		this->cmd == CMD_DUMP_MCAST_FWD ? "CFG DUMP_FWD" :
		this->cmd == CMD_DUMP_MCAST_SUBS ? "CFG DUMP_SUBS" :
		this->cmd == CMD_MCAST_SUBSCRIBE ? "CFG SUBSCRIBE" :
		this->cmd == CMD_MCAST_UNSUBSCRIBE ? "CFG UNSUBSCRIBE" :
		NULL;

	/* Always track aggregations for multicast ops */
	if (this->name != NULL) {
		@cfg_counts[this->name] = count();
	}
}

xde_ioc_opte_cmd:entry
/!suppress_output && this->name != NULL/
{
	printf(DBG_LINE_FMT, this->name, "", "");
}

/* Dedicated control-plane probes (if present) */
mcast-map-set {
	/* arg0=af, arg1=group_ptr, arg2=underlay_ptr, arg3=vni */
	this->af = arg0;
	this->group_ptr = arg1;
	this->underlay = (in6_addr_t *)arg2;
	this->vni = arg3;

	/* Always track aggregations */
	@cfg_counts["MAP_SET"] = count();
}

mcast-map-set
/!suppress_output/
{
	this->group = MCAST_GROUP_STR(this->af, this->group_ptr);
	this->ul = inet_ntoa6(this->underlay);
	printf(M_LINE_FMT, "CFG MAP-SET", this->vni, this->group, this->ul);
}

mcast-map-clear {
	/* arg0=af, arg1=group_ptr, arg2=underlay_ptr, arg3=vni */
	this->af = arg0;
	this->group_ptr = arg1;
	this->underlay = (in6_addr_t *)arg2;
	this->vni = arg3;

	/* Always track aggregations */
	@cfg_counts["MAP_CLEAR"] = count();
}

mcast-map-clear
/!suppress_output/
{
	this->group = MCAST_GROUP_STR(this->af, this->group_ptr);
	this->ul = inet_ntoa6(this->underlay);
	printf(M_LINE_FMT, "CFG MAP-CLEAR", this->vni, this->group, this->ul);
}

mcast-fwd-set {
	/* arg0=underlay_ptr, arg1=count, arg2=vni */
	this->underlay = (in6_addr_t *)arg0;
	this->count = arg1;
	this->vni = arg2;

	/* Always track aggregations */
	@cfg_counts["FWD_SET"] = count();
}

mcast-fwd-set
/!suppress_output/
{
	this->ul = inet_ntoa6(this->underlay);
	printf(M_LINE_FMT, "CFG FWD-SET", this->vni, "-", this->ul);
}

mcast-fwd-clear {
	/* arg0=underlay_ptr, arg1=vni */
	this->underlay = (in6_addr_t *)arg0;
	this->vni = arg1;

	/* Always track aggregations */
	@cfg_counts["FWD_CLEAR"] = count();
}

mcast-fwd-clear
/!suppress_output/
{
	this->ul = inet_ntoa6(this->underlay);
	printf(M_LINE_FMT, "CFG FWD-CLEAR", this->vni, "-", this->ul);
}

mcast-subscribe {
	/* arg0=port_cstr, arg1=af, arg2=group_ptr, arg3=vni */
	this->port = stringof(arg0);
	this->af = arg1;
	this->group_ptr = arg2;
	this->vni = arg3;

	/* Always track aggregations */
	@cfg_counts["SUBSCRIBE"] = count();
}

mcast-subscribe
/!suppress_output/
{
	this->group = MCAST_GROUP_STR(this->af, this->group_ptr);
	printf(M_LINE_FMT, "SUBSCRIBE", this->vni, this->group, this->port);
}

mcast-unsubscribe {
	/* arg0=port_cstr, arg1=af, arg2=group_ptr, arg3=vni */
	this->port = stringof(arg0);
	this->af = arg1;
	this->group_ptr = arg2;
	this->vni = arg3;

	/* Always track aggregations */
	@cfg_counts["UNSUBSCRIBE"] = count();
}

mcast-unsubscribe
/!suppress_output/
{
	this->group = MCAST_GROUP_STR(this->af, this->group_ptr);
	printf(M_LINE_FMT, "UNSUBSCR", this->vni, this->group, this->port);
}

/* Dataplane failure probes */
mcast-tx-pullup-fail {
	/* arg0=len */
	this->len = arg0;

	/* Always track aggregations */
	@by_event["TX_FAIL"] = count();
}

mcast-tx-pullup-fail
/!suppress_output/
{
	printf(M_LINE_FMT, "TX_FAIL", 0, "-", "-");
}

mcast-rx-pullup-fail {
	/* arg0=len */
	this->len = arg0;

	/* Always track aggregations */
	@by_event["RX_FAIL"] = count();
}

mcast-rx-pullup-fail
/!suppress_output/
{
	printf(M_LINE_FMT, "RX_FAIL", 0, "-", "-");
}

mcast-no-fwd-entry {
	/* arg0=underlay_ptr, arg1=vni */
	this->underlay = (in6_addr_t *)arg0;
	this->vni = arg1;

	/* Always track aggregations */
	@by_event["NOFWD"] = count();
}

mcast-no-fwd-entry
/!suppress_output/
{
	this->ul = inet_ntoa6(this->underlay);
	printf(M_LINE_FMT, "NOFWD", this->vni, "-", this->ul);
}

/* Print aggregated summary when the script ends (if enabled) */
END
/show_summary/
{
	printf("\nSummary by event:\n");
	printa(@by_event);
	printf("\nSummary by event and VNI:\n");
	printa(@by_vni);
	printf("\nSummary by overlay group (TX/RX/DELIVER):\n");
	printa(@by_group);
	printf("\nSummary by underlay multicast address (UNDERLAY/EXTERNAL):\n");
	printa(@by_underlay);
	printf("\nLocal delivery by port:\n");
	printa(@by_port);
	printf("\nForwarding by unicast next-hop (routing address):\n");
	printa(@by_nexthop_unicast);
	printf("\nConfig ops:\n");
	printa(@cfg_counts);
}
