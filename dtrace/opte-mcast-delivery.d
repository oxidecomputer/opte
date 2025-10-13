/*
 * Track multicast packet delivery.
 *
 * dtrace -L ./lib -I . -Cqs ./opte-mcast-delivery.d
 */
#include "common.h"

#define	HDR_FMT     "%-8s %-6s %-39s %-20s %-10s\n"
#define	LINE_FMT    "%-8s %-6d %-39s %-20s %-10s\n"

BEGIN {
	printf(HDR_FMT, "EVENT", "VNI", "GROUP", "PORT/NEXTHOP", "REPL");
	num = 0;
}

sdt:xde::mcast-tx {
	/* arg0=af, arg1=addr_ptr, arg2=vni, arg3=replication */
	this->af = arg0;
	this->group_ptr = arg1;
	this->vni = arg2;
	this->repl = arg3;

	if (num >= 10) {
		printf(HDR_FMT, "EVENT", "VNI", "GROUP", "PORT/NEXTHOP", "REPL");
		num = 0;
	}

	this->group_str = (this->af == AF_INET) ?
	    inet_ntoa((ipaddr_t *)this->group_ptr) :
	    inet_ntoa6((in6_addr_t *)this->group_ptr);
	this->repl_str = (this->repl == 0) ? "External" :
	                  (this->repl == 1) ? "Underlay" :
	                  (this->repl == 2) ? "All" : "Unknown";
	printf(LINE_FMT, "TX", this->vni, this->group_str, "-", this->repl_str);
	num++;
}

sdt:xde::mcast-rx {
	/* arg0=af, arg1=addr_ptr, arg2=vni, arg3=replication */
	this->af = arg0;
	this->group_ptr = arg1;
	this->vni = arg2;
	this->repl = arg3;

	if (num >= 10) {
		printf(HDR_FMT, "EVENT", "VNI", "GROUP", "PORT/NEXTHOP", "REPL");
		num = 0;
	}

	this->group_str = (this->af == AF_INET) ?
	    inet_ntoa((ipaddr_t *)this->group_ptr) :
	    inet_ntoa6((in6_addr_t *)this->group_ptr);
	this->repl_str = (this->repl == 0) ? "External" :
	                  (this->repl == 1) ? "Underlay" :
	                  (this->repl == 2) ? "All" : "Unknown";
	printf(LINE_FMT, "RX", this->vni, this->group_str, "-", this->repl_str);
	num++;
}

sdt:xde::mcast-local-delivery {
	/* arg0=af, arg1=addr_ptr, arg2=vni, arg3=port */
	this->af = arg0;
	this->group_ptr = arg1;
	this->vni = arg2;
	this->port = stringof(arg3);

	if (num >= 10) {
		printf(HDR_FMT, "EVENT", "VNI", "GROUP", "PORT/NEXTHOP", "REPL");
		num = 0;
	}

	this->group_str = (this->af == AF_INET) ?
	    inet_ntoa((ipaddr_t *)this->group_ptr) :
	    inet_ntoa6((in6_addr_t *)this->group_ptr);
	printf(LINE_FMT, "DELIVER", this->vni, this->group_str, this->port, "-");
	num++;
}

sdt:xde::mcast-underlay-fwd {
	/* arg0=af, arg1=addr_ptr, arg2=vni, arg3=next_hop */
	this->af = arg0;
	this->group_ptr = arg1;
	this->vni = arg2;
	this->next_hop = (in6_addr_t *)arg3;

	if (num >= 10) {
		printf(HDR_FMT, "EVENT", "VNI", "GROUP", "PORT/NEXTHOP", "REPL");
		num = 0;
	}

	this->group_str = (this->af == AF_INET) ?
	    inet_ntoa((ipaddr_t *)this->group_ptr) :
	    inet_ntoa6((in6_addr_t *)this->group_ptr);
	this->next_hop_str = inet_ntoa6(this->next_hop);
	printf(LINE_FMT, "UNDERLAY", this->vni, this->group_str, this->next_hop_str, "-");
	num++;
}
