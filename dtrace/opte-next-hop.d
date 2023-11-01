/*
 * Track next hop resolution.
 *
 * dtrace -L ./lib -I . -Cqs ./opte-next-hop.d
 */
#include "common.h"

#define	HDR_FMT		"%-24s %-24s %-17s %-17s %s\n"

BEGIN {
	printf(HDR_FMT, "DEST", "GATEWAY", "SRC MAC", "DST MAC", "MSG");
	num = 0;
}

next-hop {
	this->dst = (in6_addr_t *)arg0;
	this->gw = (in6_addr_t *)arg1;
	this->gw_eth_src = (uchar_t *)arg2;
	this->gw_eth_dst = (uchar_t *)arg3;
	this->msg = stringof(arg4);
	this->msg = this->msg == "" ? "--" : this->msg;

	ETH_FMT(this->gw_eth_src_s, this->gw_eth_src);
	ETH_FMT(this->gw_eth_dst_s, this->gw_eth_dst);
	printf(HDR_FMT, inet_ntoa6(this->dst), inet_ntoa6(this->gw),
	    this->gw_eth_src_s, this->gw_eth_dst_s, this->msg);
}
