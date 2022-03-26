/*
 * Track guest loopback packets as they happen.
 *
 * dtrace -L ./lib -I . -Cqs ./opte-guest-loopback.d
 */
#include "common.h"

#define	HDR_FMT		"%-43s %-12s %-12s\n"

BEGIN {
	/*
	 * Use an associative array to stringify the protocol number.
	 */
	protos[1] = "ICMP";
	protos[2] = "IGMP";
	protos[6] = "TCP";
	protos[17] = "UDP";
	protos[255] = "XXX";

	printf(HDR_FMT, "FLOW", "SRC PORT", "DST PORT");
	num = 0;
}

guest-loopback {
	this->flow = (flow_id_sdt_arg_t *)arg1;
	this->src = stringof(arg2);
	this->dst = stringof(arg3);
	this->af = this->flow->af;
	num++;

	if (num >= 10) {
		printf(HDR_FMT, "FLOW", "SRC PORT", "DST PORT");
		num = 0;
	}

	if (this->af != AF_INET && this->af != AF_INET6) {
		printf("BAD ADDRESS FAMILY: %d\n", this->af);
	}
}

guest-loopback /this->af == AF_INET/ {
	FLOW_FMT(this->s, this->flow);
	printf(HDR_FMT, this->s, this->src, this->dst);
	num++;
}

guest-loopback /this->af == AF_INET6/ {
	FLOW_FMT6(this->s, this->flow);
	printf(HDR_FMT,  this->s, this->src, this->dst);
	num++;
}


