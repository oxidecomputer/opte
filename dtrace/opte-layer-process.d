/*
 * Track a flow as it is processed by different layers. This only
 * applies to flows without a current UFT entry.
 *
 * XXX Teach ARP to SDT probe + this script.
 *
 * dtrace -L ./lib -I . -Cqs ./opte-layer-process.d
 */
#include "common.h"

#define	HDR_FMT		"%-3s %-12s %-43s %s\n"

BEGIN {
	/*
	 * Use an associative array to stringify the protocol number.
	 */
	protos[0] = "FIX";
	protos[1] = "ICMP";
	protos[2] = "IGMP";
	protos[6] = "TCP";
	protos[17] = "UDP";
	protos[255] = "XXX";

	printf(HDR_FMT, "DIR", "NAME", "FLOW", "RES");
	num = 0;
}

sdt:opte::layer-process-return {
	this->dir = stringof(arg0);
	this->name = stringof(arg1);
	this->flow = (flow_id_sdt_arg_t *)arg2;
	this->res = stringof(arg3);

	if (num >= 10) {
		printf(HDR_FMT, "DIR", "NAME", "FLOW", "RES");
		num = 0;
	}

	this->af = this->flow->af;

	if (this->af != AF_INET && this->af != AF_INET6) {
		printf("BAD ADDRESS FAMILY: %d\n", this->af);
	}
}

sdt:opte::layer-process-return /this->af == AF_INET/ {
	FLOW_FMT(this->s, this->flow);
	printf(HDR_FMT, this->dir, this->name, this->s, this->res);
	num++;
}

sdt:opte::layer-process-return /this->af == AF_INET6/ {
	FLOW_FMT6(this->s, this->flow);
	printf(HDR_FMT,  this->dir, this->name, this->s, this->res);
	num++;
}
