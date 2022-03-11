/*
 * Track gen_desc() failures for stateful actions.
 *
 * dtrace -L ./lib -I . -Cqs ./opte-gen-desc-fail.d
 */
#include "common.h"

#define HDR_FMT	"%-12s %-12s %-4s %-48s %s\n"

BEGIN {
	/*
	 * Use an associative array to stringify the protocol number.
	 */
	protos[1] = "ICMP";
	protos[2] = "IGMP";
	protos[6] = "TCP";
	protos[17] = "UDP";

	printf(HDR_FMT, "PORT", "LAYER", "DIR", "FLOW", "MSG");
	num = 0;
}

gen-desc-fail {
	this->port = stringof(arg0);
	this->layer = stringof(arg1);
	this->dir = stringof(arg2);
	this->flow = (flow_id_sdt_arg_t *)arg3;
	this->msg = stringof(arg4);
	this->af = this->flow->af;
	num++;

	if (this->af != AF_INET && this->af != AF_INET6) {
		printf("BAD ADDRESS FAMILY: %d\n", this->af);
	}

	if (num >= 10) {
		printf(HDR_FMT, "PORT", "LAYER", "DIR", "FLOW", "MSG");
		num = 0;
	}
}

gen-desc-fail /this->af == AF_INET/ {
	FLOW_FMT(this->s, this->flow);
	printf(HDR_FMT, this->port, this->layer, this->dir, this->s, this->msg);
}

gen-desc-fail /this->af == AF_INET6/ {
	FLOW_FMT6(this->s, this->flow);
	printf(HDR_FMT, this->port, this->layer, this->dir, this->s, this->msg);
}
