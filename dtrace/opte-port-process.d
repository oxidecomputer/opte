/*
 * Track port process results as they happen.
 *
 * dtrace -L ./lib -I . -Cqs ./opte-port-process.d
 */
#include "common.h"

#define	HDR_FMT		"%-12s %-3s %-8s %-43s %-5s %s\n"
#define	LINE_FMT	"%-12s %-3s %-8u %-43s %-5u %s\n"

BEGIN {
	/*
	 * Use an associative array to stringify the protocol number.
	 */
	protos[1] = "ICMP";
	protos[2] = "IGMP";
	protos[6] = "TCP";
	protos[17] = "UDP";
	protos[255] = "XXX";

	printf(HDR_FMT, "NAME", "DIR", "EPOCH", "FLOW", "LEN", "RESULT");
	num = 0;
}

port-process-return {
	this->dir = stringof(arg0);
	this->name = stringof(arg1);
	this->flow = (flow_id_sdt_arg_t *)arg2;
	this->epoch = arg3;
	this->mp = (mblk_t *)arg4;
	/* If the result is a hairpin packet, then hp_mp is non-NULL. */
	this->hp_mp = (mblk_t *)arg5;
	this->res = stringof(arg6);

	if (num >= 10) {
		printf(HDR_FMT, "NAME", "DIR", "EPOCH", "FLOW", "LEN",
		    "RESULT");
		num = 0;
	}

	this->af = this->flow->af;

	if (this->af != AF_INET && this->af != AF_INET6) {
		printf("BAD ADDRESS FAMILY: %d\n", this->af);
	}
}

port-process-return /this->af == AF_INET/ {
	FLOW_FMT(this->s, this->flow);
	printf(LINE_FMT, this->name, this->dir, this->epoch, this->s,
	    msgsize(this->mp), this->res);
	num++;
}

port-process-return /this->af == AF_INET6/ {
	FLOW_FMT6(this->s, this->flow);
	printf(LINE_FMT,  this->name, this->dir, this->epoch, this->s,
	    msgsize(this->mp), this->res);
	num++;
}


