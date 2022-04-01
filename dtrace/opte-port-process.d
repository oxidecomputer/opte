/*
 * Track port process results as they happen.
 *
 * dtrace -L ./lib -I . -Cqs ./opte-port-process.d
 */
#include "common.h"

#define	HDR_FMT		"%-12s %-3s %-43s %-18s %s\n"
#define	LINE_FMT	"%-12s %-3s %-43s 0x%-16p %s\n"

BEGIN {
	/*
	 * Use an associative array to stringify the protocol number.
	 */
	protos[1] = "ICMP";
	protos[2] = "IGMP";
	protos[6] = "TCP";
	protos[17] = "UDP";
	protos[255] = "XXX";

	printf(HDR_FMT, "NAME", "DIR", "FLOW", "MBLK", "RESULT");
	num = 0;
}

port-process-return {
	this->dir = stringof(arg0);
	this->name = stringof(arg1);
	this->flow = (flow_id_sdt_arg_t *)arg2;
	this->mp = arg3;
	this->res = stringof(arg4);

	if (num >= 10) {
		printf(HDR_FMT, "NAME", "DIR", "FLOW", "MBLK", "RESULT");
		num = 0;
	}

	this->af = this->flow->af;

	if (this->af != AF_INET && this->af != AF_INET6) {
		printf("BAD ADDRESS FAMILY: %d\n", this->af);
	}
}

port-process-return /this->af == AF_INET/ {
	FLOW_FMT(this->s, this->flow);
	printf(LINE_FMT, this->name, this->dir, this->s, this->mp, this->res);
	num++;
}

port-process-return /this->af == AF_INET6/ {
	FLOW_FMT6(this->s, this->flow);
	printf(LINE_FMT,  this->name, this->dir, this->s, this->mp, this->res);
	num++;
}


