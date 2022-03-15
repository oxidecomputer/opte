#include "common.h"

/* #define	ENTRY_HDR_FMT	"%-3s %-12s %-43s 0x%p\n" */
#define	HDR_FMT	"%-3s %-12s %-43s 0x%p %s\n"

BEGIN {
	/*
	 * Use an associative array to stringify the protocol number.
	 */
	protos[1] = "ICMP";
	protos[2] = "IGMP";
	protos[6] = "TCP";
	protos[17] = "UDP";
	protos[255] = "XXX";

	printf(RETURN_HDR_FMT, "DIR", "NAME", "FLOW", "MBLK", "RESULT");
	num = 0;
}

sdt:opte::port-process-return {
	this->dir = stringof(arg0);
	this->name = stringof(arg1);
	this->flow = (flow_id_sdt_arg_t *)arg2;
	this->mp = arg3;
	this->res = stringof(arg4);

	if (num >= 10) {
		printf(HDR_FMT, "DIR", "NAME", "FLOW", "MBLK" "RESULT");
		num = 0;
	}

	this->af = this->flow->af;

	if (this->af != AF_INET && this->af != AF_INET6) {
		printf("BAD ADDRESS FAMILY: %d\n", this->af);
	}
}

sdt:opte::port-process-return /this->af == AF_INET/ {
	FLOW_FMT(this->s, this->flow);
	printf(HDR_FMT, this->dir, this->name, this->s, this->mp, this->res);
	num++;
}

sdt:opte::port-process-return /this->af == AF_INET6/ {
	FLOW_FMT6(this->s, this->flow);
	printf(HDR_FMT,  this->dir, this->name, this->s, this->mp, this->res);
	num++;
}


