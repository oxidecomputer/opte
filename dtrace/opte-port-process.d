/*
 * Track port process results as they happen.
 *
 * dtrace -L ./lib -I . -Cqs ./opte-port-process.d
 */
#include "common.h"
#include "protos.d"

#define	HDR_FMT		"%-12s %-3s %-8s %-43s %-43s %-5s %s\n"
#define	LINE_FMT	"%-12s %-3s %-8u %-43s %-43s %-5u %s\n"

BEGIN {
	printf(HDR_FMT, "NAME", "DIR", "EPOCH", "FLOW BEFORE", "FLOW AFTER",
	    "LEN", "RESULT");
	num = 0;
}

port-process-return {
	this->dir = DIR_STR(arg0);
	this->name = stringof(arg1);
	this->flow_before = (flow_id_sdt_arg_t *)arg2;
	this->flow_after = (flow_id_sdt_arg_t *)arg3;
	this->epoch = arg4;
	this->mp = (mblk_t *)arg5;
	/* If the result is a hairpin packet, then hp_mp is non-NULL. */
	this->hp_mp = (mblk_t *)arg6;
	this->res = stringof(arg7);

	if (num >= 10) {
		printf(HDR_FMT, "NAME", "DIR", "EPOCH", "FLOW BEFORE",
		    "FLOW AFTER", "LEN", "RESULT");
		num = 0;
	}

	this->af = this->flow_before->af;

	if (this->af != AF_INET && this->af != AF_INET6) {
		printf("BAD ADDRESS FAMILY: %d\n", this->af);
	}
}

port-process-return /this->af == AF_INET/ {
	FLOW_FMT(this->s_before, this->flow_before);
	FLOW_FMT(this->s_after, this->flow_after);
	printf(LINE_FMT, this->name, this->dir, this->epoch, this->s_before,
	    this->s_after, msgsize(this->mp), this->res);
	num++;
}

port-process-return /this->af == AF_INET6/ {
	FLOW_FMT6(this->s_before, this->flow_before);
	FLOW_FMT6(this->s_after, this->flow_after);
	printf(LINE_FMT,  this->name, this->dir, this->epoch, this->s_before,
	    this->s_after, msgsize(this->mp), this->res);
	num++;
}


