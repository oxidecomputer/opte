/*
 * Track a flow as it is processed by different layers. This only
 * applies to flows without a current UFT entry.
 *
 * XXX Teach ARP to SDT probe + this script.
 *
 * dtrace -L ./lib -I . -Cqs ./opte-layer-process.d
 */
#include "common.h"
#include "protos.d"

#define	HDR_FMT		"%-16s %-16s %-3s %-48s %-48s %s\n"

BEGIN {
	printf(HDR_FMT, "PORT", "LAYER", "DIR", "FLOW BEFORE", "FLOW AFTER",
	    "RES");
	num = 0;
}

layer-process-return {
	this->dir = DIR_STR(arg0);
	this->port = stringof(arg1);
	this->layer = stringof(arg2);
	this->flow_before = (flow_id_sdt_arg_t *)arg3;
	this->flow_after = (flow_id_sdt_arg_t *)arg4;
	this->msgs = (derror_sdt_arg_t*) arg5;
	this->msg_len = this->msgs->len;
	this->res = stringof("");

	if (num >= 10) {
		printf(HDR_FMT, "PORT", "LAYER", "DIR", "FLOW BEFORE",
		    "FLOW AFTER", "RES");
		num = 0;
	}

	this->af = this->flow_before->af;

	if (this->af != AF_INET && this->af != AF_INET6) {
		printf("BAD ADDRESS FAMILY: %d\n", this->af);
	}
}

layer-process-return
/this->msg_len > 0/
{
	this->res = strjoin(this->res, stringof(this->msgs->entry[0]));
}

layer-process-return
/this->msg_len > 1/
{
	this->res = strjoin(this->res, EL_DELIMIT);
	this->res = strjoin(this->res, stringof(this->msgs->entry[1]));
}

layer-process-return /this->af == AF_INET/ {
	FLOW_FMT(this->s_before, this->flow_before);
	FLOW_FMT(this->s_after, this->flow_after);
	printf(HDR_FMT, this->port, this->layer, this->dir, this->s_before,
	    this->s_after, this->res);
	num++;
}

layer-process-return /this->af == AF_INET6/ {
	FLOW_FMT6(this->s_before, this->flow_before);
	FLOW_FMT6(this->s_after, this->flow_after);
	printf(HDR_FMT, this->port, this->layer, this->dir, this->s_before,
	    this->s_after, this->res);
	num++;
}
