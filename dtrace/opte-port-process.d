/*
 * Track port process results as they happen.
 *
 * dtrace -L ./lib -I . -Cqs ./opte-port-process.d
 */
#include "common.h"
#include "protos.d"

#define	HDR_FMT		"%-12s %-3s %-8s %-43s %-43s %-5s %s %s\n"
#define	LINE_FMT	"%-12s %-3s %-8u %-43s %-43s %-5u %s %s\n"

BEGIN {
	printf(HDR_FMT, "NAME", "DIR", "EPOCH", "FLOW BEFORE", "FLOW AFTER",
	    "LEN", "RESULT", "PATH");
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
	this->msgs = (derror_sdt_arg_t*) arg7;
	this->msg_len = this->msgs->len;
	this->res = stringof("");
	this->path = PATH_STR(arg8);

	if (num >= 10) {
		printf(HDR_FMT, "NAME", "DIR", "EPOCH", "FLOW BEFORE",
		    "FLOW AFTER", "LEN", "RESULT", "PATH");
		num = 0;
	}

	this->af = this->flow_before->af;

	if (this->af != AF_INET && this->af != AF_INET6) {
		printf("BAD ADDRESS FAMILY: %d\n", this->af);
	}
}

port-process-return
/this->msg_len > 0/
{
	this->res = strjoin(this->res, stringof(this->msgs->entry[0]));
}

port-process-return
/this->msg_len > 1/
{
	this->res = strjoin(this->res, EL_DELIMIT);
	this->res = strjoin(this->res, stringof(this->msgs->entry[1]));
}

port-process-return /this->af == AF_INET/ {
	FLOW_FMT(this->s_before, this->flow_before);
	FLOW_FMT(this->s_after, this->flow_after);
	printf(LINE_FMT, this->name, this->dir, this->epoch, this->s_before,
	    this->s_after, msgsize(this->mp), this->res, this->path);
	num++;
}

port-process-return /this->af == AF_INET6/ {
	FLOW_FMT6(this->s_before, this->flow_before);
	FLOW_FMT6(this->s_after, this->flow_after);
	printf(LINE_FMT,  this->name, this->dir, this->epoch, this->s_before,
	    this->s_after, msgsize(this->mp), this->res, this->path);
	num++;
}

