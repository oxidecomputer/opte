/*
 * Track UFT entry hits as they happen. A hit occurs whenever a packet
 * matches an existing flow table entry (in- or outbound) with the same
 * epoch as the port. This is the 'fast-path' of packet matching.
 *
 * dtrace -L ./lib -I . -Cqs ./opte-uft-hit.d
 */
#include "common.h"
#include "protos.d"

#define	HDR_FMT		"%-8s %-3s %-43s %s %s\n"
#define	LINE_FMT	"%-8s %-3s %-43s %u %u\n"

BEGIN {
	printf(HDR_FMT, "PORT", "DIR", "FLOW", "EPOCH", "LAST_HIT");
	num = 0;
}

uft-hit {
	this->dir = DIR_STR(arg0);
	this->port = stringof(arg1);
	this->flow = (flow_id_sdt_arg_t *)arg2;
	this->epoch = arg3;
	this->af = this->flow->af;
	this->last_hit = arg4;

	if (num >= 10) {
		printf(HDR_FMT, "PORT", "DIR", "FLOW", "EPOCH", "LAST_HIT");
		num = 0;
	}

	if (this->af != AF_INET && this->af != AF_INET6) {
		printf("BAD ADDRESS FAMILY: %d\n", this->af);
	}
}

uft-hit /this->af == AF_INET/ {
	FLOW_FMT(this->s, this->flow);
	printf(LINE_FMT, this->port, this->dir, this->s, this->epoch, this->last_hit);
	num++;
}

uft-hit /this->af == AF_INET6/ {
	FLOW_FMT6(this->s, this->flow);
	printf(LINE_FMT, this->port, this->dir, this->s, this->epoch, this->last_hit);
	num++;
}

