/*
 * Track UFT entry invalidations as they happen. An invalidation
 * occurs when the port's epoch has move forward based on a rule
 * change but the UFT entry is based on an older epoch; therefore it
 * needs to be invalidated so that a new entry may be generated from
 * the current rule set.
 *
 * dtrace -L ./lib -I . -Cqs ./opte-uft-invalidate.d
 */
#include "common.h"
#include "protos.d"

#define	HDR_FMT		"%-8s %-3s %-43s %s\n"
#define	LINE_FMT	"%-8s %-3s %-43s %u\n"

BEGIN {
	printf(HDR_FMT, "PORT", "DIR", "FLOW", "EPOCH");
	num = 0;
}

uft-invalidate {
	this->dir = DIR_STR(arg0);
	this->port = stringof(arg1);
	this->flow = (flow_id_sdt_arg_t *)arg2;
	this->epoch = arg3;
	this->af = this->flow->af;

	if (num >= 10) {
		printf(HDR_FMT, "PORT", "DIR", "FLOW", "EPOCH");
		num = 0;
	}

	if (this->af != AF_INET && this->af != AF_INET6) {
		printf("BAD ADDRESS FAMILY: %d\n", this->af);
	}
}

uft-invalidate /this->af == AF_INET/ {
	FLOW_FMT(this->s, this->flow);
	printf(LINE_FMT, this->port, this->dir, this->s, this->epoch);
	num++;
}

uft-invalidate /this->af == AF_INET6/ {
	FLOW_FMT6(this->s, this->flow);
	printf(LINE_FMT, this->port, this->dir, this->s, this->epoch);
	num++;
}

