/*
 * Track flow expiration.
 *
 * XXX Would be nice to add lifetime Rx/Tx packets/bytes stats.
 *
 * dtrace -L ./lib -I . -Cqs ./opte-flow-expire.d
 */
#include "common.h"
#include "protos.d"

#define	HDR_FMT		"%-24s %-18s %s %s %s\n"
#define	LINE_FMT	"%-24s %-18s %s %u %u\n"

BEGIN {
	printf(HDR_FMT, "PORT", "FT NAME", "FLOW", "LAST_HIT", "NOW");
	num = 0;
}

flow-expired {
	this->port = stringof(arg0);
	this->name = stringof(arg1);
	this->flow = (flow_id_sdt_arg_t *)arg2;
	this->last_hit = arg3;
	this->now = arg4;

	if (num >= 10) {
		printf(HDR_FMT, "PORT", "FT NAME", "FLOW", "LAST_HIT", "NOW");
		num = 0;
	}

	this->af = this->flow->af;

	if (this->af != AF_INET && this->af != AF_INET6) {
		printf("BAD ADDRESS FAMILY: %d\n", this->af);
	}
}

flow-expired /this->af == AF_INET/ {
	FLOW_FMT(this->s, this->flow);
	printf(LINE_FMT, this->port, this->name, this->s, this->last_hit, this->now);
	num++;
}

flow-expired /this->af == AF_INET6/ {
	FLOW_FMT6(this->s, this->flow);
	printf(LINE_FMT, this->port, this->name, this->s, this->last_hit, this->now);
	num++;
}

