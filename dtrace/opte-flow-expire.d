/*
 * Track flow expiration.
 *
 * XXX Would be nice to add lifetime Rx/Tx packets/bytes stats.
 *
 * dtrace -L ./lib -I . -Cqs ./opte-flow-expire.d
 */
#include "common.h"

#define	HDR_FMT "%-24s %-18s %s\n"

BEGIN {
	/*
	 * Use an associative array to stringify the protocol number.
	 */
	protos[1]= "ICMP";
	protos[2] = "IGMP";
	protos[6] = "TCP";
	protos[17] = "UDP";

	printf(HDR_FMT, "PORT", "FT NAME", "FLOW");
	num = 0;
}

flow-expired {
	this->port = stringof(arg0);
	this->name = stringof(arg1);
	this->flow = (flow_id_sdt_arg_t *)arg2;

	if (num >= 10) {
		printf(HDR_FMT, "PORT", "FT NAME", "FLOW");
		num = 0;
	}

	this->af = this->flow->af;

	if (this->af != AF_INET && this->af != AF_INET6) {
		printf("BAD ADDRESS FAMILY: %d\n", this->af);
	}
}

flow-expired /this->af == AF_INET/ {
	FLOW_FMT(this->s, this->flow);
	printf(HDR_FMT, this->port, this->name, this->s);
	num++;
}

flow-expired /this->af == AF_INET6/ {
	FLOW_FMT6(this->s, this->flow);
	printf(HDR_FMT, this->port, this->name, this->s);
	num++;
}

