/*
 * Track flow expiration.
 *
 * XXX Would be nice to add lifetime Rx/Tx packets/bytes stats.
 *
 * dtrace -L ./lib -I . -Cqs ./opte-flow-expire.d
 */
#include "common.h"
#include <sys/inttypes.h>

#define	HDR_FMT "%-12s %s\n"

BEGIN {
	/*
	 * Use an associative array to stringify the protocol number.
	 */
	protos[1]= "ICMP";
	protos[2] = "IGMP";
	protos[6] = "TCP";
	protos[17] = "UDP";

	printf(HDR_FMT, "LAYER", "FLOW");
	num = 0;
}

sdt:opte::flow-expired {
	this->name = stringof(arg0);
	this->flow = (flow_id_sdt_arg_t *)arg1;

	if (num >= 10) {
		printf(HDR_FMT, "NAME", "FLOW");
		num = 0;
	}

	this->af = this->flow->af;

	if (this->af != AF_INET && this->af != AF_INET6) {
		printf("BAD ADDRESS FAMILY: %d\n", this->af);
	}
}

sdt:opte::flow-expired /this->af == AF_INET/ {
	FLOW_FMT(this->s, this->flow);
	printf(HDR_FMT, this->name, this->s);
	num++;
}

sdt:opte::flow-expired /this->af == AF_INET6/ {
	FLOW_FMT6(this->s, this->flow);
	printf(HDR_FMT, this->name, this->s);
	num++;
}

