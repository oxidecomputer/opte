/*
 * Track Header Transpositions as they happen.
 *
 * dtrace -L ./lib -I . -Cqs ./opte-ht.d
 */
#include "common.h"

#define	HDR_FMT "%-3s %-12s %-12s %-40s %-40s\n"

BEGIN {
	/*
	 * Use an associative array to stringify the protocol number.
	 */
	protos[1]= "ICMP";
	protos[2] = "IGMP";
	protos[6] = "TCP";
	protos[17] = "UDP";

	printf(HDR_FMT, "DIR", "PORT", "LOCATION", "BEFORE", "AFTER");
	num = 0;
}

ht-run {
	this->ht = (ht_run_sdt_arg_t*)arg0;
	this->dir = stringof(this->ht->dir);
	this->port = stringof(this->ht->port);
	this->loc = stringof(this->ht->loc);
	this->before = this->ht->flow_before;
	this->after = this->ht->flow_after;
	this->af = this->before->af;
	num++;

	if (this->af != AF_INET && this->af != AF_INET6) {
		printf("BAD ADDRESS FAMILY: %d\n", this->af);
	}

	if (num >= 10) {
		printf(HDR_FMT, "DIR", "PORT", "LOCATION", "BEFORE", "AFTER");
		num = 0;
	}
}

ht-run /this->af == AF_INET/ {
	FLOW_FMT(this->bs, this->before);
	FLOW_FMT(this->as, this->after);
	printf(HDR_FMT, this->dir, this->port, this->loc, this->bs, this->as);
}

ht-run /this->af == AF_INET6/ {
	FLOW_FMT6(this->bs, this->before);
	FLOW_FMT6(this->as, this->after);
	printf(HDR_FMT, this->dir, this->port, this->loc, this->bs, this->as);
}
