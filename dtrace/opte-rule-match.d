/*
 * Track rule match/no-match as it happens.
 *
 * dtrace -L ./lib -I . -Cqs ./opte-rule-match.d
 */
#include "common.h"

#define	HDR_FMT		"%-8s %-12s %-6s %-3s %-43s %s\n"

BEGIN {
	/*
	 * Use an associative array to stringify the protocol number.
	 */
	protos[1] = "ICMP";
	protos[2] = "IGMP";
	protos[6] = "TCP";
	protos[17] = "UDP";
	protos[255] = "XXX";

	printf(HDR_FMT, "PORT", "LAYER", "MATCH", "DIR", "FLOW", "ACTION");
	num = 0;
}

rule-match {
	this->match = (rule_match_sdt_arg_t *)arg0;
	this->port = stringof(this->match->port);
	this->layer = stringof(this->match->layer);
	this->flow = this->match->flow;
	this->dir = stringof(this->match->dir);
	this->af = this->flow->af;
	num++;

	if (num >= 10) {
		printf(HDR_FMT, "PORT", "LAYER", "MATCH", "DIR", "FLOW",
		    "ACTION");
		num = 0;
	}
}

rule-match /this->af == AF_INET/ {
	FLOW_FMT(this->s, this->flow);
	printf(HDR_FMT, this->port, this->layer, "YES", this->dir, this->s,
	    stringof(this->match->rule_type));
}

rule-match /this->af == AF_INET6/ {
	FLOW_FMT6(this->s, this->flow);
	printf(HDR_FMT, this->port, this->layer, "YES", this->dir, this->s,
	    stringof(this->match->rule_type));
}

rule-no-match {
	this->no_match = (rule_no_match_sdt_arg_t *)arg0;
	this->flow = this->no_match->flow;
	this->dir = stringof(this->no_match->dir);
	this->layer = stringof(this->no_match->layer);
	this->af = this->flow->af;
	num++;
}

rule-no-match /this->af == AF_INET/ {
	FLOW_FMT(this->s, this->flow);
	printf(HDR_FMT, this->port, this->layer, "NO", this->dir, this->s,
	    "--");
}

rule-no-match /this->af == AF_INET6/ {
	FLOW_FMT6(this->s, this->flow);
	printf(HDR_FMT, this->port, this->layer, "NO", this->dir, this->s,
	    "--");
}
